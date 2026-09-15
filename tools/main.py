#!/usr/bin/env python3
"""Build a version-locked LINE secondary-login IPA.

Includes private App Group fallback unless --entry-only is selected.
Legacy AppSync builds use ldid; other builds need full re-signing.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE = 'Payload/LINE.app/LINE'
PLIST = 'Payload/LINE.app/Info.plist'
NOP = bytes.fromhex('1f2003d5')
LIB_NAME = 'LINEContainerCompat.dylib'
LIB_ENTRY = 'Payload/LINE.app/Frameworks/' + LIB_NAME
LOAD_PATH = '@executable_path/Frameworks/' + LIB_NAME
LEGACY_KEYCHAIN_ENTITLEMENTS = {
    'application-identifier': 'ZW4U99SQQ3.jp.naver.line',
    'com.apple.developer.team-identifier': 'ZW4U99SQQ3',
    'keychain-access-groups': ['ZW4U99SQQ3.jp.naver.line'],
}


@dataclass(frozen=True)
class PatchProfile:
    version: str
    build: str
    executable_sha256: str
    patch_offset: int
    patch_va: int
    original: bytes
    instruction: str
    requires_ldid: bool = False


PATCH_PROFILES = (
    PatchProfile(
        version='26.14.0',
        build='2026.828.1845',
        executable_sha256='6586241b63f6a1007d5916498c77e5c539d7aa99e269e1994119d6018ac6d760',
        patch_offset=0x5D868,
        patch_va=0x10005D868,
        original=bytes.fromhex('c0040036'),
        instruction='tbz w0, #0, 0x10005d900',
    ),
    PatchProfile(
        version='15.7.2',
        build='2025.522.159',
        executable_sha256='e4a3fa01288efa7981af07dec8e75d4b4d361d15bfde2a1339b66bca373f0254',
        patch_offset=0x526D0,
        patch_va=0x1000526D0,
        original=bytes.fromhex('00040036'),
        instruction='tbz w0, #0, 0x100052750',
        requires_ldid=True,
    ),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def find_profile(info, original, allow_unverified=False):
    if info.get('CFBundleIdentifier') != 'jp.naver.line':
        raise ValueError('Expected the original jp.naver.line bundle identifier.')
    version = info.get('CFBundleShortVersionString')
    build = info.get('CFBundleVersion')
    executable_sha256 = digest(original)
    for profile in PATCH_PROFILES:
        if (version, build, executable_sha256) == (
            profile.version, profile.build, profile.executable_sha256,
        ):
            return profile
    if allow_unverified:
        matches = [profile for profile in PATCH_PROFILES
                   if (profile.version, profile.build) == (version, build)]
        if len(matches) == 1:
            return matches[0]
    supported = ', '.join(dict.fromkeys(f'{p.version} ({p.build})' for p in PATCH_PROFILES))
    raise ValueError(
        'Unsupported LINE executable. Expected a verified version/build/hash '
        f'combination ({supported}); refusing to patch.'
    )


def patched_binary(original, profile=PATCH_PROFILES[0], verify_hash=True):
    if verify_hash and digest(original) != profile.executable_sha256:
        raise ValueError('Executable SHA-256 mismatch: this patch is only for the analyzed dump.')
    if struct.unpack_from('<I', original)[0] != 0xFEEDFACF:
        raise ValueError('Expected a thin little-endian 64-bit Mach-O.')
    if original[profile.patch_offset:profile.patch_offset + 4] != profile.original:
        raise ValueError('Expected ARM64 branch not found; refusing to patch.')
    result = bytearray(original)
    result[profile.patch_offset:profile.patch_offset + 4] = NOP
    return bytes(result)


def ldid_sign(binary, ldid, entitlements=None):
    """Ad-hoc-sign a patched legacy executable for AppSync installation."""
    signature = '-S' + str(entitlements) if entitlements else '-S'
    subprocess.run([str(ldid), signature, str(binary)], check=True)


def read_ldid_entitlements(binary, ldid):
    raw = subprocess.check_output([str(ldid), '-e', str(binary)])
    entitlements = plistlib.loads(raw) if raw.strip() else {}
    if not isinstance(entitlements, dict):
        raise ValueError('Expected an entitlement dictionary.')
    return entitlements


def ldid_sign_preserving_entitlements(binary, ldid, defaults=None, require_push=False):
    source = read_ldid_entitlements(binary, ldid)
    # Fill missing legacy identity fields, never replace a source value or group list.
    entitlements = dict(defaults or {})
    entitlements.update(source)
    if require_push and entitlements.get('aps-environment') != 'production':
        raise ValueError('Source must contain aps-environment=production; refusing to invent push entitlements.')
    with tempfile.TemporaryDirectory(prefix='line-entitlements-') as temporary:
        path = Path(temporary) / 'entitlements.plist'
        path.write_bytes(plistlib.dumps(entitlements))
        ldid_sign(binary, ldid, path)
    if read_ldid_entitlements(binary, ldid) != entitlements:
        raise ValueError('ldid did not preserve the requested entitlements.')
    return {
        'source_preserved': True,
        'added_keys': sorted(entitlements.keys() - source.keys()),
        **{key: entitlements.get(key) for key in (
            'aps-environment', 'application-identifier',
            'com.apple.developer.team-identifier', 'keychain-access-groups',
        )},
    }


def code_signature_range(data):
    count, command_size = struct.unpack_from('<II', data, 16)
    cursor = 32
    end = cursor + command_size
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or cursor + size > end:
            raise ValueError('Invalid load-command layout')
        if command == 0x1d:
            offset, size = struct.unpack_from('<II', data, cursor + 8)
            if offset + size > len(data):
                raise ValueError('Invalid code-signature range')
            return range(offset, offset + size)
        cursor += size
    raise ValueError('LC_CODE_SIGNATURE is missing')


def code_signature_command_range(data):
    count, command_size = struct.unpack_from('<II', data, 16)
    cursor = 32
    end = cursor + command_size
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or cursor + size > end:
            raise ValueError('Invalid load-command layout')
        if command == 0x1d:
            return range(cursor, cursor + size)
        cursor += size
    raise ValueError('LC_CODE_SIGNATURE is missing')


def linkedit_file_size_range(data):
    count, command_size = struct.unpack_from('<II', data, 16)
    cursor = 32
    end = cursor + command_size
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or cursor + size > end:
            raise ValueError('Invalid load-command layout')
        if command == 0x19 and data[cursor + 8:cursor + 24].split(b'\0')[0] == b'__LINKEDIT':
            return range(cursor + 48, cursor + 56)
        cursor += size
    raise ValueError('__LINKEDIT segment is missing')


def add_dylib(data):
    if struct.unpack_from('<I', data, 0)[0] != 0xfeedfacf:
        raise ValueError('Expected thin 64-bit Mach-O')
    count, command_size = struct.unpack_from('<II', data, 16)
    cursor = 32
    first_section = len(data)
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, cursor)
        if size < 8 or size % 8 or cursor + size > 32 + command_size:
            raise ValueError('Invalid load-command layout')
        if cmd in (0xc, 0x80000018, 0x8000001f):
            relative = struct.unpack_from('<I', data, cursor + 8)[0]
            name = data[cursor + relative:cursor + size].split(b'\0')[0]
            if name == LOAD_PATH.encode():
                raise ValueError('Compatibility dylib already referenced')
        if cmd == 0x19:
            sections = struct.unpack_from('<I', data, cursor + 64)[0]
            for i in range(sections):
                section = cursor + 72 + i * 80
                off = struct.unpack_from('<I', data, section + 48)[0]
                if off:
                    first_section = min(first_section, off)
        cursor += size
    if cursor != 32 + command_size:
        raise ValueError('Load command size mismatch')
    raw = LOAD_PATH.encode() + b'\0'
    size = (24 + len(raw) + 7) & ~7
    command = struct.pack('<6I', 0xc, size, 24, 0, 0, 0) + raw
    command += bytes(size - len(command))
    if cursor + size > first_section or any(data[cursor:cursor + size]):
        raise ValueError('Not enough zero-filled header padding; refusing to shift binary data')
    result = bytearray(data)
    struct.pack_into('<II', result, 16, count + 1, command_size + size)
    result[cursor:cursor + size] = command
    return bytes(result), {'load_command_offset': hex(cursor), 'load_command_size': size,
                           'path': LOAD_PATH, 'first_section_offset': hex(first_section)}

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='Original verified IPA, not a previously patched IPA')
    parser.add_argument('output', type=Path)
    parser.add_argument('--entry-only', action='store_true',
                        help='Only patch the secondary-login entry; do not compile or inject a compatibility dylib')
    parser.add_argument('--diagnostics', action='store_true',
                        help='Log error codes, selected localization keys, container results and LINE offsets')
    parser.add_argument('--keychain-compat', action='store_true',
                        help='Audited E2EE/authentication missing-entitlement retry with default Keychain group; includes diagnostics')
    parser.add_argument('--legacy-keychain-compat', action='store_true',
                        help='15.7.2-only authentication-store missing-entitlement retry; includes diagnostics')
    parser.add_argument('--message-diagnostics', action='store_true',
                        help='Read-only post-login observations; includes current Keychain compatibility')
    parser.add_argument('--ldid', type=Path,
                        help='ldid executable for the 15.7.2 AppSync output (default: ldid in PATH)')
    parser.add_argument('--no-ldid', action='store_true',
                        help='Do not ldid-sign the 15.7.2 main executable and injected dylib')
    parser.add_argument('--require-push', action='store_true',
                        help='Require and preserve source production APNs entitlement for 15.7.2; delivery needs device testing')
    parser.add_argument('--allow-unverified', action='store_true',
                        help='Allow a different executable hash for a known version/build; still checks the original ARM64 instruction')
    args = parser.parse_args(argv)
    if args.message_diagnostics:
        args.keychain_compat = True
    if args.legacy_keychain_compat:
        args.diagnostics = True
    if args.keychain_compat:
        args.diagnostics = True
    if args.entry_only and args.diagnostics:
        parser.error('--entry-only cannot be combined with diagnostics or Keychain compatibility.')
    if args.keychain_compat and args.legacy_keychain_compat:
        parser.error('--keychain-compat and --legacy-keychain-compat cannot be used together.')
    if args.ldid and args.no_ldid:
        parser.error('--ldid and --no-ldid cannot be used together.')
    if args.require_push and args.no_ldid:
        parser.error('--require-push requires ldid signing.')
    if (args.output.exists() or args.output.with_suffix('.manifest.json').exists() or
            args.output.resolve() == args.input.resolve()):
        parser.error('Output and manifest must be new files distinct from the input.')
    return args


def main():
    args = parse_args()
    with zipfile.ZipFile(args.input) as source:
        if len(source.namelist()) != len(set(source.namelist())):
            raise ValueError('Duplicate ZIP entry names are not supported.')
        original = source.read(EXECUTABLE)
        info = plistlib.loads(source.read(PLIST))
        profile = find_profile(info, original, args.allow_unverified)
    if args.legacy_keychain_compat and not profile.requires_ldid:
        raise ValueError('--legacy-keychain-compat only supports LINE 15.7.2.')
    if args.require_push and not profile.requires_ldid:
        raise ValueError('--require-push only supports the 15.7.2 AppSync build.')
    if profile.requires_ldid and args.keychain_compat:
        raise ValueError(
            'The 15.7.2 AppSync build supports --legacy-keychain-compat; '
            'the 26.14.0 Keychain offsets are not valid for this executable.'
        )
    build, lib_data = (None, None) if args.entry_only else build_compat_dylib(args, info)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.input) as source:
        names = source.namelist()
        if len(names) != len(set(names)) or (lib_data is not None and LIB_ENTRY in names):
            raise ValueError('Unexpected or duplicate archive member')
        entry_patched = patched_binary(
            original, profile, verify_hash=not args.allow_unverified
        )
        modified, injection = (entry_patched, None) if args.entry_only else add_dylib(entry_patched)
        signing = 'not_requested'
        signing_entitlements = None
        if profile.requires_ldid and not args.no_ldid:
            ldid = args.ldid or Path('ldid')
            with tempfile.TemporaryDirectory(prefix='line-container-ldid-') as temporary:
                main_executable = Path(temporary) / 'LINE'
                injected_dylib = Path(temporary) / LIB_NAME
                main_executable.write_bytes(modified)
                if lib_data is not None:
                    injected_dylib.write_bytes(lib_data)
                signing_entitlements = ldid_sign_preserving_entitlements(
                    main_executable, ldid,
                    defaults=LEGACY_KEYCHAIN_ENTITLEMENTS if args.legacy_keychain_compat else None,
                    require_push=args.require_push,
                )
                if lib_data is not None:
                    ldid_sign(injected_dylib, ldid)
                modified = main_executable.read_bytes()
                if lib_data is not None:
                    lib_data = injected_dylib.read_bytes()
            signing = f'ldid_ad_hoc:{ldid}'
        elif profile.requires_ldid:
            signing = 'skipped_by_no_ldid'
        with zipfile.ZipFile(args.output, 'x') as target:
            target.comment = source.comment
            for entry in source.infolist():
                target.writestr(entry, modified if entry.filename == EXECUTABLE else source.read(entry))
            if lib_data is not None:
                entry = zipfile.ZipInfo(LIB_ENTRY, (2026, 9, 15, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = 0o100755 << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                target.writestr(entry, lib_data)
    # Full round-trip archive comparison, including the original resources and extensions.
    with zipfile.ZipFile(args.input) as source, zipfile.ZipFile(args.output) as target:
        if target.namelist() != source.namelist() + ([LIB_ENTRY] if lib_data is not None else []):
            raise AssertionError('Unexpected member layout')
        for name in source.namelist():
            expected = modified if name == EXECUTABLE else source.read(name)
            if target.read(name) != expected:
                raise AssertionError('Unexpected changed member: ' + name)
        if (lib_data is not None and target.read(LIB_ENTRY) != lib_data) or target.testzip() is not None:
            raise AssertionError('Dylib or ZIP verification failed')
    if modified[profile.patch_offset:profile.patch_offset + 4] != NOP:
        raise AssertionError('Patched ARM64 instruction differs from NOP.')
    start = int(injection['load_command_offset'], 16) if injection else 0
    end = start + injection['load_command_size'] if injection else 0
    changed = [i for i, (a, b) in enumerate(zip(original, modified)) if a != b]
    allowed = ((injection is not None and (16 <= i < 24 or start <= i < end)) or
               profile.patch_offset <= i < profile.patch_offset + 4
               for i in changed)
    signature_growth = False
    if signing.startswith('ldid_ad_hoc:'):
        original_signature_range = code_signature_range(original)
        signature_range = code_signature_range(modified)
        original_signature_command = code_signature_command_range(original)
        signature_command = code_signature_command_range(modified)
        linkedit_file_size = linkedit_file_size_range(modified)
        allowed = ((injection is not None and (16 <= i < 24 or start <= i < end)) or
                   profile.patch_offset <= i < profile.patch_offset + 4 or
                   i in original_signature_range or i in signature_range or
                   i in original_signature_command or
                   i in signature_command or i in linkedit_file_size
                   for i in changed)
        signature_growth = (original_signature_range.stop == len(original) and
                            signature_range.stop == len(modified))
    if (len(modified) != len(original) and not signature_growth) or any(
            not allowed_change for allowed_change in allowed):
        raise AssertionError('Changed bytes outside documented patch regions')
    # Keep a local binary for inspection; signing this file alone is NOT installation signing.
    if build is not None:
        (build / 'LINE-container-compat').write_bytes(modified)
    manifest = {'status': ('experimental_ldid_ad_hoc_signed_not_device_tested'
                           if signing.startswith('ldid_ad_hoc:') else
                           'experimental_not_device_tested_requires_resigning'),
                'diagnostics': args.diagnostics,
                'entry_only': args.entry_only,
                'version': profile.version,
                'build': profile.build,
                'minimum_ios': info['MinimumOSVersion'],
                'keychain_compat': args.keychain_compat,
                'legacy_keychain_compat': args.legacy_keychain_compat,
                'allow_unverified': args.allow_unverified,
                'executable_hash_verified': (
                    digest(original) == profile.executable_sha256
                ),
                'legacy_keychain_entitlements': (
                    {key: signing_entitlements[key] for key in LEGACY_KEYCHAIN_ENTITLEMENTS}
                    if args.legacy_keychain_compat and signing_entitlements else None
                ),
                'bundle_identifier': info['CFBundleIdentifier'],
                'signing_entitlements': signing_entitlements,
                'push_delivery': 'not_device_tested',
                'message_diagnostics': args.message_diagnostics,
                'source_ipa_sha256': digest(args.input.read_bytes()),
                'output_ipa_sha256': digest(args.output.read_bytes()),
                'source_executable_sha256': digest(original), 'patched_executable_sha256': digest(modified),
                'dylib_sha256': digest(lib_data) if lib_data is not None else None, 'injection': injection,
                'entry_patch_offset': hex(profile.patch_offset),
                'signing': signing,
                'allowed_group_ids': [] if args.entry_only else ['group.com.linecorp.line', 'group.share.com.linecorp.line'],
                'fallback': None if args.entry_only else 'Library/Application Support/LINEContainerCompat/<group ID>',
                'scope': (
                    'Main app only; exact 15.7.2 authentication-store Keychain missing-entitlement '
                    'errors retry without an explicit access group. Source entitlements are preserved '
                    'when ldid-signing; missing legacy identity fields use fallback values. '
                    'No E2EE patch; private fallback containers are not shared with extensions. '
                    'APNs delivery requires device testing.'
                    if args.legacy_keychain_compat else
                    'Main app only; audited E2EE and exact authentication-store Keychain missing-entitlement errors retry without explicit access group. No cross-extension sharing or push identity.'
                    if args.keychain_compat else
                    'Main app only; private fallback containers are not shared with extensions. '
                    'Source entitlements are preserved when ldid-signing; APNs delivery requires device testing. '
                    'No Keychain remapping.'
                ),
                'verification': ('All original archive contents identical except documented Mach-O patches; '
                                 'one added dylib; ZIP CRC passed; both injected components ldid-signed; '
                                 'main executable entitlements read back and verified.'
                                 if signing.startswith('ldid_ad_hoc:') else
                                 'All original archive contents identical except documented Mach-O patches; '
                                 'one added dylib; ZIP CRC passed; dylib ad hoc signature verified.')}
    if args.entry_only:
        manifest.update({
            'scope': 'Secondary-login entry only; no injected dylib or container/Keychain hooks.',
            'source_ipa': args.input.name,
            'output_ipa': args.output.name,
            'original_executable_sha256': digest(original),
            'patch': {'virtual_address': hex(profile.patch_va), 'file_offset': hex(profile.patch_offset),
                      'original_hex': profile.original.hex(), 'patched_hex': NOP.hex(),
                      'original_instruction': profile.instruction, 'patched_instruction': 'nop'},
            'changed_byte_offsets': [hex(i) for i in changed],
            'verification': 'All other ZIP member contents identical; ZIP CRC and patch verification passed.',
        })
    args.output.with_suffix('.manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


def build_compat_dylib(args, info):
    build = ROOT / 'build'
    build.mkdir(exist_ok=True)
    if args.diagnostics:
        build = build / ('keychain-compat' if args.keychain_compat else 'diagnostics')
        build.mkdir(exist_ok=True)
    lib = build / LIB_NAME
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
    subprocess.run(['xcrun', '--sdk', 'iphoneos', 'clang',
                    '-target', 'arm64-apple-ios' + info['MinimumOSVersion'],
                    '-isysroot', sdk, '-fobjc-arc', '-fblocks', '-O2', '-Wall', '-Wextra',
                    *(['-DLINE_MULTI_DIAGNOSTICS=1'] if args.diagnostics else []),
                    *(['-DLINE_MULTI_KEYCHAIN_COMPAT=1', '-framework', 'Security'] if args.keychain_compat else []),
                    *(['-DLINE_MULTI_KEYCHAIN_COMPAT=1', '-DLINE_MULTI_LEGACY_KEYCHAIN_COMPAT=1',
                       '-framework', 'Security'] if args.legacy_keychain_compat else []),
                    *(['-DLINE_MULTI_MESSAGE_DIAGNOSTICS=1'] if args.message_diagnostics else []),
                    '-dynamiclib', '-framework', 'Foundation',
                    '-Wl,-install_name,' + LOAD_PATH,
                    str(ROOT / 'compat' / 'LINEContainerCompat.m'), '-o', str(lib)], check=True)
    subprocess.run(['codesign', '--force', '--sign', '-', str(lib)], check=True)
    subprocess.run(['codesign', '--verify', '--strict', str(lib)], check=True)
    lib_data = lib.read_bytes()
    # The load command requests version 0.0.0, matching the dylib's LC_ID_DYLIB.
    cursor = 32
    identity_checked = False
    for _ in range(struct.unpack_from('<I', lib_data, 16)[0]):
        cmd, size = struct.unpack_from('<II', lib_data, cursor)
        if cmd == 0xd:
            relative, _, current, compatibility = struct.unpack_from('<4I', lib_data, cursor + 8)
            name = lib_data[cursor + relative:cursor + size].split(b'\0')[0].decode()
            if name != LOAD_PATH or current != 0 or compatibility != 0:
                raise ValueError('Dylib identity/version differs from the injected load command')
            identity_checked = True
        cursor += size
    if not identity_checked:
        raise ValueError('Dylib identity command missing')
    return build, lib_data


if __name__ == '__main__':
    main()
