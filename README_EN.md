# LINE Cheater - Multidevice

This tool disguises a second iPhone as an iPad companion device to complete companion-device authentication for the same LINE account.

[繁體中文](README.md)

## Supported Versions 📦

| LINE version | Jailbreak required | Installation method | Advantages | Limitations |
|---|---|---|---|---|
| 15.7.2 | Yes | Dopamine + AppSync | Supports iOS 16.7.16 with push notifications | Requires a jailbreak and uses an older version |
| 26.14.0 | No | Self-signing | No jailbreak required and uses a newer version | Requires iOS 18 or later, with no push notifications |

An iPhone 8 or iPhone X is recommended. These models can run Dopamine jailbreak on the latest iOS 16.7.16. With AppSync, they can install LINE 15.7.2 without needing to find a device on a particular firmware version, while retaining notification support.

### LINE 15.7.2

Build from a decrypted dumped IPA. If the executable SHA-256 differs for a dump of the same version, use `--allow-unverified`. The tool still verifies the bundle ID, version, build, and original instructions:

```sh
python3 tools/main.py --legacy-keychain-compat --require-push --allow-unverified \
  LINE-decrypted.ipa output/LINE-15.7.2.ipa
```

On a jailbroken device, use [ipa-dumper](https://github.com/hirakujira/ipa-dumper) to obtain a decrypted IPA.
This version has been tested for companion-device sign-in, sending and receiving messages, and receiving notifications.

### LINE 26.14.0

```sh
python3 tools/main.py --keychain-compat \
  jp.naver.line_26.14.0_und3fined.ipa \
  output/LINE-26.14.0.ipa
```

A decrypted IPA is also required. If you do not have a jailbroken device to create a dump, search online for an existing IPA.
This version is fully re-signed with its own certificate and provisioning profile. It can send and receive messages but does not support push notifications.
Use [AltStore](https://altstore.io/) or [Sideloadly](https://sideloadly.io/) for re-signing.

## Demo 📱

![Demo](demo.jpg)

## How It Works ⚙️

- LINE checks whether the device is an iPad. The tool modifies only the conditional branch for the companion-device sign-in entry point, rather than globally spoofing the device type.
- It injects a compatibility layer that uses the app's private directory when App Groups are unavailable, and handles some Keychain incompatibilities.
- The modified app is re-signed with `ldid`, and AppSync allows installation on jailbroken devices.
- LINE 15.7.2 preserves the dumped IPA's bundle ID, APNs, and Keychain entitlements, so push notifications currently work in testing.
- The tool verifies the version, build, and executable SHA-256, and applies patches only to analyzed versions.

## Notes ⚠️

- Only verified versions and IPAs are supported. Other versions will be rejected.
- Back up your LINE data before installing on a test device.

## Disclaimer 📄

This project is intended solely for academic research, compatibility testing, and educational use. It is an unofficial research and modification tool and is not affiliated with LINE, NAVER, or Apple. Using a modified IPA may cause issues with your account, chat data, or notifications, and may violate applicable terms of service. Back up your data, ensure that your use complies with applicable laws and service terms, and assume all risks and responsibilities.
