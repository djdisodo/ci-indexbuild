# APK Public Keyring

Put trusted APK signing public keys in this directory.

- Expected extension: `.pub`
- Example filename: `ci-repo@example.com-67f95f6f.rsa.pub`
- Keep key filenames stable once packages are published. APK signatures embed the key filename
  (for example `root-69d6bd9f.rsa.pub`), so renaming/removing that filename causes `UNTRUSTED`
  verification failures even when the key material is unchanged.
- This repo currently includes the default Alpine public keys copied from `alpine:3.20` (`/etc/apk/keys`).

The workflow uses repository variable `TRUSTED_APK_KEYS_DIR` (default `trusted/apk-keys`) and verifies downloaded packages against these keys before indexing.
