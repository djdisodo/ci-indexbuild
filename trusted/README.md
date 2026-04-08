# Trusted APK Keys

This directory stores the trusted APK public keyring used by CI.

- `apk-keys/*.pub`: trusted public keys used by `apk verify`.

CI passes `--trusted-keys-dir` to `scripts/reindex_dirty.py`, which runs:

- `apk --keys-dir <trusted-key-dir> verify <downloaded-apks...>`

Add/remove `.pub` files when your trusted package signing keys change.
