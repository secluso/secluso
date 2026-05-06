Secluso deploy tool (developer notes)

This repo is the full deploy workflow for Secluso. It prepares a Raspberry Pi image, provisions a server over SSH, and shows live status in the UI while image or SSH steps run. Binaries and images are downloaded through secluso-update verification.

The UI lives in src/ with the SvelteKit pages, while src-tauri/ holds the backend commands used for image preparation and server provision. The server install script lives under src-tauri/assets/server/, and the test/ folder has the manual harness and fixtures.

For dev work you need node 18+, pnpm, rust 1.85.0, and the normal Tauri system deps for your OS. Install and run dev with:
```
pnpm install
pnpm dev
pnpm tauri dev
```

Checks and production builds are:
```
pnpm check
pnpm build
pnpm tauri build
```

The image flow collects output paths and optional dev settings, generates the camera_secret and wifi_password provisioning files locally, downloads and verifies the prebuilt Pi image through secluso-update library, then injects those generated files into the image's /provision partition. 

The server flow collects the SSH target plus credentials, generates user credentials locally, then runs the remote install script and enables services.

Developer settings are stored in localStorage under secluso-dev-settings. Developer mode lets you set a custom repo plus signature keys for updater verification. Signature keys are passed as name:github_user via --sig-key.
