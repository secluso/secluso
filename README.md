<div align="center">

<p>
  <img src="media/banner-private-home-security.png" alt="Private home security without cloud surveillance" width="1200" />
</p>

# Secluso

Private DIY home security for Raspberry Pi, with encrypted remote access and a 2-minute setup.

[Download Secluso Deploy](https://github.com/secluso/secluso/releases) • [Build Your Own Guide](https://secluso.com/build-your-own) • [Security Model](SECURITY.md) • [Website](https://secluso.com)

</div>

Secluso is a private home security camera system for Raspberry Pi. Watch live video, get alerts, and open recordings from your phone without handing your footage to a cloud provider.

Secluso is developed by Secluso, Inc. and co-founded by Ardalan Amiri Sani, a UC Irvine professor with expertise in computer security and privacy.

## Features

- **End-to-end encrypted remote access:** Watch live video, get alerts, and open recordings from your phone.
- **2-minute setup:** Secluso Deploy handles image building, pairing, and relay setup in the normal path.
- **Open source:** Inspect the code, self-host it, and contribute.
- **Reproducible releases:** Verify the released binaries against the public source code.

## Requirements

- **Raspberry Pi:** Raspberry Pi Zero 2W or Raspberry Pi 4
- **Camera:** Raspberry Pi Camera Module
- **Relay:** your own Linux VPS login, or an email to us for free beta relay hosting while testing
- **Phone:** Android or iPhone for pairing, alerts, and playback

## Set up in 5 minutes (Quick Start)

1. Download **Secluso Deploy** from the [latest releases](https://github.com/secluso/secluso/releases).
2. Choose your Raspberry Pi target, build the image locally, and save the pairing QR code.
3. Let Secluso Deploy provision your relay over SSH, or email us if you want free beta relay hosting while testing.
4. Boot the Pi and pair it in the mobile app.

If you are still choosing hardware or a VPS, [Build Your Own Guide](https://secluso.com/build-your-own) gives you hardware suggestions and a simple starting path.

<!--
TODO: A polished GIF showing Secluso Deploy 
-->

## Mobile App

After setup, use the mobile app to check in remotely, review recent events, and open encrypted clips.

<!--
GIF of mobile apps
-->

## Security

See [SECURITY.md](SECURITY.md) for the full security model, including the untrusted-relay design, forward secrecy, and post-compromise security.

## Reproducible Builds

We do not distribute a prebuilt Raspberry Pi image. Secluso Deploy assembles the image on your machine from released binaries produced by Secluso's deterministic build pipeline, so the software you run can be checked against the public source code instead of taken on faith.

See [releases/README.md](releases/README.md) for the reproducibility checker.

## Documentation and Help

Need hardware suggestions, a starter VPS, or a short BYO walkthrough? See [Build Your Own](https://secluso.com/build-your-own). If you get stuck, email [secluso@proton.me](mailto:secluso@proton.me). We are happy to help whether or not you ever buy from us.

## Contributing

Questions and contributions are welcome. Contributions are made under the project license in [LICENSE](LICENSE).

## Project Founders

- Ardalan Amiri Sani (UC Irvine professor focused on computer security and privacy)
- John Kaczman (Open source and privacy enthusiast with experience in automation, systems, and AI)

Secluso is developed and supported by Secluso, Inc.

## Disclaimers

This project uses cryptography. Check your local laws before use.

Use at your own risk. The project authors provide no guarantees of privacy or home security.
