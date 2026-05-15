# Secluso: A Home Security Camera Designed to Protect User Privacy

## Table of Contents
- [End-to-End Encryption](#end-to-end-encryption)
  - [Threat Model and Guarantees](#threat-model-and-guarantees)
- [Verifiability by users and auditors](#verifiability-by-users-and-auditors)
  - [Open Source Software](#open-source-software)
  - [Reproducible Builds](#reproducible-builds)
  - [Immutable Releases](#immutable-releases)

The goal of Secluso is to provide a home security camera solution that strongly protects the privacy of its users, while being easy-to-use and providing important features available in commercial (non-private) alternatives.
To achieve its privacy goal, Secluso uses two key principles:

* End-to-end encryption
* Verifiability by users and auditors

Next, we provide more details on each of these principles.

## End-to-End Encryption

Secluso uses end-to-end encryption between the camera and the app.
That is, the camera always encrypts the videos (either event-triggered videos and their thumbnails or livestream videos) using keys only available to the camera and the app.
It then sends the videos to the apps, which can decrypt them.
The videos are sent to the app via a server, which is fully untrusted: it only sees encrypted video files, but is not able to decrypt them.

Secluso uses Messaging Layer Security (MLS) for its end-to-end encryption.
MLS is an Internet Engineering Task Force (IETF) standard (RFC 9420: https://www.rfc-editor.org/rfc/rfc9420).
More specifically, Secluso uses OpenMLS, an open source implementation of MLS in Rust.
Please see [ENCRYPTION.md](ENCRYPTION.md) for the details of how we use MLS in this project and the guarantees it provides.

### Threat Model and Guarantees

Secluso makes the following assumptions in its end-to-end encryption:

* It assumes that the camera and the smartphone running the mobile app are secure and not compromised.
* It assumes that the server is fully untrusted and under the control of the adversary.

It then provides the following guarantees:

* It guarantees that only the hub and the mobile app have access to unecrypted videos.
* It guarantees that the server cannot decrypt the videos.

Note: Secluso does NOT currently hide the timing of events, livestreams, or notification delivery from the adversary (who we assume may control the server and the notification transport). On Android, that transport is FCM/UnifiedPush. On iOS, that transport is the Secluso iOS relay and APNS.

## Verifiability by users and auditors

Many products, including security cameras, try to address privacy concerns by simply releasing a "Privacy Policy" and promising to follow some privacy practices, e.g., not sharing users' data with third parties.
However, they offer no way for users and independent auditors to verify that they uphold these promises.
We have designed Secluso differently.
We designed it so that Secluso's privacy guarantees are verifiable by users and auditors: we should not be able to violate the privacy guarantees even if we wanted to!
While we do not have any intentions of violating users' privacy, we do not include "trust in ourselves" as an assumption in our design.

To achieve this goal, we use the following techniques:

* Open source software
* Reproducible builds
* Immutable releases

### Open Source Software

A key aspect of Secluso is its fully open source software. This includes the camera firmware as well as the mobile app, both of which are critical to ensuring user privacy. The availability of software allows users as well as independent auditors to inspect the code and check all our claims, e.g., end-to-end encryption.

### Reproducible Builds

The availability of our software allows a user to build all the required binaries from our source, ensuring that the binaries are compiled from our sources.
However, most users will not build our source code on their own.
Rather, they use the binaries we release.
In order to enable users and auditors to verify that our binaries are built from our source code, Secluso supports reproducible builds for all distributed binaries.
This ensures that the code you see in this repository can be independently verified against the binaries we publish.

To avoid duplication, we do not repeat the full technical details here.
Instead, please see [releases/README.md](releases/README.md) for a complete description of our reproducible build pipeline, including step-by-step instructions on how to rebuild and verify our releases.

### Immutable Releases

Secluso enables the camera to update its firmware by fetching the latest firmware binaries released in our Github repository.
This raises a concern: what if we (or an attacker who has compromised our Github accounts) release a malicious binary and then delete it shortly thereafter?
This will compromise users' cameras, while potentially leaving no trace for third-party auditing.
To defeat such an attack, we require immutable storage for our releases.
We currently use Github immutable releases, which ensures that a released binary cannot be deleted for good.
This way, any released binary will be available for users and auditors to inspect and study.
Moreover, our update logic in the camera firmware always checks the immutability of the release before fetching it.

