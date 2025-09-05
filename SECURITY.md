# Secluso's Security Details

## Table of Contents
- [Threat Model and Guarantees](#threat-model-and-guarantees)
- [End-to-End Encryption](#end-to_end-encryption)
  - [Group Membership](#group-membership)
  - [Forward Secrecy and Post-Compromise Security](#forward-secrecy-and-post-compromise-security)
    - [Analysis](#analysis)
- [Pairing](#pairing)
- [Reproducible Builds](#reproducible-builds)

## Threat Model and Guarantees

The key advantage of Secluso over existing home security camera solutions is that it provides strong privacy assurance using end-to-end encryption.
More specifically, it makes the following assumptions:

* It assumes that the machine running the hub (e.g., Raspberry Pi or the local machine connected to IP cameras) and the smartphone running the mobile app are secure and not compromised.
* It assumes that the server is fully untrusted and under the control of the adversary.
* It makes minimal trust assumptions about IP cameras. That is, it assumes that the camera does not have a covert, undisclosed network interface card (e.g., cellular) to connect to the Internet on its own (therefore, it's best that this is explicitly checked and verified by user). Other than that, the IP camera is untrusted and hence Secluso does not directly connect the camera to the Internet; rather, the camera is connected to the hub directly.

It then provides the following guarantees:

* It guarantees that only the hub and the mobile app have access to unecrypted videos.
* It guarantees that the server cannot decrypt the videos.
* It provides forward secrecy and post-compromise security through MLS.
* It does NOT currently hide the timing of events and livestreams from the adversary (who we assume is in control of the server and/or FCM channel).

## End-to-End Encryption

Secluso uses end-to-end encryption between the camera and the app.
That is, the camera always encrypts the videos (either event-triggered videos and their thumbnails or livestream videos) using keys only available to the camera and the app.
It then sends the videos to the apps, which can decrypt them.
The videos are sent to the app via a server.
The server is fully untrusted.
It only sees encrypted video files, but is not able to decrypt them.

Secluso uses Messaging Layer Security (MLS) for its end-to-end encryption.
MLS is an Internet Engineering Task Force (IETF) standard (RFC 9420: https://www.rfc-editor.org/rfc/rfc9420).
More specifically, Secluso uses OpenMLS, an open source implementation of MLS in Rust.

MLS is designed for secure messaging using end-to-end encryption.
Secluso leverages MLS by breaking down videos into small chunks that are then encrypted by MLS.

### Group Membership

A key feature of MLS is its support for group messaging.
In Secluso, in the pairing phase, the camera creates an MLS group and then invites the app to join the group.
This then allows the camera and the app to exchange encrypted messages.
Secluso in fact uses multiple MLS groups, one for event-based videos, one for livestream, one for FCM notifications, one for configuration messages, and one for video thumbnails.
It only provides post-compromise security for the first two since they are used for transferring videos.
The rest of the discussion here mainly focuses on these two groups.

Secluso currently limits group membership to two members only since its authentication service cannot authenticate any members beyond the camera and the app that pairs with it.
That is, after the app joins the camera's group, the camera does not invite any other entities to join the group.
This means that Secluso only support one app instance to use a camera.
We plan to remove this limitation in the future.

### Forward Secrecy and Post-Compromise Security

MLS provides two important security properties: forward secrecy and post-compromise security.
The former means that if a group member (camera or app here) is compromised (including all the MLS state files and keys), it cannot be used to decrypt any of the previous messages (and hence videos).
To achive this, MLS changes the keys it uses for every message.
Both members of the MLS group follow the same key schedule and hence are able to continue exchanging messages.

But if a group member is compromised, the attacker could potentially follow the same key schedule and hence decrypt all future messages.
This is where the latter guarantee, i.e., post-compromise security, comes into play.
Every once in a while, fresh group secrets are shared between the group members.
At this point, we say that a new epoch has started.
Assuming the attacker cannot receive the new secrets, it will not be able to decrypt messages in the new epoch.
To make sure this assumption is correct, group members need to update their *encryption keys*, i.e., public/private key pairs used for sharing new secrets.
This is also called *self-update* in the MLS terminology.

An MLS group always starts in epoch 1 and advances to new epochs by exchanging fresh secrets.
MLS does not automatically advance the epoch and leaves it to the program to decide when to do that.
Secluso uses a new epoch for every new event-based video, every livestream session, and every video thumbnail.
The epoch is advanced by the camera and the camera always performs a self-update for the new epoch.

More specifically, to advance an epoch, the camera issues an MLS self-update process, which generates an MLS commit message.
It then merges the commit, which means that it advances the epoch.
It also sends the commit messages to the app.
For event-based videos and thumbnails, the commit message is included in the beginning of the encrypted file.
For livestreams, it is sent as livestream chunk 0, before data chunks are transmitted.

The app on the other hand does not perform self-updates directly and as frequently (since doing those will complicate the protocol design).
Instead, it issues a self-update proposal and sends it to the camera every time it sends a heartbeat message.
Currently, the app is programmed to send a heartbeat message every time the app is launched and every 6 hours.
The camera then includes this proposal in the next commit message used for the next video.

Post-compromise security by advancing the epochs creates a challenge: if the commit message is lost, the camera and app will not be able to communicate anymore since they are in different epochs.
Secluso uses various techniques to reduce the likelihood of losing a message.
For example, we systematically look for and fix what we call "fatal crash points."
These are code locations within the camera or app that if a crash occurs, the camera and the app will end up in different epochs.
For example, imagine what happens if the camera generates the commit message, merges it, persists the new keys in storage, deletes the old keys, and then crashes before sending the commit message to the app.
If the camera is launched again, it will now be in a different epoch than the app and there is no way to recover from that.
We call this a fatal crash point.
This example fatal crash point can then be fixed by making sure that a copy of the commit message is persisted in storage before it is merged.

We note that OpenMLS can be configured to allow decryption of messages of certain number of epochs in the past.
While useful to mitigate some of the issues mentioned in the last paragraph, we opted against using this feature since it weakens forward secrecy.
More specifically, this feature maintains keys used in the previous epochs and does not immediately delete them when epoch changes.
This will then enable an attacker than manages to compromise a group member to decrypts videos from previous epochs.

#### Analysis

We can now analyze our aforementioned protocol and understand the forward secrecy and post-compromise security guarantees provided by Secluso.
For this analysis, we assume an attacker that compromises the camera or the app and takes a copy of all the Secluso files in them.
We however do not assume a persistent compromise.
That is, the attacker cannot continue to access the files on the device going forward.
Against such an attacker, we can provide forward secrecy, but not post-compromise security.
Also, for simplicity, we first assume that the camera and app do not store any of the previous videos.
We will then relax this assumption at the end of this analysis.

First, consider the case where the attacker compromises the camera.
The attacker could achieve this, for example, by physically accessing the camera, removing the micro SD card, and copying all the relevant files.
This attacker will only be able to decrypt one video (one motion video and one livestream session) and one thumbnail.
It cannot decrypt any videos from before or after.

Second, consider the case where the attacker compromises the app.
This attacker cannot decrypt any of the video from the past.
It can however decrypt motion and livestream videos and thumbnails from the point of compromise until when the app sends a heartbeat message to the camera.
Note that we assume that attacker is not capable of blocking heartbeats.
If heartbeats are blocked, the user will receive notifications saying that the camera seems to be offline.
In such a case, the user needs to look into the issue immediately.

As mentioned earlier, we assumed that the camera and the app did not store any of the previous videos at the time of compromise.
In practice, that's not the case.
The app stores the videos until deleted by the user.
The camera stores the event-based videos until it receives a heartbeat (which also acts as an ack).
This impacts forward secrecy.
For the app, it is our recommendation that the user deletes old videos as often as possible.
For the camera, this means that forward secrecy window could be as large as 6 hours (assuminmg the app does not miss heartbeats).

## Pairing

Secluso has a secure pairing process to ensure that only the camera owner's app can establish an MLS connection (i.e., an MLS group) with the camera and that pairing needs to take place when the smartphone running the app and the camera are in close physical proximity.
When the camera is turned on for the first time or upon a factory-reset, it listens for wireless connections from devices in its vicinity.
It does so by creating a WiFi hotspot and waiting for connections.
When another device connects to the hotspot, the camera exchanges MLS key packages with the device in order to establish an MLS group.
To ensure that only the owner's app can successfully pair with the camera, Secluso provisions a secret inside the camera and shares that secret with the owner in the form of a QR code.
During the pairing process, the owner needs to scan this QR code.
The owner is required to keep this secret confidential.

How is the secret used to secure the pairing process? Secluso uses a feature of MLS called "external pre-shared key (psk)." Both the camera and the app need to inject this secret into their key schedule via an external psk.
If either fails to do so, the app cannot successfully join the MLS group created by the camera.

Using the aforementioned techniques, Secluso guarantees that for an app to be able to successfully pair with the camera, it needs to be on a smartphone in physical proximity of the camera, and it needs to have access to the secret.
We assume that the attacker does not have access to the secret and/or cannot be in physical proximity of the camera.

It is important to note that the MLS standard defines an "authentication service."
This service needs to be implemented by a program using MLS and its role is to enable members of a group to authenticate each other.
Secluso's secure pairing process plays this role.
In other words, the camera and the app authenticate each other using the secret available only to them.

## Reproducible Builds

Secluso supports reproducible builds for all distributed binaries.  
This ensures that the code you see in this repository can be independently verified against the binaries we publish.  

To avoid duplication, we do not repeat the full technical details here.  
Instead, please see [releases/README.md](releases/README.md) for a complete description of our reproducible build pipeline,  
including step-by-step instructions on how to rebuild and verify our releases yourself.
