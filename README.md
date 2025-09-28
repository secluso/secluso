<p align="center">
  <img src="https://github.com/secluso/images/blob/main/banner.svg" alt="Secluso" />
</p>

# Secluso

Secluso is a privacy-preserving home security camera solution that uses end-to-end encryption.
In Secluso, the camera encrypts the videos end-to-end for the app on the user's smartphone.
Videos are relayed by a server, but the server cannot decrypt them.

Secluso has two key benefits:

* **End-to-end encryption** using the OpenMLS implementation of the Messaging Layer Security (MLS) protocol.
* **Rust** implementation.

## Components

Secluso has three components:

* A **camera hub** that records, encrypts, and sends videos.
* A **mobile app** that allows one to receive event notifications (e.g., person or motion) from the camera as well as livestream the camera remotely.
* An **untrusted server** that relays (encrypted) messages between the hub and the app. In addition, Secluso uses the Google Firebase Cloud Messaging (FCM) for notifications. Similar to the server, FCM is untrusted.

## Camera types

Secluso supports two types of cameras.

* **Standalone camera** using a Raspberry Pi. In this case, the camera hub runs directly on the Raspberry Pi.
* Commercial **IP cameras**. In this case, the camera hub runs on another machine and works with existing IP cameras with minimal trust assumptions about these cameras.

### Plug-and-play camera

We are also working on a plug-and-play camera based on our Raspberry Pi prototype. The goal is to make our camera more accessible to people who need a private camera but don't have time to set up our open-source project. Below is a photo of this plug-and-play camera. If you're interested, check out our website [here](https://secluso.com) and join our mailing list on the website. We will be sending updates on our plug-and-play camera as well as our progress on our open source software.

<p align="center">
  <img src="https://secluso.com/images/Group-5.png" alt="Secluso plug-and-play camera" />
</p>

## Security

Secluso has been carefully designed to strongly protect the user's videos against an attacker that might try to access and view them.
It provides advanced encryption guarantees, namely **forward secrecy** and **post-compromise security**.
For a more accurate and detailed discussion of its security guarantees, please see [here](SECURITY.md).

## Event detection

The camera hub is capable of detecting various events and sending a notification to the mobile app.

* Events supported for the standalone camera: motion, person, pet, vehicle

* Events supported for IP cameras: motion

## Supported Cameras

* Standalone camera: Secluso should be able to run on any Raspberry Pi boards that is capable of running its event detection pipeline.
So far, the following boards have been successfully tested:

  * Raspberry Pi Zero 2W
  * Raspberry Pi 4

* IP camera: Secluso camera can theoretically support any IP camera (or any other camera that has an open interface).
The current prototype relies on RTSP and MJPEG support by the camera.
The former is used for streaming videos from the camera and the latter is used for a custom motion detection implementation.
So far, the following cameras have been tested:

  * Amcrest, model: IP4M-1041W ([Link](https://www.amazon.com/Amcrest-UltraHD-Security-4-Megapixel-IP4M-1041W/dp/B095XD17K5/) on Amazon)
    * Software Version: V2.800.00AC006.0.R, Build Date: 2023-10-27
    * WEB Version: V3.2.1.18144

## Supported mobile OSes

* Android
* iOS

## Tested smartphones (OS version)

* Google Pixel 8 Pro (Android 15)
* Google Pixel 7 (Android 14)
* Moto G 5G (2024) (Android 14)
* iPhone 16 Pro (iOS 18.5)

## (Current) key limitations

* The camera hub pairs with one app instance only.
* Performance may become a bottleneck for high camera resolutions and frame rates.

## Instructions

See [here](HOW_TO.md) for instructions for setting up Secluso.

## Contributions

We welcome contributions to the project. Before working on a contribution, please check with us via email: secluso@proton.me

Contributions are made under Secluso's [license](LICENSE).


## Project Founders

* Ardalan Amiri Sani (Ph.D., Computer Science professor at UC Irvine with expertise in computer security and privacy)
* John Kaczman (Open source and privacy enthusiast. Experienced in automation, systems and AI)

Note: this is a side project of Ardalan Amiri Sani and John Kaczman, who work on it in their spare time.

## Disclaimers

This project uses cryptography libraries/software. Before using it, check your country's laws and regulations.

Use at your own risks. The project authors do not provide any guarantees of privacy or home security.
