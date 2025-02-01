## Instructions

Privastead is fully open source and hence can be used by anyone interested in it.
Below are the instructions.

### Requirements

You will need the following:

- An IP camera (see [here](README.md) for the list of IP cameras tested with Privastead).
- A smartphone (see [here](README.md) for the list of smartphones tested with Privastead).
- A local machine (e.g., a laptop or desktop). The local machine will be connected to the IP camera and to the Internet.
- A server. The server needs to be accessible by the hub and the mobile app on the smartphone. Given that the smartphone could be connected to various networks, the server should have a public IP address. We refer to this address as the server IP address going forward.
- A Google account to set up the FCM project. (Create a new account. Don't use your personal account.)

Fetch the Privastead source code both in the hub and in the server:

```
git clone https://github.com/privastead/privastead.git
```

### Step 1: Generating Privastead credentials

The server is fully untrusted and cannot decrypt videos.
Yet, we have a simple authentication protocol between the hub/app and the server in order to prevent unauthorized access to the server (since servers cost money and you may not want others to use your server.)

To generate credentials, do the following (preferrably in the local machine):

```
cd privastead/config_tool
cargo run -- --generate-user-credentials --dir .
```

This generates two files: user_credentials and user_credentials_qrcode.png.
We will use the former for the camera hub and the server and the latter for the app.
Keep these files in mind and we will come back to using them in the following steps.

### Step 2: Generating FCM credentials

Privastead uses FCM to send notifications to the android app.
We need to set up an FCM project and then generate two credential files, one for the server to be able to send notifications via FCM and one for the app to be able to receive them.

Go to: https://console.firebase.google.com/

(Sign in to the Google account you created if you have not.)

Click on "Create a project."

Enter the project name, e.g.: Privastead

Disable Google Analytics (unless you want it).

The project is now created and you will be redirected to its dashboard.

Click on "Add app" and then on the Android icon.

Now you need to register our app. For the package name, add: privastead.camera

Then click on Register App. You will now be able to download the file: google-services.json. Download it and save it somewhere. You'll need in one of the steps below.

You don't need to continue with the rest of the steps (as we have already done those for the app).

Now go back to the Firebase project dashboard. Click on the Settings icon next to the project overview on the top left. Then click "Project settings".

On the top, click on the "Service accounts" tab, then on Generate new private key, and (read the warning) then Generate key.

This will create a json file for you. As the warning said, it includes a private key. Therefore, do not share it publicly. Rename this file to: service_account_key.json

Hold on to the file for now. We'll use it in the next step.

### Step 3: Running the server

The server needs to be able to send notification requests to FCM. Therefore, copy the service_account_key.json file generated in the last step in the Privastead server directory.

```
mv /path-to-json-file/service_account_key.json /path-to-privastead/server/
```

To run the server, you need to execute this command:

```
cd /path-to-privastead/server/
cargo run --release -- -p 12346
```

However, the server program might crash.
Or your server machine (e.g., a VM) might reboot.
Therefore, we suggest using a systemd service to ensure that the server program is restarted after every crash and after every reboot.
You can find instructions to do this online, e.g., ([here](https://www.shubhamdipt.com/blog/how-to-create-a-systemd-service-in-linux/)).

Here is an example of what the service file could look like:

```
[Unit]
Description=privastead_server

[Service]
User=your-username
WorkingDirectory=/absolute-path-to-privastead-source/server/
ExecStart=/absolute-path-to-cargo-executable/cargo run --release -- -p 12346
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
```

Put these inside the file "/etc/systemd/system/privastead.service".
Then do the following

```
sudo systemctl daemon-reload
sudo systemctl start privastead.service
```

Then, check to make sure it's correctly started:

```
sudo systemctl status privastead.service
```

Finally, enable it so that it runs on every reboot:

```
sudo systemctl enable privastead.service
```

### Step 4: Configuring the IP camera and connecting it to your local machine

Our goal is to connect the camera to your local machine (aka machine) without giving the IP camera Internet access.
You will use this local machine later to run the Privastead camera hub software.
To achieve this, we will use two network interfaces of the machine.
One will be used for Internet access for the machine and the other will be used to create a local network to connect the IP camera to the machine.
For example, assume the machine has Ethernet and WiFi interfaces.
The IP camera should be connected to the machine using Ethernet.
Therefore, you will use WiFi for Internet access for the machine.
This is the setup for which we provide instructions below.

Note: you might wonder if you can connect the camera wirelessly to the local machine? This is technically doable, but it opens up an attack vector. The videos will be transmitted unencrypted from the camera to the local machine. An attacker present in the vicinity of your house can then snif the packets and record the videos. Therefore, we do not recommend this setup and do not provide instructions on how it could be configured.

Back to instructions:

Create a local network on the machine's Ethernet interface:

```
sudo ip addr add 192.168.1.1/24 dev [eth0]
```

(Note that you might need to rerun this command if you reboot your local machine or if you disconnect/reconnect the camera's Ethernet cable.)

Replace [eth0] with your interface name.

To find your Ethernet interface name, you can run:

```
ifconfig
```

Then, connect the IP camera with an Ethernet cable to the machine.
Now, we need to find the IP address assigned to the IP camera. Run:

```
nmap -sP 192.168.1.1/24
```

You'll see 192.168.1.1 (which is the machine) and another one (let's say 192.168.1.108) for the IP camera.
Record the IP camera's IP address. You will use it in the next steps and also later for configuring the Privastead camera hub software.

Now open a browser in the local machine and put the IP camera's address there.
You'll see the camera's web interface.
Enter the default username and password (admin and admin on my camera).
It will then ask you to change the password.
Choose a strong password.

In the camera's web interface, do the following (note that these instructions are for the aforementioned Amcrest camera):

1) Go Setup -> Camera -> Video -> Main Stream. Set the Encode Mode to H.264, Smart Codec to Off, resolution to 1280x720(720P), framerate to 10, Bit Rate Type to CBR, and Bit Rate to Customized. Then uncheck Watermark Settings, and disable Sub stream. Make sure to press Save. These suggestions (and the ones below for audio) are simply based on my experience. With these, the videos have adequate quality and Privastead achieves good performance. You might need to change these based on your network connection's bandwidth.

2) Then go to Setup -> Camera -> Audio. Under Main Stream, set Encode Mode to AAC and sampling frequency to 8000. Disable Sub Stream. Press Save.

3) Go Setup -> Camera -> Video -> Overlay. Disable Channel Title, Time, and Logo Overlay to remove clutter from the video.

4) Go to Setup -> System -> General -> Date&Time. Set the date (including the correct timezone) and press on PC Sync. The latter syncs the time on the camera to that of the local machine.This step is needed since without it, the Privastead hub cannot authenticate to the IP camera through the ONVIF interface. (Quite annoyingly) you'll have to redo this last step (the PC Sync) whenever you reset the camera (e.g., unplug/plug).

You are now done configuring the camera. Make sure to connect the machine to the Internet using WiFi.

### Step 5: Configuring and running camera hub

Copy over the example_cameras.yaml file into cameras.yaml
```
cp example_cameras.yaml cameras.yaml
```

You can add as many cameras as you want by copy and pasting the individual camera blocks
```
  - name: "Front Door"
    ip: "IP address of camera configured in Step 3"
    rtsp_port: 554
    username: "username here"
    password: "password here"
```

You may choose to omit the username and password, which will instead prompt you upon executing the program below.

The RTSP port is usually 554, but may vary depending on your camera.

```
mv /address/to/user_credentials /path-to-privastead/camera_hub
cd /path-to-privastead/camera_hub
cargo run --release --
```

The Privastead hub will now run and ask you for the username and password for each IP camera if not provided originally in the configuration file. 
After providing them, it will create a QR code containing a secret needed for pairing (camera_hub/camera_name_secret_qrcode.png).
Each camera then waits to be paired with the app.

### Step 6: Building and installing the app

Fetch the app from our repo:

```
git clone https://github.com/privastead/android_app.git
```

Then copy the google-services.json generated in an earlier step into the app source code:

```
mv /path-to-json-file/google-services.json /path-to-app-source/android_app/app/
```

The app uses a native JNI library implemented in Rust for OpenMLS and for communication with the server.
You'll need to build this library and copy it to the app source tree.

First, let's build the library:

```
cd /path-to-privastead/android_app_native
cargo ndk -t arm64-v8a build --release
```

Note that we're building it for the arm64-v8a architecture.
This is the architecture used in most modern phones and the only one we have tested.

Now, copy the library to the Android app source tree:

```
mkdir -p /path-to-privastead-android-app/app/src/main/jniLibs/arm64-v8a
cp /path-to-privastead/android_app_native/target/aarch64-linux-android/release/libprivastead_android_app_native.so \
	    /path-to-privastead-android-app/app/src/main/jniLibs/arm64-v8a/libprivastead_android_app_native.so

```

Now you need to build the app and install it on the device.
We recommend using the Android Studio.
We don't provide more details on that here since there are plenty of resources online.

### Step 7: Pairing the app with the hub

When you first run the app, it will ask you for the IP address of teh server and credentials needed to access the server in the form of a QR code.
Enter the IP address.
Then scan user_credentials_qrcode.png file that you generated in Step 1.
Note that the app will ask you for permission to access the camera in order to scan the QR code.
It is enough to give one-time access to the app.
It does not need the camera other than for scanning QR codes (also needed when pairing with the camera).

Next, the app will ask you for notifications permissions.
Grant the permissions if you want to receive motion notifications.

Next, you will go to the main app page.
To pair with the camera, press the + button on the bottom right of the screen.
A new activity will be launched asking you to enter a name for the camera, the IP address of the hub, and the camera secret QR code.
The name can be anything you'd like to use to refer to the camera (anything without a space).
The IP address is the address of the hub (not the IP camera!).
The smartphone running the app and the machine running the hub need to be connected to the same network for the pairing process.
Therefore, make sure they are both connected to the same router.
To find the IP address of the hub, you can again use the ifconfig command.
The QR code is the one that the camera hub generated (camera_hub/camera_name_secret_qrcode.png).
Once you've provided all, click on ADD CAMERA.
The camera hub and the app should be paired now.
The camera hub will also print:

```
[Camera Name] Pairing successful.
[Camera Name] Running...
```

At this point, the system is operational.
Whenever the camera detects motion, the camera hub will record a video and send it to the app.
Also, in the app, you can livestream the camera.