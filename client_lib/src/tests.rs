//! SPDX-License-Identifier: GPL-3.0-or-later

/// Before running the tests:
/// 1. Create the test_data folder and copy the user_credentials file in it (credentials not needed for the pairing_test).
/// 2. Run the deliver service locally and on port 12346.
/// 3. Make sure to use --test-threads=1. Tests might reuse file addresses and hence will corrupt each other if run
/// in parallel.

#[cfg(test)]
mod tests {
    use crate::pairing::{App, Camera, NUM_SECRET_BYTES};
    use crate::user::{KeyPackages, User};
    use std::fs;
    use std::io;
    use std::io::{BufRead, BufReader};
    use std::net::TcpStream;

    const GROUP_NAME: &str = "group";
    const SERVER_ADDR: &str = "127.0.0.1:12346";

    #[test]
    fn pairing_test() {
        let secret: [u8; NUM_SECRET_BYTES] = [
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2,
            3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
        ];

        let camera_server_stream = TcpStream::connect("127.0.0.1:12346").unwrap();
        let app_server_stream = TcpStream::connect("127.0.0.1:12346").unwrap();
        let credentials = get_user_credentials();

        let camera_client = User::new(
            "camera".to_string(),
            camera_server_stream,
            true,
            true,
            "test_data".to_string(),
            "camera".to_string(),
            credentials.clone(),
            false,
        )
        .map_err(|e| {
            println!("User::new() returned error:");
            e
        })
        .unwrap();

        let app_client = User::new(
            "app".to_string(),
            app_server_stream,
            true,
            true,
            "test_data".to_string(),
            "app".to_string(),
            credentials.clone(),
            false,
        )
        .map_err(|e| {
            println!("User::new() returned error:");
            e
        })
        .unwrap();

        // app key packages
        let app_key_packages: KeyPackages = app_client.key_packages();

        // camera key packages
        let camera_key_packages: KeyPackages = camera_client.key_packages();

        let app = App::new(secret, app_key_packages.clone());
        let camera = Camera::new(secret, camera_key_packages.clone());

        let msg = app.generate_msg_to_camera();

        // send msg to camera here
        let (received_app_key_packages, msg2) = camera.process_app_msg_and_generate_msg_to_app(msg);

        // send msg to app here
        let received_camera_key_packages = app.process_camera_msg(msg2);

        assert!(app_key_packages == received_app_key_packages);
        assert!(camera_key_packages == received_camera_key_packages);
    }

    fn get_user_credentials() -> Vec<u8> {
        let pathname = "./test_data/user_credentials";
        let file = fs::File::open(pathname).expect("Could not open user_credentials file");
        let mut reader =
            BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
        let data = reader.fill_buf().unwrap();

        data.to_vec()
    }

    fn pair() -> (User, User) {
        let credentials = get_user_credentials();

        let _ = fs::remove_dir_all("test_data/camera");
        fs::create_dir("test_data/camera").unwrap();
        let _ = fs::remove_dir_all("test_data/app");
        fs::create_dir("test_data/app").unwrap();

        let stream_camera = match TcpStream::connect(SERVER_ADDR.to_string()) {
            Ok(stream) => stream,
            Err(e) => {
                panic!("Error: Could not connect to the server: {e}");
            }
        };

        let stream_app = match TcpStream::connect(SERVER_ADDR.to_string()) {
            Ok(stream) => stream,
            Err(e) => {
                panic!("Error: Could not connect to the server: {e}");
            }
        };

        // Create clients
        let mut camera = User::new(
            "camera".to_string(),
            stream_camera,
            true,
            true,
            "test_data/camera".to_string(),
            "camera".to_string(),
            credentials.clone(),
            false,
        )
        .unwrap();

        let mut app = User::new(
            "app".to_string(),
            stream_app,
            true,
            true,
            "test_data/app".to_string(),
            "app".to_string(),
            credentials,
            false,
        )
        .unwrap();

        // Exchange key packages, create group, invite, and join
        let camera_contact = camera
            .add_contact("app".to_string(), app.key_packages())
            .unwrap();
        let app_contact = app
            .add_contact("camera".to_string(), camera.key_packages())
            .unwrap();

        camera.create_group(GROUP_NAME.to_string());
        camera.save_groups_state();

        camera
            .invite(&camera_contact, GROUP_NAME.to_string())
            .unwrap();
        camera.save_groups_state();

        app.receive_welcome(app_contact).unwrap();
        app.save_groups_state();

        (camera, app)
    }

    fn reinitialize_app() -> User {
        let credentials = get_user_credentials();

        let stream_app = match TcpStream::connect(SERVER_ADDR.to_string()) {
            Ok(stream) => stream,
            Err(e) => {
                panic!("Error: Could not connect to the server: {e}");
            }
        };

        let app = User::new(
            "app".to_string(),
            stream_app,
            false, // not the first time
            false, // no need to reregister with the server
            "test_data/app".to_string(),
            "app".to_string(),
            credentials,
            false,
        )
        .unwrap();

        app
    }

    #[test]
    /// Camera invites app and immediately sends a message to it.
    fn camera_to_app_message_test() {
        let (mut camera, mut app) = pair();

        // Camera sends a message
        let message = "Hello, app!".to_string();
        camera
            .send(message.clone().as_bytes(), GROUP_NAME.to_string())
            .unwrap();

        //App receives the message
        let mut message_received = false;
        let callback = |msg_bytes: Vec<u8>, contact_name: String| -> io::Result<()> {
            message_received = true;
            assert!(contact_name == *"camera");
            assert!(String::from_utf8(msg_bytes).unwrap() == message);

            Ok(())
        };

        app.receive(callback).unwrap();
        assert!(message_received);

        camera.deregister().unwrap();
        app.deregister().unwrap();
    }

    #[test]
    /// Camera invites app and the app immediately sends a message to camera.
    fn app_to_camera_message_test() {
        let (mut camera, mut app) = pair();

        //App sends a message
        let message = "Hello, camera!".to_string();
        app.send(message.clone().as_bytes(), GROUP_NAME.to_string())
            .unwrap();

        //App receives the message
        let mut message_received = false;
        let callback = |msg_bytes: Vec<u8>, contact_name: String| -> io::Result<()> {
            message_received = true;
            assert!(contact_name == *"app");
            assert!(String::from_utf8(msg_bytes).unwrap() == message);

            Ok(())
        };

        camera.receive(callback).unwrap();
        assert!(message_received);

        camera.deregister().unwrap();
        app.deregister().unwrap();
    }

    #[test]
    /// Camera invites app and immediately sends a message to it.
    /// It then does a self update and sends another message.
    fn update_test() {
        let (mut camera, mut app) = pair();

        //Camera sends a message
        let message = "Hello, app!".to_string();
        camera
            .send(message.clone().as_bytes(), GROUP_NAME.to_string())
            .unwrap();

        //App receives the message
        let mut message_received = false;
        let callback = |msg_bytes: Vec<u8>, contact_name: String| -> io::Result<()> {
            message_received = true;
            assert!(contact_name == *"camera");
            assert!(String::from_utf8(msg_bytes).unwrap() == message);

            Ok(())
        };

        app.receive(callback).unwrap();
        assert!(message_received);

        //Camera performs an MLS update.
        camera.perform_update(GROUP_NAME.to_string()).unwrap();
        camera.send_update(GROUP_NAME.to_string()).unwrap();

        //Camera sends the second messages
        let message2 = "Hello, again!".to_string();
        camera
            .send(message2.clone().as_bytes(), GROUP_NAME.to_string())
            .unwrap();

        //App receives the update.
        let callback_app = |_msg_bytes: Vec<u8>, _contact_name: String| -> io::Result<()> {
            println!("contact_name = {:?}", _contact_name);
            Ok(())
        };

        app.receive(callback_app).unwrap();

        //App receives the message
        let mut message2_received = false;
        let callback = |msg_bytes: Vec<u8>, contact_name: String| -> io::Result<()> {
            message2_received = true;
            assert!(contact_name == *"camera");
            assert!(String::from_utf8(msg_bytes).unwrap() == message2);

            Ok(())
        };

        app.receive(callback).unwrap();
        assert!(message2_received);

        camera.deregister().unwrap();
        app.deregister().unwrap();
    }

    #[test]
    /// Camera invites app and immediately sends a message to it.
    /// It then does a self update, does not send the update, but sends another message
    /// (which cannot be successfully decrypted by the app).
    /// The camera then sends the update, followed by another message
    /// (which should be successfully decrypted by the app).
    /// This is important to ensure that a loss of an update message does not break the
    /// channel permanently.
    fn update_no_send_first_test() {
        let (mut camera, mut app) = pair();

        //Camera sends a message
        let message = "Hello, app!".to_string();
        camera
            .send(message.clone().as_bytes(), GROUP_NAME.to_string())
            .unwrap();

        //App receives the message
        let mut message_received = false;
        let callback = |msg_bytes: Vec<u8>, contact_name: String| -> io::Result<()> {
            message_received = true;
            assert!(contact_name == *"camera");
            assert!(String::from_utf8(msg_bytes).unwrap() == message);

            Ok(())
        };

        app.receive(callback).unwrap();
        assert!(message_received);

        //Camera performs an MLS update, but does not send the update.
        camera.perform_update(GROUP_NAME.to_string()).unwrap();

        //Camera sends the second messages
        let message2 = "Hello, again!".to_string();
        camera
            .send(message2.clone().as_bytes(), GROUP_NAME.to_string())
            .unwrap();

        //App receives the message, but cannot encrypt it (hence the message is dropped).
        let mut message2_received = false;
        let callback = |_msg_bytes: Vec<u8>, _contact_name: String| -> io::Result<()> {
            message2_received = true;

            Ok(())
        };

        app.receive(callback).unwrap();
        assert!(!message2_received);

        //Camera finally sends the pending update.
        camera.perform_update(GROUP_NAME.to_string()).unwrap();
        camera.send_update(GROUP_NAME.to_string()).unwrap();

        //App receives the update.
        let callback_app = |_msg_bytes: Vec<u8>, _contact_name: String| -> io::Result<()> {
            println!("contact_name = {:?}", _contact_name);
            Ok(())
        };

        app.receive(callback_app).unwrap();

        //Camera sends the third messages
        let message3 = "Hello, again and again!".to_string();
        camera
            .send(message3.clone().as_bytes(), GROUP_NAME.to_string())
            .unwrap();

        //App receives the message.
        let mut message3_received = false;
        let callback = |msg_bytes: Vec<u8>, contact_name: String| -> io::Result<()> {
            message3_received = true;
            assert!(contact_name == *"camera");
            assert!(String::from_utf8(msg_bytes).unwrap() == message3);

            Ok(())
        };

        app.receive(callback).unwrap();
        assert!(message3_received);

        camera.deregister().unwrap();
        app.deregister().unwrap();
    }

    #[test]
    /// Camera invites app and immediately sends a message to it.
    /// It then issues an update, which the app receives.
    /// The app then initializes.
    /// The camera then sends another message for the app to receive.
    fn app_reinit_test() {
        let (mut camera, mut app) = pair();

        // Camera sends a message
        let message = "Hello, app!".to_string();
        camera
            .send(message.clone().as_bytes(), GROUP_NAME.to_string())
            .unwrap();
        camera.save_groups_state();

        //App receives the message
        let mut message_received = false;
        let callback = |msg_bytes: Vec<u8>, contact_name: String| -> io::Result<()> {
            message_received = true;
            assert!(contact_name == *"camera");
            assert!(String::from_utf8(msg_bytes).unwrap() == message);

            Ok(())
        };

        app.receive(callback).unwrap();
        app.save_groups_state();
        assert!(message_received);

        //Camera performs an MLS update.
        camera.perform_update(GROUP_NAME.to_string()).unwrap();
        camera.save_groups_state();
        camera.send_update(GROUP_NAME.to_string()).unwrap();

        //App receives the update.
        let callback_app = |_msg_bytes: Vec<u8>, _contact_name: String| -> io::Result<()> {
            println!("contact_name = {:?}", _contact_name);
            Ok(())
        };

        app.receive(callback_app).unwrap();
        app.save_groups_state();

        // App reinitializes
        let mut app = reinitialize_app();

        // Camera sends the second message
        let message = "Hello, app, again!".to_string();
        camera
            .send(message.clone().as_bytes(), GROUP_NAME.to_string())
            .unwrap();
        camera.save_groups_state();

        //App receives the message
        let mut message_received = false;
        let callback = |msg_bytes: Vec<u8>, contact_name: String| -> io::Result<()> {
            message_received = true;
            assert!(contact_name == *"camera");
            assert!(String::from_utf8(msg_bytes).unwrap() == message);

            Ok(())
        };

        app.receive(callback).unwrap();
        app.save_groups_state();
        assert!(message_received);

        camera.deregister().unwrap();
        app.deregister().unwrap();
    }
}
