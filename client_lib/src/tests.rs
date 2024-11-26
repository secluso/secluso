//! Copyright (C) 2024  Ardalan Amiri Sani
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU General Public License as published by
//! the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU General Public License for more details.
//!
//! You should have received a copy of the GNU General Public License
//! along with this program.  If not, see <https://www.gnu.org/licenses/>.

/// Before running the tests:
/// 1. Create the test_data folder and copy the user_credentials file in it.
/// 2. Run the deliver service locally and on port 12347.
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

    fn get_user_credentials() -> Vec<u8> {
        let pathname = "./test_data/user_credentials";
        let file = fs::File::open(pathname).expect("Could not open user_credentials file");
        let mut reader =
            BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
        let data = reader.fill_buf().unwrap();

        data.to_vec()
    }

    #[test]
    /// Camera invites app and immediately sends a message to it.
    fn camera_to_app_message_test() {
        let credentials = get_user_credentials();

        let camera_server_stream = TcpStream::connect("127.0.0.1:12347").unwrap();
        let app_server_stream = TcpStream::connect("127.0.0.1:12347").unwrap();

        let mut camera = User::new(
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

        let mut app = User::new(
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

        //Camera and app generate key packages and then add each other as contacts
        camera.generate_key_packages().unwrap();
        let camera_key_packages = camera.key_packages();
        app.generate_key_packages().unwrap();
        let app_key_packages = app.key_packages();

        let app_contact = camera.add_contact("app".to_string(), app_key_packages);
        let _camera_contact = app.add_contact("camera".to_string(), camera_key_packages);

        //Camera creates a group and invites app
        let group_name = "group".to_string();
        camera.create_group(group_name.clone());
        camera.invite(&app_contact, group_name.clone()).unwrap();

        //Camera sends a message
        let message = "Hello, app!".to_string();
        camera.send(message.clone().as_bytes(), group_name).unwrap();

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
    }

    #[test]
    /// Camera invites app and the app immediately sends a message to camera.
    fn app_to_camera_message_test() {
        let credentials = get_user_credentials();

        let camera_server_stream = TcpStream::connect("127.0.0.1:12347").unwrap();
        let app_server_stream = TcpStream::connect("127.0.0.1:12347").unwrap();

        let mut camera = User::new(
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

        let mut app = User::new(
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

        //Camera and app generate key packages and then add each other as contacts
        camera.generate_key_packages().unwrap();
        let camera_key_packages = camera.key_packages();
        app.generate_key_packages().unwrap();
        let app_key_packages = app.key_packages();

        let app_contact = camera.add_contact("app".to_string(), app_key_packages);
        let _camera_contact = app.add_contact("camera".to_string(), camera_key_packages);

        //Camera creates a group and invites app
        let group_name = "group".to_string();
        camera.create_group(group_name.clone());
        camera.invite(&app_contact, group_name.clone()).unwrap();

        //App receives welcome message
        let callback_app =
            |_msg_bytes: Vec<u8>, _contact_name: String| -> io::Result<()> { Ok(()) };

        app.receive(callback_app).unwrap();

        //App sends a message
        let message = "Hello, app!".to_string();
        app.send(message.clone().as_bytes(), group_name).unwrap();

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
    }

    #[test]
    /// Camera invites app and immediately sends a message to it.
    /// It then does a self update and sends another message.
    fn update_test() {
        let credentials = get_user_credentials();

        let camera_server_stream = TcpStream::connect("127.0.0.1:12347").unwrap();
        let app_server_stream = TcpStream::connect("127.0.0.1:12347").unwrap();

        let mut camera = User::new(
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

        let mut app = User::new(
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

        //Camera and app generate key packages and then add each other as contacts
        camera.generate_key_packages().unwrap();
        let camera_key_packages = camera.key_packages();
        app.generate_key_packages().unwrap();
        let app_key_packages = app.key_packages();

        let app_contact = camera.add_contact("app".to_string(), app_key_packages);
        let _camera_contact = app.add_contact("camera".to_string(), camera_key_packages);

        //Camera creates a group and invites app
        let group_name = "group".to_string();
        camera.create_group(group_name.clone());
        camera.invite(&app_contact, group_name.clone()).unwrap();

        //Camera sends a message
        let message = "Hello, app!".to_string();
        camera
            .send(message.clone().as_bytes(), group_name.clone())
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
        camera.update(group_name.clone()).unwrap();

        //Camera sends the second messages
        let message2 = "Hello, again!".to_string();
        camera
            .send(message2.clone().as_bytes(), group_name)
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
        let credentials = get_user_credentials();

        let camera_server_stream = TcpStream::connect("127.0.0.1:12347").unwrap();
        let app_server_stream = TcpStream::connect("127.0.0.1:12347").unwrap();

        let mut camera = User::new(
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

        let mut app = User::new(
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

        //Camera and app generate key packages and then add each other as contacts
        camera.generate_key_packages().unwrap();
        let camera_key_packages = camera.key_packages();
        app.generate_key_packages().unwrap();
        let app_key_packages = app.key_packages();

        let app_contact = camera.add_contact("app".to_string(), app_key_packages);
        let _camera_contact = app.add_contact("camera".to_string(), camera_key_packages);

        //Camera creates a group and invites app
        let group_name = "group".to_string();
        camera.create_group(group_name.clone());
        camera.invite(&app_contact, group_name.clone()).unwrap();

        //Camera sends a message
        let message = "Hello, app!".to_string();
        camera
            .send(message.clone().as_bytes(), group_name.clone())
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
        camera.update_no_send(group_name.clone()).unwrap();

        //Camera sends the second messages
        let message2 = "Hello, again!".to_string();
        camera
            .send(message2.clone().as_bytes(), group_name.clone())
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
        camera.update(group_name.clone()).unwrap();

        //App receives the update.
        let callback_app = |_msg_bytes: Vec<u8>, _contact_name: String| -> io::Result<()> {
            println!("contact_name = {:?}", _contact_name);
            Ok(())
        };

        app.receive(callback_app).unwrap();

        //Camera sends the third messages
        let message3 = "Hello, again and again!".to_string();
        camera
            .send(message3.clone().as_bytes(), group_name)
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
    }

    #[test]
    fn pairing_works() {
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
}
