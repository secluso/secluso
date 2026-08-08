//! SPDX-License-Identifier: GPL-3.0-or-later

/// Note: Make sure to use --test-threads=1. That is: cargo test -- --test-threads=1
/// Tests might reuse file addresses and hence will corrupt each other if run
/// in parallel.

#[cfg(test)]
mod tests {
    use crate::pairing::NUM_SECRET_BYTES;
    use crate::mls_client::{MlsClient, Contact, ClientType};
    use crate::video::{encrypt_video_file, decrypt_video_file,
        encrypt_thumbnail_file, decrypt_thumbnail_file};
    use crate::thumbnail_meta_info::ThumbnailMetaInfo;
    use openmls::prelude::QueuedProposal;
    use std::fs::{self, File};
    use std::io;
    use std::io::{Read, Write};
    use std::path::Path;

    const GROUP_NAME: &str = "group";

    /// Receives the secrets known by the camera and the app and perform the
    // initial steps of pairing all the way until generating the welcome message.
    /// We break down the pairing process into two parts to be able
    /// to test the authentication separately.
    fn pair_initial(
        camera_secret: Vec<u8>,
    ) -> io::Result<(MlsClient, MlsClient, Contact, Vec<u8>)> {
        let test_data_path = Path::new("test_data");
        if test_data_path.exists() { 
            fs::remove_dir_all(&test_data_path).unwrap();
        }
        fs::create_dir(&test_data_path).unwrap();

        let test_data_camera_path = test_data_path.join("camera");
        fs::create_dir(&test_data_camera_path).unwrap();

        let test_data_app_path = test_data_path.join("app");
        fs::create_dir(&test_data_app_path).unwrap();

        // Create clients
        let mut camera = MlsClient::new(
            "camera".to_string(),
            true,
            "test_data/camera".to_string(),
            "camera".to_string(),
            ClientType::Camera,
        )?;

        let mut app = MlsClient::new(
            "app".to_string(),
            true,
            "test_data/app".to_string(),
            "app".to_string(),
            ClientType::App,
        )?;

        // Exchange key packages, create group, invite, and join
        let camera_contact =
            MlsClient::create_contact("app", app.key_package())?;
        let app_contact =
            MlsClient::create_contact("camera", camera.key_package())?;

        camera.create_group(GROUP_NAME)?;
        camera.save_group_state().unwrap();

        let (welcome_msg_vec, _, _) = camera
            .invite_with_secret(&camera_contact, camera_secret)?;
        camera.save_group_state().unwrap();

        Ok((camera, app, app_contact, welcome_msg_vec))
    }

    /// This function is a complete pairing process.
    /// It requires the caller to pass the secrets known
    /// to the app and camera.
    fn pair_pass_secrets(
        camera_secret: Vec<u8>,
        app_secret: Vec<u8>,
    ) -> io::Result<(MlsClient, MlsClient)> {
        let (camera, mut app, app_contact, welcome_msg_vec) = pair_initial(camera_secret).unwrap();

        app.process_welcome_with_secret(app_contact, welcome_msg_vec, app_secret, GROUP_NAME).unwrap();
        app.save_group_state().unwrap();

        Ok((camera, app))
    }
    
    /// This function is a complete, successful pairing process with built-in secrets.
    /// It is used in other tests.
    fn pair() -> (MlsClient, MlsClient) {
        let secret = vec![0u8; NUM_SECRET_BYTES];

        let (camera, app) = pair_pass_secrets(secret.clone(), secret).unwrap();

        (camera, app)
    }

    fn reinitialize_camera() -> MlsClient {
        let camera = MlsClient::new(
            "camera".to_string(),
            false,
            "test_data/camera".to_string(),
            "camera".to_string(),
            ClientType::Camera,
        )
        .unwrap();

        camera
    }

    fn reinitialize_app() -> MlsClient {
        let app = MlsClient::new(
            "app".to_string(),
            false,
            "test_data/app".to_string(),
            "app".to_string(),
            ClientType::App,
        )
        .unwrap();

        app
    }

    #[test]
    /// Camera and app both have the same secret and hence can
    /// successfuly authenticate and pair.
    fn pair_successful() {
        let secret = vec![0u8; NUM_SECRET_BYTES];

        let _ = pair_pass_secrets(secret.clone(), secret).unwrap();
    }

    #[test]
    /// Camera and app do not have the same secrets and hence cannot
    /// successfuly authenticate and pair.
    fn pair_unsuccessful() {
        let camera_secret = vec![0u8; NUM_SECRET_BYTES];
        let app_secret = vec![1u8; NUM_SECRET_BYTES];

        let (_, mut app, app_contact, welcome_msg_vec) = pair_initial(camera_secret).unwrap();

        let welcome_result = app.process_welcome_with_secret(app_contact, welcome_msg_vec, app_secret, GROUP_NAME);

        assert!(welcome_result.is_err());
    }

    #[test]
    /// Camera invites app and immediately sends a message to it.
    fn camera_to_app_message_test() {
        let (mut camera, mut app) = pair();

        // Camera encrypts the message
        let msg = "Hello, app!";
        let msg_enc = camera
            .encrypt(msg.as_bytes())
            .unwrap();
        camera.save_group_state().unwrap();

        //App decrypts the message
        let msg_dec_vec = app.decrypt(msg_enc, true).unwrap();
        app.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);
    }

    #[test]
    /// Camera invites app and the app immediately sends a message to camera.
    fn app_to_camera_message_test() {
        let (mut camera, mut app) = pair();

        // Camera encrypts the message
        let msg = "Hello, app!";
        let msg_enc = app
            .encrypt(msg.as_bytes())
            .unwrap();
        app.save_group_state().unwrap();

        //App decrypts the message
        let msg_dec_vec = camera.decrypt(msg_enc, true).unwrap();
        camera.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);
    }

    #[test]
    /// Camera invites app and then sends a couple of messages to the app.
    /// The camera and the app reinitialize multiple times in this process.
    fn camera_to_app_message_reinit_test() {
        let _ = pair();

        for i in 0..10 {
            let mut camera = reinitialize_camera();
            let mut app = reinitialize_app();

            // Camera encrypts the message
            let msg = format!("Hello, app! -- {i}");
            let msg_enc = camera
                .encrypt(msg.as_bytes())
                .unwrap();
            camera.save_group_state().unwrap();

            //App decrypts the message
            let msg_dec_vec = app.decrypt(msg_enc, true).unwrap();
            app.save_group_state().unwrap();
            let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

            assert!(msg == msg_dec);
        }
    }

    #[test]
    /// Camera invites app and the app sends a couple of messages to camera.
    /// The camera and the app reinitialize multiple times in this process.
    fn app_to_camera_message_reinit_test() {
        let _ = pair();

        for i in 0..10 {
            let mut camera = reinitialize_camera();
            let mut app = reinitialize_app();

            // Camera encrypts the message
            let msg = format!("Hello, camera! -- {i}");
            let msg_enc = app
                .encrypt(msg.as_bytes())
                .unwrap();
            app.save_group_state().unwrap();

            //App decrypts the message
            let msg_dec_vec = camera.decrypt(msg_enc, true).unwrap();
            camera.save_group_state().unwrap();
            let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

            assert!(msg == msg_dec);
        }
    }

    #[test]
    /// Camera invites app and immediately sends a message to it.
    /// It then does a self update and sends another message.
    /// This repeats a few times.
    /// On every other iteration, app also generates an update
    /// proposal and asks the camera to commit it.
    fn update_test() {
        let (mut camera, mut app) = pair();

        for i in 0..10 {
            let msg = format!("Hello, app! -- {i}");
            let msg_enc = camera
                .encrypt(msg.as_bytes())
                .unwrap();
            camera.save_group_state().unwrap();

            //App decrypts the message
            let msg_dec_vec = app.decrypt(msg_enc, true).unwrap();
            app.save_group_state().unwrap();
            let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

            assert!(msg == msg_dec);

            let camera_leaf_nodes_before = camera.get_own_leaf_node();
            let app_leaf_nodes_before = app.get_own_leaf_node();

            //Camera performs an MLS update and send the commit to the app.
            let (commit_msg, _) = camera.update().unwrap();
            camera.save_group_state().unwrap();

            // The app merges the commits.
            app.decrypt(commit_msg, false).unwrap();
            app.save_group_state().unwrap();

            // Compare the ratchet trees maintained by camera and app.
            // They should match.
            let camera_ratchet_tree = camera.get_ratchet_tree();
            let app_ratchet_tree = app.get_ratchet_tree();
            assert_eq!(camera_ratchet_tree, app_ratchet_tree);

            let camera_leaf_nodes_after = camera.get_own_leaf_node();
            let app_leaf_nodes_after = app.get_own_leaf_node();

            if i % 2 == 0 {
                // In these iterations, only the camera should be updated.
                assert_ne!(camera_leaf_nodes_before, camera_leaf_nodes_after);
                assert_eq!(app_leaf_nodes_before, app_leaf_nodes_after);

                let update_proposal = app.update_proposal().unwrap();
                app.save_group_state().unwrap();
                camera.decrypt(update_proposal, false).unwrap();
                camera.save_group_state().unwrap();
            } else {
                // In these iterations, both the camera and the app should be updated.
                assert_ne!(camera_leaf_nodes_before, camera_leaf_nodes_after);
                assert_ne!(app_leaf_nodes_before, app_leaf_nodes_after);
            }
        }
    }

    #[test]
    /// The same as the update_test. The difference is that
    /// the app and camera reinitialize multiple times in the process.
    fn update_with_reinit_test() {
        let _ = pair();
        //let (mut camera, mut app) = pair();

        for i in 0..10 {
            let mut camera = reinitialize_camera();
            let mut app = reinitialize_app();

            let msg = format!("Hello, app! -- {i}");
            let msg_enc = camera
                .encrypt(msg.as_bytes())
                .unwrap();
            camera.save_group_state().unwrap();

            //App decrypts the message
            let msg_dec_vec = app.decrypt(msg_enc, true).unwrap();
            app.save_group_state().unwrap();
            let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

            assert!(msg == msg_dec);

            let camera_leaf_nodes_before = camera.get_own_leaf_node();
            let app_leaf_nodes_before = app.get_own_leaf_node();

            //Camera performs an MLS update and send the commit to the app.
            let (commit_msg, _) = camera.update().unwrap();
            camera.save_group_state().unwrap();

            // The app merges the commits.
            app.decrypt(commit_msg, false).unwrap();
            app.save_group_state().unwrap();

            // Compare the ratchet trees maintained by camera and app.
            // They should match.
            let camera_ratchet_tree = camera.get_ratchet_tree();
            let app_ratchet_tree = app.get_ratchet_tree();
            assert_eq!(camera_ratchet_tree, app_ratchet_tree);

            let camera_leaf_nodes_after = camera.get_own_leaf_node();
            let app_leaf_nodes_after = app.get_own_leaf_node();

            if i % 2 == 0 {
                // In these iterations, only the camera should be updated.
                assert_ne!(camera_leaf_nodes_before, camera_leaf_nodes_after);
                assert_eq!(app_leaf_nodes_before, app_leaf_nodes_after);

                let update_proposal = app.update_proposal().unwrap();
                app.save_group_state().unwrap();
                camera.decrypt(update_proposal, false).unwrap();
                camera.save_group_state().unwrap();
            } else {
                // In these iterations, both the camera and the app should be updated.
                assert_ne!(camera_leaf_nodes_before, camera_leaf_nodes_after);
                assert_ne!(app_leaf_nodes_before, app_leaf_nodes_after);
            }
        }
    }

    #[test]
    /// Camera invites app and immediately sends a message to it.
    /// It then does a self update and sends the commit message.
    /// App also generates an update proposal, which is lost,
    /// followed by another update proposal, which is sent to
    /// the camera.
    fn update_with_missed_update_proposal_test() {
        let (mut camera, mut app) = pair();

        let msg = format!("Hello, app!");
        let msg_enc = camera
            .encrypt(msg.as_bytes())
            .unwrap();
        camera.save_group_state().unwrap();

        //App decrypts the message
        let msg_dec_vec = app.decrypt(msg_enc, true).unwrap();
        app.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);

        let camera_leaf_nodes_before = camera.get_own_leaf_node();
        let app_leaf_nodes_before = app.get_own_leaf_node();

        //Camera performs an MLS update and send the commit to the app.
        let (commit_msg, _) = camera.update().unwrap();
        camera.save_group_state().unwrap();

        // The app merges the commits.
        app.decrypt(commit_msg, false).unwrap();
        app.save_group_state().unwrap();

        // Compare the ratchet trees maintained by camera and app.
        // They should match.
        let camera_ratchet_tree = camera.get_ratchet_tree();
        let app_ratchet_tree = app.get_ratchet_tree();
        assert_eq!(camera_ratchet_tree, app_ratchet_tree);

        let camera_leaf_nodes_after = camera.get_own_leaf_node();
        let app_leaf_nodes_after = app.get_own_leaf_node();

        // Only the camera should be updated.
        assert_ne!(camera_leaf_nodes_before, camera_leaf_nodes_after);
        assert_eq!(app_leaf_nodes_before, app_leaf_nodes_after);

        let camera_leaf_nodes_before = camera.get_own_leaf_node();
        let app_leaf_nodes_before = app.get_own_leaf_node();

        // App generates an update proposal, which is "lost."
        let _update_proposal_lost = app.update_proposal().unwrap();
        app.save_group_state().unwrap();

        // App then generates another update proposal, which is successfully
        // sent to the camera.
        let update_proposal = app.update_proposal().unwrap();
        app.save_group_state().unwrap();

        camera.decrypt(update_proposal, false).unwrap();
        camera.save_group_state().unwrap();

        //Camera performs an MLS update and send the commit to the app.
        let (commit_msg, _) = camera.update().unwrap();
        camera.save_group_state().unwrap();

        // The app merges the commits.
        app.decrypt(commit_msg, false).unwrap();
        app.save_group_state().unwrap();

        let camera_leaf_nodes_after = camera.get_own_leaf_node();
        let app_leaf_nodes_after = app.get_own_leaf_node();

        // Both the camera and the app should be updated.
        // They should also match.
        assert_ne!(camera_leaf_nodes_before, camera_leaf_nodes_after);
        assert_ne!(app_leaf_nodes_before, app_leaf_nodes_after);
        assert_eq!(camera_ratchet_tree, app_ratchet_tree);
    }

    #[test]
    /// Camera invites app and immediately sends a message to it.
    /// It then does a self update and sends the commit message.
    /// App also generates two update proposals, but only the first
    //  one (old one) is used by the camera.
    fn update_with_old_update_proposal_test() {
        let (mut camera, mut app) = pair();

        let msg = format!("Hello, app!");
        let msg_enc = camera
            .encrypt(msg.as_bytes())
            .unwrap();
        camera.save_group_state().unwrap();

        //App decrypts the message
        let msg_dec_vec = app.decrypt(msg_enc, true).unwrap();
        app.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);

        let camera_leaf_nodes_before = camera.get_own_leaf_node();
        let app_leaf_nodes_before = app.get_own_leaf_node();

        //Camera performs an MLS update and send the commit to the app.
        let (commit_msg, _) = camera.update().unwrap();
        camera.save_group_state().unwrap();

        // The app merges the commits.
        app.decrypt(commit_msg, false).unwrap();
        app.save_group_state().unwrap();

        // Compare the ratchet trees maintained by camera and app.
        // They should match.
        let camera_ratchet_tree = camera.get_ratchet_tree();
        let app_ratchet_tree = app.get_ratchet_tree();
        assert_eq!(camera_ratchet_tree, app_ratchet_tree);

        let camera_leaf_nodes_after = camera.get_own_leaf_node();
        let app_leaf_nodes_after = app.get_own_leaf_node();

        // Only the camera should be updated.
        assert_ne!(camera_leaf_nodes_before, camera_leaf_nodes_after);
        assert_eq!(app_leaf_nodes_before, app_leaf_nodes_after);

        let camera_leaf_nodes_before = camera.get_own_leaf_node();
        let app_leaf_nodes_before = app.get_own_leaf_node();

        // App generates the first (old) update proposal.
        let update_proposal_old = app.update_proposal().unwrap();
        app.save_group_state().unwrap();

        // App then generates another update proposal, which is not
        // used by the camera
        let _update_proposal = app.update_proposal().unwrap();
        app.save_group_state().unwrap();

        camera.decrypt(update_proposal_old, false).unwrap();
        camera.save_group_state().unwrap();

        //Camera performs an MLS update and send the commit to the app.
        let (commit_msg, _) = camera.update().unwrap();
        camera.save_group_state().unwrap();

        // The app merges the commits.
        app.decrypt(commit_msg, false).unwrap();
        app.save_group_state().unwrap();

        let camera_leaf_nodes_after = camera.get_own_leaf_node();
        let app_leaf_nodes_after = app.get_own_leaf_node();

        // Both the camera and the app should be updated.
        // They should also match.
        assert_ne!(camera_leaf_nodes_before, camera_leaf_nodes_after);
        assert_ne!(app_leaf_nodes_before, app_leaf_nodes_after);
        assert_eq!(camera_ratchet_tree, app_ratchet_tree);
    }

    #[test]
    /// Camera invites app and immediately sends a message to it.
    /// It then does a self update, does not send the update, but sends another message
    /// (which cannot be successfully decrypted by the app).
    /// The camera then sends the update, followed by another message
    /// (which should be successfully decrypted by the app).
    fn update_no_send_first_test() {
        let (mut camera, mut app) = pair();

        //Camera generates a message for the pp
        let msg = format!("Hello, app! -- 1");
        let msg_enc = camera
            .encrypt(msg.as_bytes())
            .unwrap();
        camera.save_group_state().unwrap();

        //App decrypts the message
        let msg_dec_vec = app.decrypt(msg_enc, true).unwrap();
        app.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);

        let camera_leaf_nodes_before = camera.get_own_leaf_node();
        let app_leaf_nodes_before = app.get_own_leaf_node();

        //Camera performs an MLS update
        let (commit_msg, _) = camera.update().unwrap();
        camera.save_group_state().unwrap();

        //Camera generates another message for the app
        let msg = format!("Hello, app! -- 2");
        let msg_enc = camera
            .encrypt(msg.as_bytes())
            .unwrap();
        camera.save_group_state().unwrap();

        //App decrypts the message
        let dec_result = app.decrypt(msg_enc, true);
        app.save_group_state().unwrap();
        assert!(dec_result.is_err());

        // The app finally merges the commits.
        app.decrypt(commit_msg, false).unwrap();
        app.save_group_state().unwrap();

        // Compare the ratchet trees maintained by camera and app.
        // They should match.
        let camera_ratchet_tree = camera.get_ratchet_tree();
        let app_ratchet_tree = app.get_ratchet_tree();
        assert_eq!(camera_ratchet_tree, app_ratchet_tree);

        let camera_leaf_nodes_after = camera.get_own_leaf_node();
        let app_leaf_nodes_after = app.get_own_leaf_node();

        assert_ne!(camera_leaf_nodes_before, camera_leaf_nodes_after);
        assert_eq!(app_leaf_nodes_before, app_leaf_nodes_after);

        //Camera generates another message for the app
        let msg = format!("Hello, app! -- 3");
        let msg_enc = camera
            .encrypt(msg.as_bytes())
            .unwrap();
        camera.save_group_state().unwrap();

        //App successfully decrypts the message
        let msg_dec_vec = app.decrypt(msg_enc, true).unwrap();
        app.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);
    }

    /// This function is a complete, successful pairing process with the first
    /// secondary app (app2) with built-in secrets.
    /// It is used in other tests.
    fn pair_with_app2(
        camera: &mut MlsClient,
        app: &mut MlsClient,
    ) -> MlsClient {
        fs::create_dir("test_data/app2").unwrap();

        // Add the second app
        let mut app2 = MlsClient::new(
            "app2".to_string(),
            true,
            "test_data/app2".to_string(),
            "app2".to_string(),
            ClientType::App,
        ).unwrap();

        // Exchange key packages, create group, invite, and join
        let camera_contact =
            MlsClient::create_contact("app2", app2.key_package()).unwrap();
        let app2_contact =
            MlsClient::create_contact("camera", camera.key_package()).unwrap();

        let new_secret = vec![2u8; NUM_SECRET_BYTES];

        let (welcome_msg_vec, psk_proposal_vec, commit_msg_vec) = camera
            .invite_with_secret(&camera_contact, new_secret.clone()).unwrap();
        camera.save_group_state().unwrap();
        let update_proposals = camera.get_update_proposals().unwrap();

        app2.process_welcome_with_secret(app2_contact, welcome_msg_vec, new_secret.clone(), GROUP_NAME).unwrap();
        app2.save_group_state().unwrap();

        // App merges the psk_proposal and commit for the add operation
        app.store_update_proposals(update_proposals).unwrap();
        app.decrypt(psk_proposal_vec, false).unwrap();
        app.decrypt_with_secret(commit_msg_vec, false, new_secret).unwrap();
        app.save_group_state().unwrap();

        app2
    }

    /// This function is the first step of adding the second secondary app (app3).
    /// It is used in other tests.
    fn pair_with_app3_handshake(
        camera: &mut MlsClient,
        app: &mut MlsClient,
    ) -> (MlsClient, Vec<u8>, Vec<u8>, Vec<QueuedProposal>) {
        fs::create_dir("test_data/app3").unwrap();

        // Add the third app
        let mut app3 = MlsClient::new(
            "app3".to_string(),
            true,
            "test_data/app3".to_string(),
            "app3".to_string(),
            ClientType::App,
        ).unwrap();

        let camera_contact =
            MlsClient::create_contact("app3", app3.key_package()).unwrap();
        let app3_contact =
            MlsClient::create_contact("camera", camera.key_package()).unwrap();

        let new_secret = vec![3u8; NUM_SECRET_BYTES];

        let update_proposals = camera.get_update_proposals().unwrap();
        let (welcome_msg_vec, psk_proposal_vec, commit_msg_vec) = camera
            .invite_with_secret(&camera_contact, new_secret.clone()).unwrap();
        camera.save_group_state().unwrap();

        app3.process_welcome_with_secret(app3_contact, welcome_msg_vec, new_secret.clone(), GROUP_NAME).unwrap();
        app3.save_group_state().unwrap();

        app.store_update_proposals(update_proposals.clone()).unwrap();
        app.decrypt(psk_proposal_vec.clone(), false).unwrap();
        app.decrypt_with_secret(commit_msg_vec.clone(), false, new_secret.clone()).unwrap();
        app.save_group_state().unwrap();

        (app3, psk_proposal_vec, commit_msg_vec, update_proposals)
    }

    /// This function is the second step of adding the second secondary app (app3).
    /// It is used in other tests.
    fn pair_with_app3_inform_app2(
        app2: &mut MlsClient,
        psk_proposal_vec: Vec<u8>,
        commit_msg_vec: Vec<u8>,
        update_proposals: Vec<QueuedProposal>,
    ) {
        // Must be the same as the one in pair_with_app3_handshake()
        let new_secret = vec![3u8; NUM_SECRET_BYTES];
        
        app2.store_update_proposals(update_proposals).unwrap();
        app2.decrypt(psk_proposal_vec, false).unwrap();
        app2.decrypt_with_secret(commit_msg_vec, false, new_secret).unwrap();
        app2.save_group_state().unwrap();
    }

    /// This function is a complete, successful pairing process with built-in secrets.
    /// It is used in other tests.
    fn pair_with_two_more_apps(
        camera: &mut MlsClient,
        app: &mut MlsClient,
    ) -> (MlsClient, MlsClient) {
        let mut app2 = pair_with_app2(camera, app);
        let (app3, psk_proposal_vec, commit_msg_vec, update_proposals) = pair_with_app3_handshake(camera, app);
        pair_with_app3_inform_app2(&mut app2, psk_proposal_vec, commit_msg_vec, update_proposals);
        
        (app2, app3)
    }

    #[test]
    /// Camera invites app and immediately sends a message to it.
    /// It then invites two more apps and sends a message to all three apps.
    fn add_more_apps() {
        let (mut camera, mut app) = pair();

        // Camera encrypts the message
        let msg = "Hello, app!";
        let msg_enc = camera
            .encrypt(msg.as_bytes())
            .unwrap();
        camera.save_group_state().unwrap();

        //App decrypts the message
        let msg_dec_vec = app.decrypt(msg_enc, true).unwrap();
        app.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);

        let (mut app2, mut app3) = pair_with_two_more_apps(&mut camera, &mut app);

        // Camera encrypts a new message
        let msg = "Hello, apps!";
        let msg_enc = camera
            .encrypt(msg.as_bytes())
            .unwrap();
        camera.save_group_state().unwrap();

        //App decrypts the message
        let msg_dec_vec = app.decrypt(msg_enc.clone(), true).unwrap();
        app.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);

        //App2 decrypts the message
        let msg_dec_vec = app2.decrypt(msg_enc.clone(), true).unwrap();
        app2.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);

        //App3 decrypts the message
        let msg_dec_vec = app3.decrypt(msg_enc, true).unwrap();
        app3.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);
    }

    #[test]
    /// Camera invites three apps and immediately sends a message to them.
    /// It then does a self update and sends another message.
    /// This repeats a few times.
    /// On every other iteration, apps also generate update
    /// proposals and ask the camera to commit them.
    fn update_test_with_more_apps() {
        let (mut camera, mut app) = pair();
        let (mut app2, mut app3) = pair_with_two_more_apps(&mut camera, &mut app);

        for i in 0..10 {
            let msg = format!("Hello, app! -- {i}");
            let msg_enc = camera
                .encrypt(msg.as_bytes())
                .unwrap();
            camera.save_group_state().unwrap();

            //App decrypts the message
            let msg_dec_vec = app.decrypt(msg_enc.clone(), true).unwrap();
            app.save_group_state().unwrap();
            let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

            assert!(msg == msg_dec);

            //App2 decrypts the message
            let msg_dec_vec = app2.decrypt(msg_enc.clone(), true).unwrap();
            app2.save_group_state().unwrap();
            let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

            assert!(msg == msg_dec);

            //App3 decrypts the message
            let msg_dec_vec = app3.decrypt(msg_enc, true).unwrap();
            app3.save_group_state().unwrap();
            let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

            assert!(msg == msg_dec);

            let camera_leaf_nodes_before = camera.get_own_leaf_node();
            let app_leaf_nodes_before = app.get_own_leaf_node();
            let app2_leaf_nodes_before = app2.get_own_leaf_node();
            let app3_leaf_nodes_before = app3.get_own_leaf_node();

            //Camera performs an MLS update and send the commit to the apps.
            let (commit_msg, _) = camera.update().unwrap();
            camera.save_group_state().unwrap();

            // The apps merge the commit.
            app.decrypt(commit_msg.clone(), false).unwrap();
            app.save_group_state().unwrap();
            app2.decrypt(commit_msg.clone(), false).unwrap();
            app2.save_group_state().unwrap();
            app3.decrypt(commit_msg, false).unwrap();
            app3.save_group_state().unwrap();

            // Compare the ratchet trees maintained by camera and apps.
            // They should match.
            let camera_ratchet_tree = camera.get_ratchet_tree();
            let app_ratchet_tree = app.get_ratchet_tree();
            let app2_ratchet_tree = app2.get_ratchet_tree();
            let app3_ratchet_tree = app3.get_ratchet_tree();
            assert_eq!(camera_ratchet_tree, app_ratchet_tree);
            assert_eq!(camera_ratchet_tree, app2_ratchet_tree);
            assert_eq!(camera_ratchet_tree, app3_ratchet_tree);

            let camera_leaf_nodes_after = camera.get_own_leaf_node();
            let app_leaf_nodes_after = app.get_own_leaf_node();
            let app2_leaf_nodes_after = app2.get_own_leaf_node();
            let app3_leaf_nodes_after = app3.get_own_leaf_node();

            if i % 2 == 0 {
                // In these iterations, only the camera should be updated.
                assert_ne!(camera_leaf_nodes_before, camera_leaf_nodes_after);
                assert_eq!(app_leaf_nodes_before, app_leaf_nodes_after);
                assert_eq!(app2_leaf_nodes_before, app2_leaf_nodes_after);
                assert_eq!(app3_leaf_nodes_before, app3_leaf_nodes_after);

                let app_update_proposal = app.update_proposal().unwrap();
                camera.decrypt(app_update_proposal.clone(), false).unwrap();
                app2.decrypt(app_update_proposal.clone(), false).unwrap();
                app3.decrypt(app_update_proposal, false).unwrap();

                let app2_update_proposal = app2.update_proposal().unwrap();
                camera.decrypt(app2_update_proposal.clone(), false).unwrap();
                app.decrypt(app2_update_proposal.clone(), false).unwrap();
                app3.decrypt(app2_update_proposal, false).unwrap();

                let app3_update_proposal = app3.update_proposal().unwrap();
                camera.decrypt(app3_update_proposal.clone(), false).unwrap();
                app.decrypt(app3_update_proposal.clone(), false).unwrap();
                app2.decrypt(app3_update_proposal, false).unwrap();

                camera.save_group_state().unwrap();
                app.save_group_state().unwrap();
                app2.save_group_state().unwrap();
                app3.save_group_state().unwrap();
            } else {
                // In these iterations, the camera and the apps should all be updated.
                assert_ne!(camera_leaf_nodes_before, camera_leaf_nodes_after);
                assert_ne!(app_leaf_nodes_before, app_leaf_nodes_after);
                assert_ne!(app2_leaf_nodes_before, app2_leaf_nodes_after);
                assert_ne!(app3_leaf_nodes_before, app3_leaf_nodes_after);
            }
        }
    }

    fn generate_dummy_file(
        pathname: &str,
        file_size: usize,
    ) {
        let mut video_file = File::create(pathname).unwrap();

        let chunk_size = 8192;
        let buffer = vec![0u8; chunk_size];

        let mut remaining = file_size;

        while remaining > 0 {
            let write_size = remaining.min(chunk_size);
            video_file.write_all(&buffer[..write_size]).unwrap();
            remaining -= write_size;
        }
    }

    fn check_decrypted_dummy_file(
        dec_pathname: &str,
        expected_file_size: usize,
    ) {
        let dec_video_file = File::open(dec_pathname).unwrap();
        let metadata = dec_video_file.metadata().unwrap();

        let dec_size = metadata.len();
        assert!(dec_size == expected_file_size as u64);

        // Check all bytes are zero
        let mut reader = io::BufReader::new(dec_video_file);
        let mut dec_buffer = [0u8; 8192];

        loop {
            let bytes_read = reader.read(&mut dec_buffer).unwrap();
            if bytes_read == 0 {
                break;
            }

            assert!(!dec_buffer[..bytes_read].iter().any(|&b| b != 0));
        }
    }

    #[test]
    /// Camera invites app and immediately sends a video to it.
    fn camera_to_app_video_test() {
        let (mut camera, mut app) = pair();

        // Create input video file to be encrypted (all 0's)
        let video_pathname = "test_data/video_file";
        let file_size: usize = 96 * 1024 + 135;

        generate_dummy_file(video_pathname, file_size);

        // Camera encrypts video file
        let enc_video_pathname = "test_data/enc_video_file";

        encrypt_video_file(
            &mut camera,
            video_pathname,
            enc_video_pathname,
            0,
        ).unwrap();

        // App decrypts video file
        fs::create_dir("test_data/app/videos").unwrap();

        let dec_video_filename = decrypt_video_file(
            &mut app,
            enc_video_pathname,
        ).unwrap();

        let dec_video_pathname = format!("test_data/app/videos/{}", dec_video_filename);

        // Check decrypted file
        check_decrypted_dummy_file(&dec_video_pathname, file_size);
    }

    #[test]
    /// Camera invites app and immediately sends a video to it.
    fn camera_to_app_thumbnail_test() {
        let (mut camera, mut app) = pair();

        // Create input thumbnail file to be encrypted (all 0's)
        let thumbnail_pathname = "test_data/thumbnail_file";
        let file_size: usize = 1069;

        generate_dummy_file(thumbnail_pathname, file_size);

        // Camera encrypts thumbnail file
        let enc_thumbnail_pathname = "test_data/enc_thumbnail_file";
        let mut thumbnail_info =
                    ThumbnailMetaInfo::new(0, 0, vec![]);

        encrypt_thumbnail_file(
            &mut camera,
            thumbnail_pathname,
            enc_thumbnail_pathname,
            &mut thumbnail_info,
        ).unwrap();

        // App decrypts thumbnail file
        fs::create_dir("test_data/app/videos").unwrap();

        let dec_thumbnail_filename = decrypt_thumbnail_file(
            &mut app,
            enc_thumbnail_pathname,
            "test_data",
        ).unwrap();

        let dec_thumbnail_pathname = format!("test_data/app/videos/{}", dec_thumbnail_filename);

        // Check decrypted file
        check_decrypted_dummy_file(&dec_thumbnail_pathname, file_size);
    }

    #[test]
    /// Camera invites app and immediately sends two videos to it.
    /// The first video is however "lost".
    /// The app tries to decrypt the second video and it fails.
    fn camera_to_app_missed_video_test() {
        let (mut camera, mut app) = pair();

        // Create input video file to be encrypted (all 0's)
        let video_pathname = "test_data/video_file";
        let file_size: usize = 96 * 1024 + 135;

        generate_dummy_file(video_pathname, file_size);

        // Camera encrypts the first video file.
        let enc_first_video_pathname = "test_data/enc_video_file_0";

        encrypt_video_file(
            &mut camera,
            video_pathname,
            enc_first_video_pathname,
            0,
        ).unwrap();

        // First video is "lost".

        // Camera encrypts the second video file.
        let enc_second_video_pathname = "test_data/enc_video_file_1";

        encrypt_video_file(
            &mut camera,
            video_pathname,
            enc_second_video_pathname,
            1,
        ).unwrap();

        // App tries to decrypt the video file
        fs::create_dir("test_data/app/videos").unwrap();

        let ret = decrypt_video_file(
            &mut app,
            enc_second_video_pathname,
        );

        assert!(ret.is_err());
    }

    #[test]
    /// Camera invites app and immediately sends two thumbnails to it.
    /// The first thumbnail is however "lost".
    /// The app tries to decrypt the second thumbnail and it fails.
    fn camera_to_app_missed_thumbnail_test() {
        let (mut camera, mut app) = pair();

        // Create input thumbnail file to be encrypted (all 0's)
        let thumbnail_pathname = "test_data/thumbnail_file";
        let file_size: usize = 1069;

        generate_dummy_file(thumbnail_pathname, file_size);

        // Camera encrypts the first thumbnail file
        let enc_first_thumbnail_pathname = "test_data/enc_thumbnail_file_0";
        let mut first_thumbnail_info =
                    ThumbnailMetaInfo::new(0, 0, vec![]);

        encrypt_thumbnail_file(
            &mut camera,
            thumbnail_pathname,
            enc_first_thumbnail_pathname,
            &mut first_thumbnail_info,
        ).unwrap();

        // First video is "lost".

        // Camera encrypts the second thumbnail file
        let enc_second_thumbnail_pathname = "test_data/enc_thumbnail_file_1";
        let mut second_thumbnail_info =
                    ThumbnailMetaInfo::new(0, 0, vec![]);

        encrypt_thumbnail_file(
            &mut camera,
            thumbnail_pathname,
            enc_second_thumbnail_pathname,
            &mut second_thumbnail_info,
        ).unwrap();

        // App tries to decrypt the second thumbnail file
        fs::create_dir("test_data/app/videos").unwrap();

        let ret = decrypt_thumbnail_file(
            &mut app,
            enc_second_thumbnail_pathname,
            "test_data",
        );

        assert!(ret.is_err());
    }

    fn camera_to_app_video_decrypt_crash(
        crash_site: &str,
        crash_site_returns_err: bool,
    ) {
        let (mut camera, mut app) = pair();

        // Create input video file to be encrypted (all 0's)
        let video_pathname = "test_data/video_file";
        let file_size: usize = 96 * 1024 + 135;

        generate_dummy_file(video_pathname, file_size);

        // Camera encrypts video file
        let enc_video_pathname = "test_data/enc_video_file";

        encrypt_video_file(
            &mut camera,
            video_pathname,
            enc_video_pathname,
            0,
        ).unwrap();

        // App tires to decrypt video file but it "crashes" halfway.
        fs::create_dir("test_data/app/videos").unwrap();

        std::env::set_var(crash_site, "1");
        let ret = decrypt_video_file(
            &mut app,
            enc_video_pathname,
        );

        if crash_site_returns_err {
            assert!(ret.is_err());
        }

        std::env::remove_var(crash_site);

        // App reinitializes, tries to decrypt again, and succeeds.
        let mut app = reinitialize_app();

        let dec_video_filename = decrypt_video_file(
            &mut app,
            enc_video_pathname,
        ).unwrap();

        let dec_video_pathname = format!("test_data/app/videos/{}", dec_video_filename);

        // Check decrypted file
        check_decrypted_dummy_file(&dec_video_pathname, file_size);
    }

    #[test]
    /// Camera invites app and immediately sends a video to it.
    /// The app tries to decrypt the video, but crashes halfway.
    /// It then tries again and decrypts it successfully.
    fn camera_to_app_video_decrypt_crash_test_1() {
        camera_to_app_video_decrypt_crash("DECRYPT_VIDEO_FILE_CRASH", true);
    }

    #[test]
    fn camera_to_app_video_decrypt_crash_test_2() {
        camera_to_app_video_decrypt_crash("SAVE_GROUP_STATE_CRASH", false);
    }

    #[test]
    /// Camera invites app and immediately sends a thumbnail to it.
    /// The app tries to decrypt the thumbnail, but crashes halfway.
    /// It then tries again and decrypts it successfully.
    fn camera_to_app_thumbnail_decrypt_crash_test() {
        let (mut camera, mut app) = pair();

        // Create input thumbnail file to be encrypted (all 0's)
        let thumbnail_pathname = "test_data/thumbnail_file";
        let file_size: usize = 1069;

        generate_dummy_file(thumbnail_pathname, file_size);

        // Camera encrypts thumbnail file
        let enc_thumbnail_pathname = "test_data/enc_thumbnail_file";
        let mut thumbnail_info =
                    ThumbnailMetaInfo::new(0, 0, vec![]);

        encrypt_thumbnail_file(
            &mut camera,
            thumbnail_pathname,
            enc_thumbnail_pathname,
            &mut thumbnail_info,
        ).unwrap();

        // App tires to decrypt thumbnail file but it "crashes" halfway.
        fs::create_dir("test_data/app/videos").unwrap();

        std::env::set_var("DECRYPT_THUMBNAIL_FILE_CRASH", "1");
        let ret = decrypt_thumbnail_file(
            &mut app,
            enc_thumbnail_pathname,
            "test_data",
        );

        assert!(ret.is_err());

        std::env::remove_var("DECRYPT_THUMBNAIL_FILE_CRASH");

        // App reinitializes, tries to decrypt again, and succeeds.
        let mut app = reinitialize_app();

        let dec_thumbnail_filename = decrypt_thumbnail_file(
            &mut app,
            enc_thumbnail_pathname,
            "test_data",
        ).unwrap();

        let dec_thumbnail_pathname = format!("test_data/app/videos/{}", dec_thumbnail_filename);

        // Check decrypted file
        check_decrypted_dummy_file(&dec_thumbnail_pathname, file_size);
    }

    #[test]
    /// Camera invites app.
    /// App then sends an update proposal.
    /// Camera receives that proposal and then sends a video.
    fn camera_to_app_update_video_test() {
        let (mut camera, mut app) = pair();

        // App generates an update proposal
        let update_proposal = app.update_proposal().unwrap();
        app.save_group_state().unwrap();

        // Camera receives it
        camera.decrypt(update_proposal, false).unwrap();
        camera.save_group_state().unwrap();

        // Create input video file to be encrypted (all 0's)
        let video_pathname = "test_data/video_file";
        let file_size: usize = 96 * 1024 + 135;

        generate_dummy_file(video_pathname, file_size);

        // Camera encrypts video file
        let enc_video_pathname = "test_data/enc_video_file";

        encrypt_video_file(
            &mut camera,
            video_pathname,
            enc_video_pathname,
            0,
        ).unwrap();

        // App decrypts video file
        fs::create_dir("test_data/app/videos").unwrap();

        let dec_video_filename = decrypt_video_file(
            &mut app,
            enc_video_pathname,
        ).unwrap();

        let dec_video_pathname = format!("test_data/app/videos/{}", dec_video_filename);

        // Check decrypted file
        check_decrypted_dummy_file(&dec_video_pathname, file_size);
    }

    #[test]
    /// Camera invites three apps.
    /// It then sends a video to all of them.
    fn camera_to_more_apps_video_test() {
        let (mut camera, mut app) = pair();
        let (mut app2, mut app3) = pair_with_two_more_apps(&mut camera, &mut app);

        // Create input video file to be encrypted (all 0's)
        let video_pathname = "test_data/video_file";
        let file_size: usize = 96 * 1024 + 135;

        generate_dummy_file(video_pathname, file_size);

        // Camera encrypts video file
        let enc_video_pathname = "test_data/enc_video_file";

        encrypt_video_file(
            &mut camera,
            video_pathname,
            enc_video_pathname,
            0,
        ).unwrap();

        let mut apps = [
            (&mut app, "app"),
            (&mut app2, "app2"),
            (&mut app3, "app3"),
        ];

        for (app, name) in apps.iter_mut() {
            // App decrypts video file
            let dir = format!("test_data/{}/videos", name);
            fs::create_dir(&dir).unwrap();

            let dec_video_filename = decrypt_video_file(
                *app,
                enc_video_pathname,
            ).unwrap();

            let dec_video_pathname = format!("{}/{}", dir, dec_video_filename);

            // Check decrypted file by app
            check_decrypted_dummy_file(&dec_video_pathname, file_size);
        }
    }

    #[test]
    /// Camera invites three apps.
    /// All apps then send update proposals.
    /// Camera receives those proposals and
    /// then sends a video to all of them.
    fn camera_to_more_apps_update_video_test() {
        let (mut camera, mut app) = pair();
        let (mut app2, mut app3) = pair_with_two_more_apps(&mut camera, &mut app);

        let apps = [&mut app, &mut app2, &mut app3];

        for app in apps {
            // App generates an update proposal
            let update_proposal = app.update_proposal().unwrap();
            app.save_group_state().unwrap();

            // Camera receives it
            camera.decrypt(update_proposal, false).unwrap();
            camera.save_group_state().unwrap();
        }

        // Create input video file to be encrypted (all 0's)
        let video_pathname = "test_data/video_file";
        let file_size: usize = 96 * 1024 + 135;

        generate_dummy_file(video_pathname, file_size);

        // Camera encrypts video file
        let enc_video_pathname = "test_data/enc_video_file";

        encrypt_video_file(
            &mut camera,
            video_pathname,
            enc_video_pathname,
            0,
        ).unwrap();

        let mut apps = [
            (&mut app, "app"),
            (&mut app2, "app2"),
            (&mut app3, "app3"),
        ];

        for (app, name) in apps.iter_mut() {
            // App decrypts video file
            let dir = format!("test_data/{}/videos", name);
            fs::create_dir(&dir).unwrap();

            let dec_video_filename = decrypt_video_file(
                *app,
                enc_video_pathname,
            ).unwrap();

            let dec_video_pathname = format!("{}/{}", dir, dec_video_filename);

            // Check decrypted file
            check_decrypted_dummy_file(&dec_video_pathname, file_size);
        }
    }

    #[test]
    /// Camera invites app.
    /// App then sends an update proposal.
    /// Camera receives that proposal and then sends a thumbnail.
    fn camera_to_app_update_thumbnail_test() {
        let (mut camera, mut app) = pair();

        // App generates an update proposal
        let update_proposal = app.update_proposal().unwrap();
        app.save_group_state().unwrap();

        // Camera receives it
        camera.decrypt(update_proposal, false).unwrap();
        camera.save_group_state().unwrap();

        // Create input thumbnail file to be encrypted (all 0's)
        let thumbnail_pathname = "test_data/thumbnail_file";
        let file_size: usize = 1069;

        generate_dummy_file(thumbnail_pathname, file_size);

        // Camera encrypts thumbnail file
        let enc_thumbnail_pathname = "test_data/enc_thumbnail_file";
        let mut thumbnail_info =
                    ThumbnailMetaInfo::new(0, 0, vec![]);

        encrypt_thumbnail_file(
            &mut camera,
            thumbnail_pathname,
            enc_thumbnail_pathname,
            &mut thumbnail_info,
        ).unwrap();

        // App decrypts thumbnail file
        fs::create_dir("test_data/app/videos").unwrap();

        let dec_thumbnail_filename = decrypt_thumbnail_file(
            &mut app,
            enc_thumbnail_pathname,
            "test_data",
        ).unwrap();

        let dec_thumbnail_pathname = format!("test_data/app/videos/{}", dec_thumbnail_filename);

        // Check decrypted file
        check_decrypted_dummy_file(&dec_thumbnail_pathname, file_size);
    }

    #[test]
    /// Camera invites three apps.
    /// It then sends a thumbnail to all of them.
    fn camera_to_more_apps_thumbnail_test() {
        let (mut camera, mut app) = pair();
        let (mut app2, mut app3) = pair_with_two_more_apps(&mut camera, &mut app);

        // Create input thumbnail file to be encrypted (all 0's)
        let thumbnail_pathname = "test_data/thumbnail_file";
        let file_size: usize = 1069;

        generate_dummy_file(thumbnail_pathname, file_size);

        // Camera encrypts thumbnail file
        let enc_thumbnail_pathname = "test_data/enc_thumbnail_file";
        let mut thumbnail_info =
                    ThumbnailMetaInfo::new(0, 0, vec![]);

        encrypt_thumbnail_file(
            &mut camera,
            thumbnail_pathname,
            enc_thumbnail_pathname,
            &mut thumbnail_info,
        ).unwrap();

        let mut apps = [
            (&mut app, "app"),
            (&mut app2, "app2"),
            (&mut app3, "app3"),
        ];

        for (app, name) in apps.iter_mut() {
            // App decrypts thumbnail file
            let dir = format!("test_data/{}/videos", name);
            fs::create_dir(&dir).unwrap();

            let dec_thumbnail_filename = decrypt_thumbnail_file(
                *app,
                enc_thumbnail_pathname,
                "test_data",
            ).unwrap();

            let dec_thumbnail_pathname = format!("{}/{}", dir, dec_thumbnail_filename);

            // Check decrypted file
            check_decrypted_dummy_file(&dec_thumbnail_pathname, file_size);
        }
    }

    #[test]
    /// Camera invites three apps.
    /// All apps then send update proposals.
    /// Camera receives those proposals and
    /// then sends a thumbnail to all of them.
    fn camera_to_more_apps_update_thumbnail_test() {
        let (mut camera, mut app) = pair();
        let (mut app2, mut app3) = pair_with_two_more_apps(&mut camera, &mut app);

        let apps = [&mut app, &mut app2, &mut app3];

        for app in apps {
            // App generates an update proposal
            let update_proposal = app.update_proposal().unwrap();
            app.save_group_state().unwrap();

            // Camera receives it
            camera.decrypt(update_proposal, false).unwrap();
            camera.save_group_state().unwrap();
        }

        // Create input thumbnail file to be encrypted (all 0's)
        let thumbnail_pathname = "test_data/thumbnail_file";
        let file_size: usize = 1069;

        generate_dummy_file(thumbnail_pathname, file_size);

        // Camera encrypts thumbnail file
        let enc_thumbnail_pathname = "test_data/enc_thumbnail_file";
        let mut thumbnail_info =
                    ThumbnailMetaInfo::new(0, 0, vec![]);

        encrypt_thumbnail_file(
            &mut camera,
            thumbnail_pathname,
            enc_thumbnail_pathname,
            &mut thumbnail_info,
        ).unwrap();

        let mut apps = [
            (&mut app, "app"),
            (&mut app2, "app2"),
            (&mut app3, "app3"),
        ];

        for (app, name) in apps.iter_mut() {
            // App decrypts thumbnail file
            let dir = format!("test_data/{}/videos", name);
            fs::create_dir(&dir).unwrap();

            let dec_thumbnail_filename = decrypt_thumbnail_file(
                *app,
                enc_thumbnail_pathname,
                "test_data",
            ).unwrap();

            let dec_thumbnail_pathname = format!("{}/{}", dir, dec_thumbnail_filename);

            // Check decrypted file
            check_decrypted_dummy_file(&dec_thumbnail_pathname, file_size);
        }
    }

    /// The input app generates an update proposal and returns it.
    fn app_update(
        app: &mut MlsClient,
    ) -> Vec<u8> {
        let update_proposal = app.update_proposal().unwrap();
        app.save_group_state().unwrap();

        update_proposal
    }

    /// Camera receives the update proposal.
    fn camera_receive_update_proposal(
        camera: &mut MlsClient,
        update_proposal: Vec<u8>,
    ) {
        camera.decrypt(update_proposal, false).unwrap();
        camera.save_group_state().unwrap();
    }

    /// Camera receives the update proposal.
    fn camera_receive_update_proposal_ignore_old(
        camera: &mut MlsClient,
        update_proposal: Vec<u8>,
    ) {
        let _ = camera.decrypt(update_proposal, false);
        camera.save_group_state().unwrap();
    }

    /// Decrypts an encrypted file and check the decrypted file.
    fn decrypt_and_check_file(
        app: &mut MlsClient,
        name: &str,
        enc_video_pathname: &str,
        file_size: usize,
    ) {
        // App decrypts video file
        let dir = format!("test_data/{}/videos", name);
        fs::create_dir_all(&dir).unwrap();

        let dec_video_filename = decrypt_video_file(
            app,
            enc_video_pathname,
        ).unwrap();

        let dec_video_pathname = format!("{}/{}", dir, dec_video_filename);

        // Check decrypted file
        check_decrypted_dummy_file(&dec_video_pathname, file_size);
    }

    #[test]
    /// Functionally, this test is supposed to be similar
    /// to camera_to_more_apps_update_video_test.
    /// However, it is one of the tests that shuffle
    /// the operations to test race conditions that we find.
    /// In this specific test, app3 is added after updates by other apps,
    /// but before a video is encrypted.
    fn camera_to_more_apps_update_video_race_test_1() {
        let (mut camera, mut app) = pair();
        let mut app2 = pair_with_app2(&mut camera, &mut app);

        // app1 update
        let update_proposal = app_update(&mut app);
        camera_receive_update_proposal(&mut camera, update_proposal);

        // app2 update
        let update_proposal = app_update(&mut app2);
        camera_receive_update_proposal(&mut camera, update_proposal);
        
        // Create input video file to be encrypted (all 0's)
        let video_pathname = "test_data/video_file";
        let file_size: usize = 96 * 1024 + 135;

        generate_dummy_file(video_pathname, file_size);

        // Add app3
        let (mut app3, psk_proposal_vec, commit_msg_vec, update_proposals) = pair_with_app3_handshake(&mut camera, &mut app);
        pair_with_app3_inform_app2(&mut app2, psk_proposal_vec, commit_msg_vec, update_proposals);

        // Camera encrypts video file
        let enc_video_pathname = "test_data/enc_video_file";

        encrypt_video_file(
            &mut camera,
            video_pathname,
            enc_video_pathname,
            0,
        ).unwrap();

        decrypt_and_check_file(&mut app, "app", enc_video_pathname, file_size);
        decrypt_and_check_file(&mut app2, "app2", enc_video_pathname, file_size);
        decrypt_and_check_file(&mut app3, "app3", enc_video_pathname, file_size);
    }

    #[test]
    /// Functionally, this test is supposed to be similar
    /// to camera_to_more_apps_update_video_test.
    /// However, it is one of the tests that shuffle
    /// the operations to test race conditions that we find.
    /// In this specific test, app2 is informed of the addition of
    /// app3 after app performs an update.
    fn camera_to_more_apps_update_video_race_test_2() {
        let (mut camera, mut app) = pair();
        let mut app2 = pair_with_app2(&mut camera, &mut app);
        let (mut app3, psk_proposal_vec, commit_msg_vec, update_proposals) = pair_with_app3_handshake(&mut camera, &mut app);

        // app1 update
        let update_proposal = app_update(&mut app);
        camera_receive_update_proposal(&mut camera, update_proposal);

        // app2 update
        let update_proposal = app_update(&mut app2);

        pair_with_app3_inform_app2(&mut app2, psk_proposal_vec, commit_msg_vec, update_proposals);
        camera_receive_update_proposal_ignore_old(&mut camera, update_proposal);

        // app3 update
        let update_proposal = app_update(&mut app3);
        camera_receive_update_proposal(&mut camera, update_proposal);

        // Create input video file to be encrypted (all 0's)
        let video_pathname = "test_data/video_file";
        let file_size: usize = 96 * 1024 + 135;

        generate_dummy_file(video_pathname, file_size);

        // Camera encrypts video file
        let enc_video_pathname = "test_data/enc_video_file";

        encrypt_video_file(
            &mut camera,
            video_pathname,
            enc_video_pathname,
            0,
        ).unwrap();

        decrypt_and_check_file(&mut app, "app", enc_video_pathname, file_size);
        decrypt_and_check_file(&mut app2, "app2", enc_video_pathname, file_size);
        decrypt_and_check_file(&mut app3, "app3", enc_video_pathname, file_size);
    }

    #[test]
    /// Camera invites three apps and immediately sends a message to them.
    /// It then removes one of them and sends another message.
    fn remove_app() {
        let (mut camera, mut app) = pair();
        let (mut app2, mut app3) = pair_with_two_more_apps(&mut camera, &mut app);

        // Camera encrypts a new message
        let msg = "Hello, apps!";
        let msg_enc = camera
            .encrypt(msg.as_bytes())
            .unwrap();
        camera.save_group_state().unwrap();

        //App decrypts the message
        let msg_dec_vec = app.decrypt(msg_enc.clone(), true).unwrap();
        app.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);

        //App2 decrypts the message
        let msg_dec_vec = app2.decrypt(msg_enc.clone(), true).unwrap();
        app2.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);

        //App3 decrypts the message
        let msg_dec_vec = app3.decrypt(msg_enc, true).unwrap();
        app3.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);

        //Remove app2
        let remove_message = camera.remove("app2").unwrap();
        camera.save_group_state().unwrap();

        //Send remove message to app
        app.decrypt(remove_message.clone(), false).unwrap();
        app.save_group_state().unwrap();

        //Send remove message to app2 (although this is not necessary)
        app2.decrypt(remove_message.clone(), false).unwrap();
        app2.save_group_state().unwrap();

        //Send remove message to app3
        app3.decrypt(remove_message, false).unwrap();
        app3.save_group_state().unwrap();

        // Camera encrypts a new message
        let msg = "Hello, apps that are not removed!";
        let msg_enc = camera
            .encrypt(msg.as_bytes())
            .unwrap();
        camera.save_group_state().unwrap();

        //App decrypts the message
        let msg_dec_vec = app.decrypt(msg_enc.clone(), true).unwrap();
        app.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);

        //App2 fails to decrypt the message
        let ret = app2.decrypt(msg_enc.clone(), true);
        app2.save_group_state().unwrap();
        
        assert!(ret.is_err());

        //App3 decrypts the message
        let msg_dec_vec = app3.decrypt(msg_enc, true).unwrap();
        app3.save_group_state().unwrap();
        let msg_dec = std::str::from_utf8(&msg_dec_vec).unwrap();

        assert!(msg == msg_dec);
    }
}
