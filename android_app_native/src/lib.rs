//! Privastead app JNI interface
//!
//! Copyright (C) 2025  Ardalan Amiri Sani
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

//! This file uses and modifies some code from:
//! https://github.com/gendx/android-rust-library (https://gendignoux.com/blog/2022/10/24/rust-library-android.html)
//! MIT License.

pub mod core;

#[cfg(target_os = "android")]
mod logger;

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    use jni::objects::{JClass, JString};
    use jni::sys::{jboolean, jbyteArray, jstring, jlong, JNI_TRUE};
    use jni::JNIEnv;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use crate::core::{
        add_camera, decrypt_fcm_timestamp, decrypt_video, deregister, get_livestream_group_name,
        get_motion_group_name, initialize, livestream_decrypt, livestream_update, my_log, Clients,
    };

    use crate::logger::AndroidLogger;

    static CLIENTS: Mutex<Option<HashMap<String, Mutex<Option<Box<Clients>>>>>> = Mutex::new(None);

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_initialize(
        env: JNIEnv,
        _: JClass,
        dir: JString,
        name: JString,
        first: jboolean,
    ) -> jboolean {
        // First, wait for any ongoing JNI calls to finish.
        let mut clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_initialize")
            .expect("Couldn't create logger object");

        let file_dir: String = env
            .get_string(dir)
            .expect("Couldn't covert to Rust String")
            .into();
        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();
        let first_time: bool = first == JNI_TRUE;

        if (*clients).is_none() {
            *clients = Some(HashMap::new());
        }

        let camera_clients = (*clients)
            .as_mut()
            .unwrap()
            .entry(camera_name.clone())
            .or_insert(Mutex::new(None))
            .lock()
            .unwrap();

        match initialize(camera_clients, file_dir, first_time) {
            Ok(_) => {
                return true as jboolean;
            }
            Err(e) => {
                my_log(Some(&logger), format!("Error: {}", e));
                return false as jboolean;
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_deregister(
        env: JNIEnv,
        _: JClass,
        name: JString,
    ) {
        let mut clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_deregister")
            .expect("Couldn't create logger object");

        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();

        if (*clients).is_none() {
            my_log(Some(&logger), "Error: clients hashmap not initialized!");
            return;
        }

        let camera_clients = (*clients)
            .as_mut()
            .unwrap()
            .entry(camera_name.clone())
            .or_insert(Mutex::new(None))
            .lock()
            .unwrap();

        deregister(camera_clients, Some(&logger));

        if (*clients).as_mut().unwrap().remove(&camera_name).is_none() {
            my_log(
                Some(&logger),
                "Error: could not remove the clients from hashmap!",
            );
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_addCamera(
        env: JNIEnv,
        _: JClass,
        name: JString,
        ip: JString,
        secret: jbyteArray,
        standalone: jboolean,
        ssid: JString,
        password: JString,
    ) -> jboolean {
        let mut clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_addCamera")
            .expect("Couldn't create logger object");

        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();
        let camera_ip: String = env
            .get_string(ip)
            .expect("Couldn't covert to Rust String")
            .into();
        let secret_vec: Vec<u8> = env.convert_byte_array(secret).unwrap();
        let standalone_camera: bool = standalone == JNI_TRUE;
        let wifi_ssid: String = env
            .get_string(ssid)
            .expect("Couldn't covert to Rust String")
            .into();
        let wifi_password: String = env
            .get_string(password)
            .expect("Couldn't covert to Rust String")
            .into();

        if (*clients).is_none() {
            my_log(Some(&logger), "Error: clients hashmap not initialized!");
            return false as jboolean;
        }

        let camera_clients = (*clients)
            .as_mut()
            .unwrap()
            .entry(camera_name.clone())
            .or_insert(Mutex::new(None))
            .lock()
            .unwrap();

        match add_camera(
            camera_clients,
            camera_name,
            camera_ip,
            secret_vec,
            standalone_camera,
            wifi_ssid,
            wifi_password,
        ) {
            Ok(_) => {
                return true as jboolean;
            }
            Err(e) => {
                my_log(Some(&logger), format!("Error: {}", e));
                return false as jboolean;
            }
        }
    }

    /// Returns the decrypted filename.
    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_decryptVideo(
        env: JNIEnv,
        _: JClass,
        name: JString,
        enc_filename: JString,
    ) -> jstring {
        let mut clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_decryptVideo")
            .expect("Couldn't create logger object");

        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();

        let encrypted_filename: String = env
            .get_string(enc_filename)
            .expect("Couldn't covert to Rust String")
            .into();

        if (*clients).is_none() {
            my_log(Some(&logger), "Error: clients hashmap not initialized!");
            let output = env.new_string("Error").expect("Couldn't create jstring!");
            return output.into_raw();
        }

        let camera_clients = (*clients)
            .as_mut()
            .unwrap()
            .entry(camera_name.clone())
            .or_insert(Mutex::new(None))
            .lock()
            .unwrap();

        match decrypt_video(camera_clients, encrypted_filename) {
            Ok(decrypted_filename) => {
                let output = env
                    .new_string(decrypted_filename)
                    .expect("Couldn't create jstring!");
                return output.into_raw();
            }
            Err(e) => {
                my_log(Some(&logger), format!("Error: {}", e));
                let output = env.new_string("Error").expect("Couldn't create jstring!");
                return output.into_raw();
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_decryptFcmTimestamp(
        env: JNIEnv,
        _: JClass,
        name: JString,
        msg: jbyteArray,
    ) -> jstring {
        let mut clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_decryptFCMTimestamp")
            .expect("Couldn't create logger object");

        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();

        let message: Vec<u8> = env.convert_byte_array(msg).unwrap();

        if (*clients).is_none() {
            my_log(Some(&logger), "Error: clients hashmap not initialized!");
            let output = env.new_string("Error").expect("Couldn't create jstring!");
            return output.into_raw();
        }

        let camera_clients = (*clients)
            .as_mut()
            .unwrap()
            .entry(camera_name.clone())
            .or_insert(Mutex::new(None))
            .lock()
            .unwrap();

        match decrypt_fcm_timestamp(camera_clients, message) {
            Ok(timestamp) => {
                let output = env.new_string(timestamp).expect("Couldn't create jstring!");
                return output.into_raw();
            }
            Err(e) => {
                my_log(Some(&logger), format!("Error: {}", e));
                let output = env.new_string("Error").expect("Couldn't create jstring!");
                return output.into_raw();
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_getMotionGroupName(
        env: JNIEnv,
        _: JClass,
        name: JString,
    ) -> jstring {
        let mut clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_getMotionGroupName")
            .expect("Couldn't create logger object");

        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();

        if (*clients).is_none() {
            my_log(Some(&logger), "Error: clients hashmap not initialized!");
            let output = env.new_string("Error").expect("Couldn't create jstring!");
            return output.into_raw();
        }

        let camera_clients = (*clients)
            .as_mut()
            .unwrap()
            .entry(camera_name.clone())
            .or_insert(Mutex::new(None))
            .lock()
            .unwrap();

        match get_motion_group_name(camera_clients, camera_name) {
            Ok(motion_group_name) => {
                let output = env
                    .new_string(motion_group_name)
                    .expect("Couldn't create jstring!");
                return output.into_raw();
            }
            Err(e) => {
                my_log(Some(&logger), format!("Error: {}", e));
                let output = env.new_string("Error").expect("Couldn't create jstring!");
                return output.into_raw();
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_getLivestreamGroupName(
        env: JNIEnv,
        _: JClass,
        name: JString,
    ) -> jstring {
        let mut clients = CLIENTS.lock().unwrap();

        let logger =
            AndroidLogger::new(env, "Privastead Camera: RustNative_getLivestreamGroupName")
                .expect("Couldn't create logger object");

        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();

        if (*clients).is_none() {
            my_log(Some(&logger), "Error: clients hashmap not initialized!");
            let output = env.new_string("Error").expect("Couldn't create jstring!");
            return output.into_raw();
        }

        let camera_clients = (*clients)
            .as_mut()
            .unwrap()
            .entry(camera_name.clone())
            .or_insert(Mutex::new(None))
            .lock()
            .unwrap();

        match get_livestream_group_name(camera_clients, camera_name) {
            Ok(livestream_group_name) => {
                let output = env
                    .new_string(livestream_group_name)
                    .expect("Couldn't create jstring!");
                return output.into_raw();
            }
            Err(e) => {
                my_log(Some(&logger), format!("Error: {}", e));
                let output = env.new_string("Error").expect("Couldn't create jstring!");
                return output.into_raw();
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_livestreamDecrypt(
        env: JNIEnv,
        _: JClass,
        name: JString,
        data: jbyteArray,
        expected: jlong,
    ) -> jbyteArray {
        let mut clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_livestreamDecrypt")
            .expect("Couldn't create logger object");

        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();

        let enc_data: Vec<u8> = env.convert_byte_array(data).unwrap();

        if expected < 0 {
            //FIXME: There's no good way to return an error. So we panic instead.
            panic!("Error: invalid expected chunk number!");
        }

        let expected_chunk_number = expected as u64;

        if (*clients).is_none() {
            my_log(Some(&logger), "Error: clients hashmap not initialized!");
            //FIXME: There's no good way to return an error. So we panic instead.
            panic!("Error: clients hashmap not initialized!");
        }

        let camera_clients = (*clients)
            .as_mut()
            .unwrap()
            .entry(camera_name.clone())
            .or_insert(Mutex::new(None))
            .lock()
            .unwrap();

        let ret = match livestream_decrypt(camera_clients, enc_data, expected_chunk_number) {
            Ok(dec_data) => dec_data,
            Err(e) => {
                my_log(Some(&logger), format!("Error: {}", e));
                // An error could indicate a malicious input, e.g., invalid chunk order.
                // We shouldn't resume livestreaming after this point.
                // This should crash the livestreaming thread.
                panic!("Error: {}", e);
            }
        };

        let output = env
            .byte_array_from_slice(&ret)
            .expect("Couldn't create jbyteArray!");
        output
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_livestreamUpdate(
        env: JNIEnv,
        _: JClass,
        name: JString,
        msg: jbyteArray,
    ) -> jboolean {
        let mut clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_livestreamUpdate")
            .expect("Couldn't create logger object");

        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();

        let updates_msg: Vec<u8> = env.convert_byte_array(msg).unwrap();

        if (*clients).is_none() {
            my_log(Some(&logger), "Error: clients hashmap not initialized!");
            return false as jboolean;
        }

        let camera_clients = (*clients)
            .as_mut()
            .unwrap()
            .entry(camera_name.clone())
            .or_insert(Mutex::new(None))
            .lock()
            .unwrap();

        match livestream_update(camera_clients, updates_msg) {
            Ok(_) => {
                return true as jboolean;
            }
            Err(e) => {
                my_log(Some(&logger), format!("Error: {}", e));
                return false as jboolean;
            }
        }
    }
}
