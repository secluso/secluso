//! Privastead app JNI interface
//!
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

//! This file uses and modifies some code from:
//! https://github.com/gendx/android-rust-library (https://gendignoux.com/blog/2022/10/24/rust-library-android.html)
//! MIT License.

mod core;

#[cfg(target_os = "android")]
mod logger;

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    use jni::objects::{JClass, JString};
    use jni::sys::{jboolean, jbyteArray, jsize, jstring, JNI_TRUE};
    use jni::JNIEnv;
    use std::sync::Mutex;
    use std::collections::HashMap;

    use crate::core::{
        add_camera, decrypt, deregister, initialize, livestream_end, livestream_read,
        livestream_start, receive, update_token, Clients, LivestreamSession, my_log
    };
    use crate::logger::AndroidLogger;

    static CLIENTS: Mutex<Option<HashMap<String, Mutex<Option<Box<Clients>>>>>> = Mutex::new(None);
    static SESSION: Mutex<Option<Box<LivestreamSession>>> = Mutex::new(None);

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_initialize(
        env: JNIEnv,
        _: JClass,
        ip: JString,
        tokn: JString,
        dir: JString,
        name: JString,
        first: jboolean,
        credentials: jbyteArray,
        network: jboolean,
    ) -> jboolean {
        // First, wait for any ongoing JNI calls to finish.
        let mut clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_initialize")
            .expect("Couldn't create logger object");

        let server_ip: String = env
            .get_string(ip)
            .expect("Couldn't covert to Rust String")
            .into();
        let token: String = env
            .get_string(tokn)
            .expect("Couldn't covert to Rust String")
            .into();
        let file_dir: String = env
            .get_string(dir)
            .expect("Couldn't covert to Rust String")
            .into();
        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();
        let first_time: bool = first == JNI_TRUE;
        let user_credentials: Vec<u8> = env.convert_byte_array(credentials).unwrap();
        let need_network: bool = network == JNI_TRUE;

        if (*clients).is_none() {
            *clients = Some(HashMap::new());
        }

        let camera_clients = (*clients).as_mut().unwrap().entry(camera_name.clone()).or_insert(Mutex::new(None)).lock().unwrap();

        let ret = initialize(
            camera_clients,
            server_ip,
            token,
            file_dir,
            first_time,
            user_credentials,
            need_network,
            Some(&logger),
        );

        return ret as jboolean;
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_deregister(env: JNIEnv, _: JClass, name: JString) {
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
    
        let camera_clients = (*clients).as_mut().unwrap().entry(camera_name.clone()).or_insert(Mutex::new(None)).lock().unwrap();

        deregister(camera_clients, Some(&logger));

        if (*clients).as_mut().unwrap().remove(&camera_name).is_none() {
            my_log(Some(&logger), "Error: could not remove the clients from hashmap!");
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_updateToken(
        env: JNIEnv,
        _: JClass,
        tokn: JString,
        name: JString,
    ) -> jboolean {
        let mut clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_updateToken")
            .expect("Couldn't create logger object");

        let token: String = env
            .get_string(tokn)
            .expect("Couldn't covert to Rust String")
            .into();

        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();

        if (*clients).is_none() {
            my_log(Some(&logger), "Error: clients hashmap not initialized!");
            return false as jboolean;
        }

        let camera_clients = (*clients).as_mut().unwrap().entry(camera_name.clone()).or_insert(Mutex::new(None)).lock().unwrap();

        let ret = update_token(camera_clients, token, Some(&logger));

        return ret as jboolean;
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

        let camera_clients = (*clients).as_mut().unwrap().entry(camera_name.clone()).or_insert(Mutex::new(None)).lock().unwrap();

        let ret = add_camera(
            camera_clients,
            camera_name,
            camera_ip,
            secret_vec,
            standalone_camera,
            wifi_ssid,
            wifi_password,
            Some(&logger),
        );

        return ret as jboolean;
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_receive(
        env: JNIEnv,
        _: JClass,
        name: JString,
    ) -> jstring {
        let mut clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_receive")
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

        let camera_clients = (*clients).as_mut().unwrap().entry(camera_name.clone()).or_insert(Mutex::new(None)).lock().unwrap();

        let ret = receive(camera_clients, Some(&logger));

        let output = env.new_string(ret).expect("Couldn't create jstring!");
        output.into_raw()
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_decrypt(
        env: JNIEnv,
        _: JClass,
        name: JString,
        msg: jbyteArray,
    ) -> jstring {
        let mut clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_decrypt")
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

        let camera_clients = (*clients).as_mut().unwrap().entry(camera_name.clone()).or_insert(Mutex::new(None)).lock().unwrap();

        let ret = decrypt(camera_clients, message, Some(&logger));

        let output = env.new_string(ret).expect("Couldn't create jstring!");
        output.into_raw()
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_livestreamStart(
        env: JNIEnv,
        _: JClass,
        name: JString,
    ) -> jboolean {
        let mut clients = CLIENTS.lock().unwrap();
        let session = SESSION.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_livestreamStart")
            .expect("Couldn't create logger object");

        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();

        if (*clients).is_none() {
            my_log(Some(&logger), "Error: clients hashmap not initialized!");
            return false as jboolean;
        }

        let camera_clients = (*clients).as_mut().unwrap().entry(camera_name.clone()).or_insert(Mutex::new(None)).lock().unwrap();

        let ret = livestream_start(camera_clients, session, camera_name, Some(&logger));

        return ret as jboolean;
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_livestreamEnd(
        env: JNIEnv,
        _: JClass,
        name: JString,
    ) -> jboolean {
        let mut clients = CLIENTS.lock().unwrap();
        let session = SESSION.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_livestreamEnd")
            .expect("Couldn't create logger object");

        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();

        if (*clients).is_none() {
            my_log(Some(&logger), "Error: clients hashmap not initialized!");
            return false as jboolean;
        }

        let camera_clients = (*clients).as_mut().unwrap().entry(camera_name.clone()).or_insert(Mutex::new(None)).lock().unwrap();

        let ret = livestream_end(camera_clients, session, Some(&logger));

        return ret as jboolean;
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_livestreamRead(
        env: JNIEnv,
        _: JClass,
        name: JString,
        len: jsize,
    ) -> jbyteArray {
        let mut clients = CLIENTS.lock().unwrap();
        let session = SESSION.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_livestreamRead")
            .expect("Couldn't create logger object");

        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();

        let read_length: usize = len as usize;

        if (*clients).is_none() {
            my_log(Some(&logger), "Error: clients hashmap not initialized!");
            //FIXME: There's no good way to return an error. So we panic instead.
            panic!("Error: clients hashmap not initialized!");
        }

        let camera_clients = (*clients).as_mut().unwrap().entry(camera_name.clone()).or_insert(Mutex::new(None)).lock().unwrap();

        let ret = livestream_read(camera_clients, session, read_length, Some(&logger));

        let output = env
            .byte_array_from_slice(&ret)
            .expect("Couldn't create jbyteArray!");
        output
    }
}
