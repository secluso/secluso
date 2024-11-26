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

    use crate::core::{
        add_camera, decode, deregister, initialize, livestream_end, livestream_read,
        livestream_start, receive, update_token, Clients, LivestreamSession,
    };
    use crate::logger::AndroidLogger;

    static CLIENTS: Mutex<Option<Box<Clients>>> = Mutex::new(None);
    static SESSION: Mutex<Option<Box<LivestreamSession>>> = Mutex::new(None);

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_initialize(
        env: JNIEnv,
        _: JClass,
        ip: JString,
        tokn: JString,
        dir: JString,
        first: jboolean,
        credentials: jbyteArray,
    ) -> jboolean {
        // First, wait for any ongoing JNI calls to finish.
        let clients = CLIENTS.lock().unwrap();

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
        let first_time: bool = first == JNI_TRUE;
        let user_credentials: Vec<u8> = env.convert_byte_array(credentials).unwrap();

        let ret = initialize(
            clients,
            server_ip,
            token,
            file_dir,
            first_time,
            user_credentials,
            Some(&logger),
        );

        return ret as jboolean;
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_deregister(env: JNIEnv, _: JClass) {
        let clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_deregister")
            .expect("Couldn't create logger object");

        deregister(clients, Some(&logger));
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_updateToken(
        env: JNIEnv,
        _: JClass,
        tokn: JString,
    ) -> jboolean {
        let clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_updateToken")
            .expect("Couldn't create logger object");

        let token: String = env
            .get_string(tokn)
            .expect("Couldn't covert to Rust String")
            .into();

        let ret = update_token(clients, token, Some(&logger));

        return ret as jboolean;
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_addCamera(
        env: JNIEnv,
        _: JClass,
        name: JString,
        ip: JString,
        secret: jbyteArray,
    ) -> jboolean {
        let clients = CLIENTS.lock().unwrap();

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

        let ret = add_camera(clients, camera_name, camera_ip, secret_vec, Some(&logger));

        return ret as jboolean;
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_receive(
        env: JNIEnv,
        _: JClass,
    ) -> jstring {
        let clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_receive")
            .expect("Couldn't create logger object");

        let ret = receive(clients, Some(&logger));

        let output = env.new_string(ret).expect("Couldn't create jstring!");
        output.into_raw()
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_decode(
        env: JNIEnv,
        _: JClass,
        msg: jbyteArray,
    ) -> jstring {
        let clients = CLIENTS.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_decode")
            .expect("Couldn't create logger object");

        let message: Vec<u8> = env.convert_byte_array(msg).unwrap();

        let ret = decode(clients, message, Some(&logger));

        let output = env.new_string(ret).expect("Couldn't create jstring!");
        output.into_raw()
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_livestreamStart(
        env: JNIEnv,
        _: JClass,
        name: JString,
    ) -> jboolean {
        let clients = CLIENTS.lock().unwrap();
        let session = SESSION.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_livestreamStart")
            .expect("Couldn't create logger object");

        let camera_name: String = env
            .get_string(name)
            .expect("Couldn't covert to Rust String")
            .into();

        let ret = livestream_start(clients, session, camera_name, Some(&logger));

        return ret as jboolean;
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_livestreamEnd(
        env: JNIEnv,
        _: JClass,
    ) -> jboolean {
        let clients = CLIENTS.lock().unwrap();
        let session = SESSION.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_livestreamEnd")
            .expect("Couldn't create logger object");

        let ret = livestream_end(clients, session, Some(&logger));

        return ret as jboolean;
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_privastead_camera_RustNative_livestreamRead(
        env: JNIEnv,
        _: JClass,
        len: jsize,
    ) -> jbyteArray {
        let clients = CLIENTS.lock().unwrap();
        let session = SESSION.lock().unwrap();

        let logger = AndroidLogger::new(env, "Privastead Camera: RustNative_livestreamRead")
            .expect("Couldn't create logger object");

        let read_length: usize = len as usize;

        let ret = livestream_read(clients, session, read_length, Some(&logger));

        let output = env
            .byte_array_from_slice(&ret)
            .expect("Couldn't create jbyteArray!");
        output
    }
}
