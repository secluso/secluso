//! From:
//! https://github.com/gendx/android-rust-library (https://gendignoux.com/blog/2022/10/24/rust-library-android.html)
//! MIT License.

#[cfg(target_os = "android")]
use jni::objects::{JClass, JObject, JString, JValue};
#[cfg(target_os = "android")]
use jni::JNIEnv;
use std::fmt::Debug;

pub trait Logger {
    type E: Debug;

    /// Prints a message at the debug level.
    fn d(&self, message: impl AsRef<str>) -> Result<(), Self::E>;
}

#[cfg(test)]
pub struct PrintlnLogger {}

#[cfg(test)]
impl Logger for PrintlnLogger {
    type E = !;

    fn d(&self, message: impl AsRef<str>) -> Result<(), Self::E> {
        println!("{}", message.as_ref());
        Ok(())
    }
}

#[cfg(target_os = "android")]
pub struct AndroidLogger<'a> {
    /// JNI environment.
    env: JNIEnv<'a>,
    /// Reference to the android.util.Log class.
    log_class: JClass<'a>,
    /// Tag for log messages.
    tag: JString<'a>,
}

#[cfg(target_os = "android")]
impl<'a> AndroidLogger<'a> {
    pub fn new(env: JNIEnv<'a>, tag: &str) -> Result<Self, jni::errors::Error> {
        Ok(Self {
            env,
            log_class: env.find_class("android/util/Log")?,
            tag: env.new_string(tag)?,
        })
    }
}

#[cfg(target_os = "android")]
impl<'a> Logger for AndroidLogger<'a> {
    type E = jni::errors::Error;

    fn d(&self, message: impl AsRef<str>) -> Result<(), Self::E> {
        self.env.call_static_method(
            self.log_class,
            "d",
            "(Ljava/lang/String;Ljava/lang/String;)I",
            &[
                JValue::Object(JObject::from(self.tag)),
                JValue::Object(JObject::from(self.env.new_string(message)?)),
            ],
        )?;
        Ok(())
    }
}
