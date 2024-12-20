//! Code to interface with IP cameras.
//! Assumes the camera supports RTSP and ONVIF
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

use crate::delivery_monitor::VideoInfo;
use crate::fmp4;
use crate::livestream::LivestreamWriter;
use crate::mp4;
use base64::encode;
use chrono::Utc;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_xml_rs::from_str;
use sha1::{Digest, Sha1};
use std::fs;
use std::io;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process;
use std::thread;
use tokio::runtime::Runtime;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(rename = "Header")]
    header: Option<Header>,
    #[serde(rename = "Body")]
    body: Body,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Header {
    #[serde(rename = "Action")]
    action: String,
    #[serde(rename = "To")]
    to: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Body {
    #[serde(rename = "PullMessagesResponse")]
    pull_messages_response: Option<PullMessagesResponse>,
    #[serde(rename = "CreatePullPointSubscriptionResponse")]
    create_pull_point_subscription_response: Option<CreatePullPointSubscriptionResponse>,
    #[serde(rename = "Fault")]
    fault: Option<Fault>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct PullMessagesResponse {
    #[serde(rename = "CurrentTime")]
    current_time: String,
    #[serde(rename = "TerminationTime")]
    termination_time: String,
    #[serde(rename = "NotificationMessage")]
    notification_message: Vec<NotificationMessage>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct NotificationMessage {
    #[serde(rename = "Topic")]
    topic: Topic,
    #[serde(rename = "Message")]
    message: Message,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Topic {
    #[serde(rename = "$value")]
    topic: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Message {
    #[serde(rename = "UtcTime")]
    utc_time: Option<String>,
    #[serde(rename = "PropertyOperation")]
    property_operation: Option<String>,
    #[serde(rename = "Source")]
    source: Option<Source>,
    #[serde(rename = "Data")]
    data: Data,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Source {
    #[serde(rename = "SimpleItem")]
    simple_item: Vec<SimpleItem>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Data {
    #[serde(rename = "SimpleItem")]
    simple_item: Vec<SimpleItem>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SimpleItem {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Debug, Deserialize)]
struct CreatePullPointSubscriptionResponse {
    #[serde(rename = "SubscriptionReference")]
    subscription_reference: SubscriptionReference,
}

#[derive(Debug, Deserialize)]
struct SubscriptionReference {
    #[serde(rename = "Address")]
    address: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Fault {
    #[serde(rename = "Code")]
    code: FaultCode,
    #[serde(rename = "Reason")]
    reason: FaultReason,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct FaultCode {
    #[serde(rename = "Value")]
    value: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct FaultReason {
    #[serde(rename = "Text")]
    text: String,
}

pub struct IpCamera {
    ip_addr: String,
    rtsp_port: String,
    username: String,
    password: String,
    pull_url: String,
    dir: String,
}

impl IpCamera {
    pub fn new(
        ip_addr: String,
        rtsp_port: String,
        username: String,
        password: String,
        dir: String,
    ) -> io::Result<Self> {
        let pull_url = if Path::new(&(dir.clone() + "/onvif_subscription_url")).exists() {
            let file = fs::File::open(dir.clone() + "/onvif_subscription_url")
                .expect("Cannot open file to send");
            let mut reader =
                BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
            let url_bytes = reader.fill_buf().unwrap();

            String::from_utf8(url_bytes.to_vec()).unwrap()
        } else {
            let url = Self::set_up_pull_point(ip_addr.clone(), username.clone(), password.clone())?;

            let mut file = fs::File::create(dir.clone() + "/onvif_subscription_url")
                .expect("Could not create file");
            let _ = file.write_all(url.as_bytes());

            url
        };
        log::debug!("pull_url: {}", pull_url);

        Ok(Self {
            ip_addr,
            rtsp_port,
            username,
            password,
            pull_url,
            dir,
        })
    }

    pub fn delete_pull_url_file(&self) {
        let _ = fs::remove_file(self.dir.clone() + "/onvif_subscription_url");
    }

    fn set_up_pull_point(
        ip_addr: String,
        username: String,
        password: String,
    ) -> io::Result<String> {
        // URL for creating subscription
        let subscription_url = "http://".to_owned() + &ip_addr + "/onvif/event_service";

        // Create pull-point subscription request
        let create_subscription_request = Self::create_pull_point_subscription_request(
            username,
            password,
            subscription_url.clone(),
        );

        // Send create subscription request
        let response = Self::send_soap_request(subscription_url, create_subscription_request)?;

        log::debug!("Create subscription response: {}", response);
        if response.contains("Invalid username or password") {
            println!("Invalid username or password for the IP camera!");
            process::exit(0);
        } else if response.contains("Wsse authorized time check failed") {
            println!("Camera's date/time is out of sync with the hub! Resync them and run the hub again.");
            process::exit(0);
        }

        let events = Self::parse_response(response)?;

        let subscription_address =
            if let Some(response) = events.body.create_pull_point_subscription_response {
                response.subscription_reference.address
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Failed to create subscription",
                ));
            };

        // URL for PullMessages
        Ok(subscription_address)
    }

    fn pull_events(&self) -> io::Result<String> {
        // Create SOAP request for PullMessages
        let soap_pull_request = self.create_pull_messages_request();

        Self::send_soap_request(self.pull_url.clone(), soap_pull_request)
    }

    pub fn is_there_onvif_motion_event(&self) -> io::Result<bool> {
        match self.pull_events() {
            Ok(response) => {
                log::debug!("Pull messages response: {}", response);
                if response.contains("<tt:SimpleItem Name=\"IsMotion\" Value=\"true\"/>") {
                    log::debug!("Motion detected");
                    Ok(true)
                } else if response.contains("Invalid username or password") {
                    println!("Invalid username or password for the IP camera!");
                    process::exit(0);
                } else if response.contains("Fault") {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Error: Unidentified resource.".to_string(),
                    ));
                } else {
                    return Ok(false);
                }
            }
            Err(e) => {
                log::debug!("Failed to send pull events request: {}", e);
                Err(e)
            }
        }
    }

    fn generate_nonce_bytes() -> Vec<u8> {
        //FIXME: use our own rand.
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..16).map(|_| rng.gen()).collect()
    }

    fn generate_password_digest(nonce_bytes: &[u8], created: String, password: String) -> String {
        //FIXME: use our own Sha
        let mut hasher = Sha1::new();
        hasher.update(nonce_bytes);
        hasher.update(created.as_bytes());
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        encode(result)
    }

    fn generate_nonce_created_digest(password: String) -> (String, String, String) {
        // Generate nonce
        let nonce_bytes = Self::generate_nonce_bytes();
        let nonce = encode(&nonce_bytes);
        // Generate timestamp in UTC
        let created = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        // Generate password digest
        let digest = Self::generate_password_digest(&nonce_bytes, created.clone(), password);

        (nonce, created, digest)
    }

    fn create_pull_point_subscription_request(
        username: String,
        password: String,
        url: String,
    ) -> String {
        let (nonce, created, digest) = Self::generate_nonce_created_digest(password);

        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
            <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <soap:Header>
                    <wsa5:Action>http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest</wsa5:Action>
                    <wsa5:MessageID>urn:uuid:unique</wsa5:MessageID>
                    <wsa5:To>{}</wsa5:To>
                    <wsse:Security soap:mustUnderstand="1">
                        <wsse:UsernameToken wsu:Id="UsernameToken-1">
                            <wsse:Username>{}</wsse:Username>
                            <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{}</wsse:Password>
                            <wsse:Nonce>{}</wsse:Nonce>
                            <wsu:Created>{}</wsu:Created>
                        </wsse:UsernameToken>
                    </wsse:Security>
                </soap:Header>
                <soap:Body>
                    <tev:CreatePullPointSubscription>
                        <tev:InitialTerminationTime>PT1H</tev:InitialTerminationTime>
                    </tev:CreatePullPointSubscription>
                </soap:Body>
            </soap:Envelope>"#,
            url, username, digest, nonce, created
        )
    }

    fn create_pull_messages_request(&self) -> String {
        let (nonce, created, digest) = Self::generate_nonce_created_digest(self.password.clone());

        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
            <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <soap:Header>
                    <wsa5:Action>http://www.onvif.org/ver10/events/wsdl/EventPortType/PullMessagesRequest</wsa5:Action>
                    <wsa5:MessageID>urn:uuid:unique</wsa5:MessageID>
                    <wsa5:To>{}</wsa5:To>
                    <wsse:Security soap:mustUnderstand="1">
                        <wsse:UsernameToken wsu:Id="UsernameToken-2">
                            <wsse:Username>{}</wsse:Username>
                            <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{}</wsse:Password>
                            <wsse:Nonce>{}</wsse:Nonce>
                            <wsu:Created>{}</wsu:Created>
                        </wsse:UsernameToken>
                    </wsse:Security>
                </soap:Header>
                <soap:Body>
                    <tev:PullMessages>
                        <tev:Timeout>PT0M</tev:Timeout>
                        <tev:MessageLimit>1000</tev:MessageLimit>
                    </tev:PullMessages>
                </soap:Body>
            </soap:Envelope>"#,
            self.pull_url, self.username, digest, nonce, created
        )
    }

    fn send_soap_request(url: String, soap_request: String) -> io::Result<String> {
        let client = Client::new();
        let res = client
            .post(url)
            .header("Content-Type", "application/soap+xml")
            .body(soap_request.to_string())
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("send() failed: {e}")))?;

        res.text()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("text() failed: {e}")))
    }

    fn parse_response(response: String) -> io::Result<Envelope> {
        let envelope: Envelope = from_str(&response).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to deserialize xml: {e}"),
            )
        })?;
        Ok(envelope)
    }

    pub fn record_motion_video(&self, dir: String, info: &VideoInfo) -> io::Result<()> {
        let rt = Runtime::new()?;

        let future = mp4::record(
            self.username.clone(),
            self.password.clone(),
            "rtsp://".to_owned() + &self.ip_addr + ":" + &self.rtsp_port,
            dir + "/" + &info.filename,
            20,
        );

        rt.block_on(future).unwrap();

        Ok(())
    }

    pub fn launch_livestream(&self, livestream_writer: LivestreamWriter) -> io::Result<()> {
        let username = self.username.clone();
        let password = self.password.clone();
        let ip_addr = self.ip_addr.clone();
        let rtsp_port = self.rtsp_port.clone();

        thread::spawn(move || {
            let rt = Runtime::new().unwrap();

            let future = fmp4::record(
                username,
                password,
                "rtsp://".to_owned() + &ip_addr + ":" + &rtsp_port,
                livestream_writer,
            );

            rt.block_on(future).unwrap();
        });

        Ok(())
    }
}
