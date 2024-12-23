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

//! Uses some code from the Retina example MP4 writer (https://github.com/scottlamb/retina).
//! MIT License.
//!
// Copyright (C) 2021 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proof-of-concept `.mp4` writer.
//!
//! This writes media data (`mdat`) to a stream, buffering parameters for a
//! `moov` atom at the end. This avoids the need to buffer the media data
//! (`mdat`) first or reserved a fixed size for the `moov`, but it will slow
//! playback, particularly when serving `.mp4` files remotely.
//!
//! For a more high-quality implementation, see [Moonfire NVR](https://github.com/scottlamb/moonfire-nvr).
//! It's better tested, places the `moov` atom at the start, can do HTTP range
//! serving for arbitrary time ranges, and supports standard and fragmented
//! `.mp4` files.
//!
//! See the BMFF spec, ISO/IEC 14496-12:2015:
//! https://github.com/scottlamb/moonfire-nvr/wiki/Standards-and-specifications
//! https://standards.iso.org/ittf/PubliclyAvailableStandards/c068960_ISO_IEC_14496-12_2015.zip

use crate::delivery_monitor::VideoInfo;
use crate::fmp4::Fmp4Writer;
use crate::livestream::LivestreamWriter;
use crate::mp4::Mp4Writer;
use crate::traits::{CodecParameters, Mp4};
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

use anyhow::{anyhow, bail, Context, Error};
use bytes::BytesMut;
use futures::StreamExt;
use log::info;
use retina::{
    client::SetupOptions,
    codec::{AudioParameters, CodecItem, ParametersRef, VideoParameters},
};
use url::Url;

use std::convert::TryFrom;
use std::num::NonZeroU32;
use std::sync::Arc;

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

        let future = Self::write_mp4(
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

            let future = Self::write_fmp4(
                username,
                password,
                "rtsp://".to_owned() + &ip_addr + ":" + &rtsp_port,
                livestream_writer,
            );

            rt.block_on(future).unwrap();
        });

        Ok(())
    }

    /// Writes the `.mp4`, including trying to finish or clean up the file.
    async fn write_mp4(
        username: String,
        password: String,
        url: String,
        filename: String,
        duration: u64,
    ) -> Result<(), Error> {
        let (session, video_params, audio_params) =
            Self::get_stream(username, password, url).await?;

        let mut session = session
            .play(
                retina::client::PlayOptions::default()
                    .initial_timestamp(retina::client::InitialTimestampPolicy::Default)
                    .enforce_timestamps_with_max_jump_secs(NonZeroU32::new(10).unwrap())
                    .unknown_rtcp_ssrc(retina::client::UnknownRtcpSsrcPolicy::Default),
            )
            .await?
            .demuxed()?;

        let out = tokio::fs::File::create(&filename).await?;
        let mut mp4 = Mp4Writer::new(
            IpCameraVideoParameters::new(video_params),
            IpCameraAudioParameters::new(audio_params),
            out,
        )
        .await?;
        Self::copy(&mut session, &mut mp4, Some(duration)).await?;
        mp4.finish().await?;

        // FIXME: do we need to wait for teardown here?
        // Session has now been dropped, on success or failure. A TEARDOWN should
        // be pending if necessary. session_group.await_teardown() will wait for it.
        //if let Err(e) = session_group.await_teardown().await {
        //    log::error!("TEARDOWN failed: {}", e);
        //}

        Ok(())
    }

    /// Streams fmp4 video.
    async fn write_fmp4(
        username: String,
        password: String,
        url: String,
        livestream_writer: LivestreamWriter,
    ) -> Result<(), Error> {
        let (session, video_params, audio_params) =
            Self::get_stream(username, password, url).await?;

        let mut session = session
            .play(
                retina::client::PlayOptions::default()
                    .initial_timestamp(retina::client::InitialTimestampPolicy::Default)
                    .enforce_timestamps_with_max_jump_secs(NonZeroU32::new(10).unwrap())
                    .unknown_rtcp_ssrc(retina::client::UnknownRtcpSsrcPolicy::Default),
            )
            .await?
            .demuxed()?;

        let mut fmp4 = Fmp4Writer::new(
            IpCameraVideoParameters::new(video_params),
            IpCameraAudioParameters::new(audio_params),
            livestream_writer,
        )
        .await?;
        fmp4.finish_header().await?;
        Self::copy(&mut session, &mut fmp4, None).await?;

        // FIXME: do we need to wait for teardown here?

        Ok(())
    }

    /// Copies packets from `session` to `mp4` without handling any cleanup on error.
    async fn copy<'a, M: Mp4>(
        session: &'a mut retina::client::Demuxed,
        mp4: &'a mut M,
        duration: Option<u64>,
    ) -> Result<(), Error> {
        let sleep = match duration {
            Some(secs) => futures::future::Either::Left(tokio::time::sleep(
                std::time::Duration::from_secs(secs),
            )),
            None => futures::future::Either::Right(futures::future::pending()),
        };
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                pkt = session.next() => {
                    match pkt.ok_or_else(|| anyhow!("EOF"))?? {
                        CodecItem::VideoFrame(f) => {
                            if f.is_random_access_point() {
                                if let Err(_e) = mp4.finish_fragment().await {
                                    // This will be executed when livestream ends.
                                    // This is a no op for recording an .mp4 file
                                    // log::error!(".mp4 finish failed: {}", e);
                                    break;
                                }
                            }
                            let start_ctx = *f.start_ctx();
                            mp4.video(f.data(), f.timestamp().timestamp().try_into().unwrap(), f.is_random_access_point()).await.with_context(
                                || format!("Error processing video frame starting with {start_ctx}"))?;
                        },
                        CodecItem::AudioFrame(f) => {
                            let ctx = *f.ctx();
                            mp4.audio(f.data(), f.timestamp().timestamp().try_into().unwrap()).await.with_context(
                                || format!("Error processing audio frame, {ctx}"))?;
                        },
                        CodecItem::Rtcp(rtcp) => {
                            if let (Some(_t), Some(Ok(Some(_sr)))) = (rtcp.rtp_timestamp(), rtcp.pkts().next().map(retina::rtcp::PacketRef::as_sender_report)) {
                            }
                        },
                        _ => continue,
                    };
                },
                _ = &mut sleep => {
                    info!("Stopping after {} seconds", duration.unwrap());
                    break;
                },
            }
        }
        Ok(())
    }

    /// Record an mp4 video file from the IP camera
    /// username: username of the IP camera
    /// passwword: password of the IP camera
    /// url: RTSP url of the IP camera
    /// filename: the name of the mp4 file to be used
    /// duration: the duration of the video, in seconds.
    async fn get_stream(
        username: String,
        password: String,
        url: String,
    ) -> Result<
        (
            retina::client::Session<retina::client::Described>,
            VideoParameters,
            AudioParameters,
        ),
        Error,
    > {
        let creds = retina::client::Credentials { username, password };
        let session_group = Arc::new(retina::client::SessionGroup::default());
        let url_parsed = Url::parse(&url)?;
        let mut session = retina::client::Session::describe(
            url_parsed,
            retina::client::SessionOptions::default()
                .creds(Some(creds))
                .session_group(session_group.clone())
                .teardown(retina::client::TeardownPolicy::Auto),
        )
        .await?;
        let video_stream_i = {
            let s = session.streams().iter().position(|s| {
                if s.media() == "video" {
                    if s.encoding_name() == "h264" || s.encoding_name() == "jpeg" {
                        log::info!("Starting to record using h264 video stream");
                        return true;
                    }
                    log::info!(
                        "Ignoring {} video stream because it's unsupported",
                        s.encoding_name(),
                    );
                }
                false
            });
            if s.is_none() {
                log::info!("No suitable video stream found");
            }
            s
        };
        if let Some(i) = video_stream_i {
            session
                .setup(
                    i,
                    SetupOptions::default().transport(retina::client::Transport::default()),
                )
                .await?;
        }
        let audio_stream = {
            let s = session
                .streams()
                .iter()
                .enumerate()
                .find_map(|(i, s)| match s.parameters() {
                    // Only consider audio streams that can produce a .mp4 sample
                    // entry.
                    Some(retina::codec::ParametersRef::Audio(a)) if a.mp4_sample_entry().build().is_ok() => {
                        log::info!("Using {} audio stream (rfc 6381 codec {})", s.encoding_name(), a.rfc6381_codec().unwrap());
                        Some((i, Box::new(a.clone())))
                    }
                    _ if s.media() == "audio" => {
                        log::info!("Ignoring {} audio stream because it can't be placed into a .mp4 file without transcoding", s.encoding_name());
                        None
                    }
                    _ => None,
                });
            if s.is_none() {
                log::info!("No suitable audio stream found");
            }
            s
        };
        if let Some((i, _)) = audio_stream {
            session
                .setup(
                    i,
                    SetupOptions::default().transport(retina::client::Transport::default()),
                )
                .await?;
        }
        if video_stream_i.is_none() && audio_stream.is_none() {
            bail!("Exiting because no video or audio stream was selected; see info log messages above");
        }

        //FIXME: what if there are multiple streams?
        //The frame will have the stream ID: e.g., let stream = &session.streams()[f.stream_id()];
        let video_stream = &session.streams()[video_stream_i.unwrap()];
        let video_params = match video_stream.parameters() {
            Some(ParametersRef::Video(params)) => params.clone(),
            _ => {
                bail!("Exiting because no video parameters were found");
            }
        };

        let audio_params = audio_stream.map(|(_i, p)| p).unwrap();

        Ok((session, video_params, *audio_params))
    }
}

struct IpCameraVideoParameters {
    parameters: VideoParameters,
}

impl IpCameraVideoParameters {
    pub fn new(parameters: VideoParameters) -> Self {
        Self { parameters }
    }
}

impl CodecParameters for IpCameraVideoParameters {
    fn write_codec_box(&self, buf: &mut BytesMut) {
        let e = self
            .parameters
            .mp4_sample_entry()
            .build()
            .map_err(|e| {
                anyhow!(
                    "unable to produce VisualSampleEntry for {} stream: {}",
                    self.parameters.rfc6381_codec(),
                    e,
                )
            })
            .unwrap();
        buf.extend_from_slice(&e);
    }

    // Not used
    fn get_clock_rate(&self) -> u32 {
        0
    }

    fn get_dimensions(&self) -> (u32, u32) {
        let dims = self.parameters.pixel_dimensions();
        let width = u32::from(u16::try_from(dims.0).unwrap()) << 16;
        let height = u32::from(u16::try_from(dims.1).unwrap()) << 16;

        (width, height)
    }
}

struct IpCameraAudioParameters {
    parameters: AudioParameters,
}

impl IpCameraAudioParameters {
    pub fn new(parameters: AudioParameters) -> Self {
        Self { parameters }
    }
}

impl CodecParameters for IpCameraAudioParameters {
    fn write_codec_box(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(
            &self
                .parameters
                .mp4_sample_entry()
                .build()
                .expect("all added streams have sample entries"),
        );
    }

    fn get_clock_rate(&self) -> u32 {
        self.parameters.clock_rate()
    }

    // Not applicable to audio
    fn get_dimensions(&self) -> (u32, u32) {
        (0, 0)
    }
}
