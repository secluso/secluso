use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use secluso_client_server_lib::auth::{parse_user_credentials_any, parse_user_credentials_full, ServerBackend};
use secluso_client_lib::pairing::get_random_name;

/// Returns username, password, and server addr
/// Which delivery service for the provisioned credentials
pub fn read_credentials_backend() -> ServerBackend {
    let Ok(file) = File::open("credentials_full") else {
        return ServerBackend::SelfHosted;
    };
    let Ok(metadata) = file.metadata() else {
        return ServerBackend::SelfHosted;
    };
    let Ok(capacity) = metadata.len().try_into() else {
        return ServerBackend::SelfHosted;
    };

    let mut reader = BufReader::with_capacity(capacity, file);
    let Ok(data) = reader.fill_buf() else {
        return ServerBackend::SelfHosted;
    };

    parse_user_credentials_any(data.to_vec())
        .map(|credentials| credentials.backend)
        .unwrap_or(ServerBackend::SelfHosted)
}

pub fn read_parse_full_credentials() -> (String, String, String) {
    let file = File::open("credentials_full").expect("Could not open user_credentials file");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let data = reader.fill_buf().unwrap();

    let credentials_full_bytes = data.to_vec();

    let credentials = parse_user_credentials_any(credentials_full_bytes).unwrap();

    (
        credentials.username,
        credentials.password,
        credentials.server_addr,
    )
}

/// Utility function for outside the pairing module
pub fn get_names(
    state_dir: &str,
    first_time: bool,
    camera_filename: String,
    group_filename: String,
) -> anyhow::Result<(String, String)> {
    let state_dir_path = Path::new(&state_dir);
    let camera_path = state_dir_path.join(camera_filename);
    let group_path = state_dir_path.join(group_filename);

    let (camera_name, group_name) = if first_time {
        let cname = get_random_name();

        let mut file = File::create(camera_path).expect("Could not create file");
        file.write_all(cname.as_bytes())?;
        file.flush()?;
        file.sync_all()?;

        let gname = get_random_name();

        file = File::create(group_path).expect("Could not create file");
        file.write_all(gname.as_bytes())?;
        file.flush()?;
        file.sync_all()?;

        (cname, gname)
    } else {
        let file = File::open(camera_path).expect("Cannot open file to send");
        let mut reader =
            BufReader::with_capacity(usize::try_from(file.metadata()?.len())?, file);
        let cname = reader.fill_buf()?;

        let file = File::open(group_path).expect("Cannot open file to send");
        let mut reader =
            BufReader::with_capacity(usize::try_from(file.metadata()?.len())?, file);
        let gname = reader.fill_buf()?;

        (
            String::from_utf8(cname.to_vec())?,
            String::from_utf8(gname.to_vec())?,
        )
    };

    Ok((camera_name, group_name))
}

#[cfg(any(feature = "raspberry", feature = "test"))]
pub fn get_input_camera_secret() -> Vec<u8> {
    let pathname = match std::env::var("SECLUSO_USE_PROVISION").as_deref() {
        Ok("1") => "/provision/camera_secret",
        _ => "./camera_secret",
    };

    let file = File::open(pathname).expect(
        "Could not open file \"camera_secret\". You can generate this with the config_tool",
    );
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let data = reader.fill_buf().unwrap();

    data.to_vec()
}
