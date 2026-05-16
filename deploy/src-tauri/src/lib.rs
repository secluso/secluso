//! SPDX-License-Identifier: GPL-3.0-or-later
// more tauri command info at https://tauri.app/develop/calling-rust/

mod pi_hub_provision;
mod provision_server;
mod release_config;
mod open_external;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            pi_hub_provision::prepare_image,
            pi_hub_provision::generate_user_credentials,
            open_external::open_external_url,
            release_config::get_deploy_version_status,
            provision_server::fetch_server_host_key,
            provision_server::test_server_ssh,
            provision_server::provision_server,
            provision_server::check_ssh_password_auth,
            provision_server::disable_ssh_password_auth,
            provision_server::default_ssh_key_path,
            provision_server::generate_ssh_keypair,
            provision_server::install_ssh_public_key,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
