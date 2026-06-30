pub mod routes {
    use super::HttpMethod;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
    pub struct RouteSpec {
        pub method: HttpMethod,
        pub path: &'static str,
        pub params: &'static [&'static str],
    }

    const PARAM_NONE: &[&str] = &[];
    const PARAM_CAMERA: &[&str] = &["camera"];
    const PARAM_CAMERA_FILENAME: &[&str] = &["camera", "filename"];
    const PARAM_CAMERA_FILENAME_COUNTER: &[&str] = &["camera", "filename", "counter"];
    const PARAM_OP: &[&str] = &["op"];

    pub const ROUTE_PAIR: &str = "/pair";
    pub const ROUTE_UPLOAD: &str = "/<camera>/<filename>/<counter>";
    pub const ROUTE_BULK_CHECK: &str = "/bulkCheck";
    pub const ROUTE_RETRIEVE: &str = "/<camera>/<filename>";
    pub const ROUTE_DELETE_FILE: &str = "/<camera>/<filename>";
    pub const ROUTE_DELETE_CAMERA: &str = "/<camera>";
    pub const ROUTE_FCM_TOKEN: &str = "/fcm_token";
    pub const ROUTE_FCM_NOTIFICATION: &str = "/fcm_notification";
    pub const ROUTE_NOTIFICATION_TARGET: &str = "/notification_target";
    pub const ROUTE_LIVESTREAM_START: &str = "/livestream/<camera>";
    pub const ROUTE_LIVESTREAM_CHECK: &str = "/livestream/<camera>";
    pub const ROUTE_LIVESTREAM_UPLOAD: &str = "/livestream/<camera>/<filename>";
    pub const ROUTE_LIVESTREAM_RETRIEVE: &str = "/livestream/<camera>/<filename>";
    pub const ROUTE_LIVESTREAM_END: &str = "/livestream_end/<camera>";
    pub const ROUTE_CONFIG_COMMAND: &str = "/config/<camera>";
    pub const ROUTE_CONFIG_CHECK: &str = "/config/<camera>";
    pub const ROUTE_CONFIG_RESPONSE: &str = "/config_response/<camera>";
    pub const ROUTE_CONFIG_RESPONSE_RETRIEVE: &str = "/config_response/<camera>";
    pub const ROUTE_FCM_CONFIG: &str = "/fcm_config";
    pub const ROUTE_STATUS: &str = "/status";
    pub const ROUTE_DEBUG_LOGS: &str = "/debug_logs";
    pub const ROUTE_ADD_APP_CHECK: &str = "/add_app_check/<op>";
    pub const ROUTE_ADD_APP_REQUEST: &str = "/add_app_request/<op>";

    pub const BASE_ROUTES: &[RouteSpec] = &[
        RouteSpec {
            method: HttpMethod::Post,
            path: ROUTE_PAIR,
            params: PARAM_NONE,
        },
        RouteSpec {
            method: HttpMethod::Post,
            path: ROUTE_UPLOAD,
            params: PARAM_CAMERA_FILENAME_COUNTER,
        },
        RouteSpec {
            method: HttpMethod::Post,
            path: ROUTE_BULK_CHECK,
            params: PARAM_NONE,
        },
        RouteSpec {
            method: HttpMethod::Get,
            path: ROUTE_RETRIEVE,
            params: PARAM_CAMERA_FILENAME,
        },
        RouteSpec {
            method: HttpMethod::Delete,
            path: ROUTE_DELETE_FILE,
            params: PARAM_CAMERA_FILENAME,
        },
        RouteSpec {
            method: HttpMethod::Delete,
            path: ROUTE_DELETE_CAMERA,
            params: PARAM_CAMERA,
        },
        RouteSpec {
            method: HttpMethod::Post,
            path: ROUTE_FCM_TOKEN,
            params: PARAM_NONE,
        },
        RouteSpec {
            method: HttpMethod::Post,
            path: ROUTE_FCM_NOTIFICATION,
            params: PARAM_NONE,
        },
        RouteSpec {
            method: HttpMethod::Post,
            path: ROUTE_NOTIFICATION_TARGET,
            params: PARAM_NONE,
        },
        RouteSpec {
            method: HttpMethod::Get,
            path: ROUTE_NOTIFICATION_TARGET,
            params: PARAM_NONE,
        },
        RouteSpec {
            method: HttpMethod::Post,
            path: ROUTE_LIVESTREAM_START,
            params: PARAM_CAMERA,
        },
        RouteSpec {
            method: HttpMethod::Get,
            path: ROUTE_LIVESTREAM_CHECK,
            params: PARAM_CAMERA,
        },
        RouteSpec {
            method: HttpMethod::Post,
            path: ROUTE_LIVESTREAM_UPLOAD,
            params: PARAM_CAMERA_FILENAME,
        },
        RouteSpec {
            method: HttpMethod::Get,
            path: ROUTE_LIVESTREAM_RETRIEVE,
            params: PARAM_CAMERA_FILENAME,
        },
        RouteSpec {
            method: HttpMethod::Post,
            path: ROUTE_LIVESTREAM_END,
            params: PARAM_CAMERA,
        },
        RouteSpec {
            method: HttpMethod::Post,
            path: ROUTE_CONFIG_COMMAND,
            params: PARAM_CAMERA,
        },
        RouteSpec {
            method: HttpMethod::Get,
            path: ROUTE_CONFIG_CHECK,
            params: PARAM_CAMERA,
        },
        RouteSpec {
            method: HttpMethod::Post,
            path: ROUTE_CONFIG_RESPONSE,
            params: PARAM_CAMERA,
        },
        RouteSpec {
            method: HttpMethod::Get,
            path: ROUTE_CONFIG_RESPONSE_RETRIEVE,
            params: PARAM_CAMERA,
        },
        RouteSpec {
            method: HttpMethod::Get,
            path: ROUTE_FCM_CONFIG,
            params: PARAM_NONE,
        },
        RouteSpec {
            method: HttpMethod::Get,
            path: ROUTE_STATUS,
            params: PARAM_NONE,
        },
        RouteSpec {
            method: HttpMethod::Post,
            path: ROUTE_DEBUG_LOGS,
            params: PARAM_NONE,
        },
        RouteSpec {
            method: HttpMethod::Get,
            path: ROUTE_ADD_APP_CHECK,
            params: PARAM_OP,
        },
        RouteSpec {
            method: HttpMethod::Post,
            path: ROUTE_ADD_APP_REQUEST,
            params: PARAM_OP,
        },
    ];
}

pub mod types {
    use serde::{Deserialize, Serialize};
    use serde_json::Number;

    #[derive(Debug, Deserialize)]
    pub struct MotionPair {
        pub group_name: String,
        pub epoch_to_check: Number,
    }

    #[derive(Debug, Deserialize)]
    pub struct MotionPairs {
        pub group_names: Vec<MotionPair>,
    }

    #[derive(Debug, Serialize)]
    pub struct GroupTimestamp {
        pub group_name: String,
        pub timestamp: i64,
    }

    #[derive(Debug, Deserialize)]
    pub struct PairingRequest {
        pub pairing_token: String,
        pub role: String,
        #[serde(default)]
        pub notification_target: Option<NotificationTarget>,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct IosRelayBinding {
        pub relay_base_url: String,
        pub hub_token: String,
        pub app_install_id: String,
        pub hub_id: String,
        pub device_token: String,
        pub expires_at_epoch_ms: u64,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct NotificationTarget {
        pub platform: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ios_relay_binding: Option<IosRelayBinding>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub unifiedpush_endpoint_url: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub unifiedpush_pub_key: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub unifiedpush_auth: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct PairingResponse {
        pub status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub notification_target: Option<NotificationTarget>,
    }

    #[derive(Debug, Serialize)]
    pub struct ServerStatus {
        pub ok: bool,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ConfigResponse {
        pub api_key_ios: String,
        pub api_key_android: String,
        pub app_id_ios: String,
        pub app_id_android: String,
        pub messaging_sender_id: String,
        pub project_id: String,
        pub storage_bucket: String,
        pub bundle_id: String,
    }

    impl Default for ConfigResponse {
        fn default() -> Self {
            Self {
                api_key_ios: String::new(),
                api_key_android: String::new(),
                app_id_ios: String::new(),
                app_id_android: String::new(),
                messaging_sender_id: String::new(),
                project_id: String::new(),
                storage_bucket: String::new(),
                bundle_id: String::new(),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Delete,
    Put,
}
