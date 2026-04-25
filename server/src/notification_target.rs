//! Notification target delivery and allowlist helpers.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use reqwest::Url;
use secluso_server_backbone::types::{IosRelayBinding, NotificationTarget};
use std::{env, time::Duration};
use web_push_native::{p256, Auth, WebPushBuilder};

pub const UNIFIEDPUSH_ALLOWED_HOSTS_ENV: &str = "SECLUSO_UNIFIEDPUSH_ALLOWED_HOSTS";

// Hosted distributors we intentionally support out of the box. Self-hosted
// backends must be added explicitly via SECLUSO_UNIFIEDPUSH_ALLOWED_HOSTS.
const DEFAULT_ALLOWED_HOSTS: &[&str] = &[
    "ntfy.sh",
    "gotify1.unifiedpush.org",
    "push.services.mozilla.com",
    "updates.push.services.mozilla.com",
    "up.conversations.im",
    "fcm.googleapis.com",
];

// The public Secluso iOS relay and the review/testing relay are the only trusted iOS relays
const DEFAULT_IOS_RELAY_HOSTS: &[&str] = &["relay.secluso.com", "testing-relay.secluso.com"];

#[derive(Debug, Clone, PartialEq, Eq)]
struct AllowedEndpoint {
    host: String,
    port: Option<u16>,
}

#[derive(Debug, Clone, Default)]
pub struct UnifiedPushPolicy {
    allowed_endpoints: Vec<AllowedEndpoint>,
}

impl UnifiedPushPolicy {
    pub fn from_env() -> Result<Self> {
        let mut policy = Self::with_default_allowlist()?;
        let raw = env::var(UNIFIEDPUSH_ALLOWED_HOSTS_ENV).unwrap_or_default();
        policy.extend_from_allowlist_csv(&raw)?;
        Ok(policy)
    }

    #[cfg(test)]
    fn from_allowlist_csv(raw: &str) -> Result<Self> {
        let mut policy = Self::default();
        policy.extend_from_allowlist_csv(raw)?;
        Ok(policy)
    }

    fn with_default_allowlist() -> Result<Self> {
        let mut policy = Self::default();
        policy.extend_from_allowlist_csv(&DEFAULT_ALLOWED_HOSTS.join(","))?;
        Ok(policy)
    }

    fn extend_from_allowlist_csv(&mut self, raw: &str) -> Result<()> {
        for item in raw
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            let endpoint = parse_allowed_endpoint(item)?;
            if !self.allowed_endpoints.contains(&endpoint) {
                self.allowed_endpoints.push(endpoint);
            }
        }
        Ok(())
    }

    fn validate_endpoint_url(&self, raw_url: &str) -> Result<Url> {
        let parsed = Url::parse(raw_url)
            .with_context(|| format!("Invalid UnifiedPush endpoint URL: {raw_url}"))?;
        if parsed.scheme() != "https" {
            anyhow::bail!("Refusing non-HTTPS UnifiedPush endpoint URL: {raw_url}");
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            anyhow::bail!("UnifiedPush endpoint URL must not include credentials: {raw_url}");
        }
        if parsed.fragment().is_some() {
            anyhow::bail!("UnifiedPush endpoint URL must not include a fragment: {raw_url}");
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| {
                anyhow::anyhow!("UnifiedPush endpoint URL is missing a host: {raw_url}")
            })?
            .to_ascii_lowercase();
        let port = parsed.port_or_known_default().ok_or_else(|| {
            anyhow::anyhow!("UnifiedPush endpoint URL is missing an HTTPS port: {raw_url}")
        })?;

        let allowed = self.allowed_endpoints.iter().any(|candidate| {
            candidate.host == host
                && match candidate.port {
                    Some(allowed_port) => allowed_port == port,
                    None => port == 443,
                }
        });
        if !allowed {
            anyhow::bail!(
                "Refusing UnifiedPush endpoint host '{host}:{port}'. It is not in the built-in distributor allowlist and was not added via {UNIFIEDPUSH_ALLOWED_HOSTS_ENV}."
            );
        }

        Ok(parsed)
    }
}

fn parse_allowed_endpoint(raw: &str) -> Result<AllowedEndpoint> {
    if raw.contains("://") {
        anyhow::bail!(
            "Invalid {UNIFIEDPUSH_ALLOWED_HOSTS_ENV} entry '{raw}'. Use host or host:port, not a full URL."
        );
    }

    let parsed = Url::parse(&format!("https://{raw}"))
        .with_context(|| format!("Invalid {UNIFIEDPUSH_ALLOWED_HOSTS_ENV} entry '{raw}'"))?;
    if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
        anyhow::bail!(
            "Invalid {UNIFIEDPUSH_ALLOWED_HOSTS_ENV} entry '{raw}'. Only host or host:port is allowed."
        );
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!(
            "Invalid {UNIFIEDPUSH_ALLOWED_HOSTS_ENV} entry '{raw}'. Credentials are not allowed."
        );
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid {UNIFIEDPUSH_ALLOWED_HOSTS_ENV} entry '{raw}'"))?
        .to_ascii_lowercase();

    Ok(AllowedEndpoint {
        host,
        port: parsed.port(),
    })
}

/// Validate the configured iOS relay base URL before the server stores or re-serves it back to a hub.
/// The hub treats this URL as an outbound notification destination, so we enforce HTTPS only, no credentials, no query/fragment/path prefix, and one of the built-in relay hosts.
fn validate_ios_relay_base_url(raw_url: &str) -> Result<Url> {
    let parsed =
        Url::parse(raw_url).with_context(|| format!("Invalid iOS relay base URL: {raw_url}"))?;
    if parsed.scheme() != "https" {
        anyhow::bail!("Refusing non-HTTPS iOS relay base URL: {raw_url}");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("iOS relay base URL must not include credentials: {raw_url}");
    }
    if parsed.query().is_some() {
        anyhow::bail!("iOS relay base URL must not include a query: {raw_url}");
    }
    if parsed.fragment().is_some() {
        anyhow::bail!("iOS relay base URL must not include a fragment: {raw_url}");
    }
    if parsed.path() != "/" {
        anyhow::bail!("iOS relay base URL must not include a path prefix: {raw_url}");
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("iOS relay base URL is missing a host: {raw_url}"))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("iOS relay base URL is missing an HTTPS port: {raw_url}"))?;
    if port != 443 {
        anyhow::bail!("iOS relay base URL must use the default HTTPS port: {raw_url}");
    }
    if !DEFAULT_IOS_RELAY_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
    {
        anyhow::bail!("Refusing unexpected iOS relay host {host}");
    }

    Ok(parsed)
}

/// Validate that an iOS relay binding is complete enough to be usable and that its relay base URL still points at a trusted relay.
fn validate_ios_binding(binding: &IosRelayBinding) -> Result<()> {
    let relay_base = binding.relay_base_url.trim();
    if relay_base.is_empty() {
        anyhow::bail!("iOS relay base URL is required.");
    }
    validate_ios_relay_base_url(relay_base)?;

    if binding.hub_token.trim().is_empty()
        || binding.app_install_id.trim().is_empty()
        || binding.hub_id.trim().is_empty()
        || binding.device_token.trim().is_empty()
    {
        anyhow::bail!("iOS relay binding is incomplete.");
    }
    if binding.expires_at_epoch_ms == 0 {
        anyhow::bail!("iOS relay binding must include a non-zero expiration.");
    }

    Ok(())
}

/// Validate notification delivery metadata before persisting it or handing it back to the hub.
/// iOS targets are allowed to appear without a relay binding during the placeholder stage of pairing, but any supplied relay binding must still pass the trusted-relay checks above.
pub fn validate_notification_target(
    unifiedpush_policy: &UnifiedPushPolicy,
    target: &NotificationTarget,
) -> Result<()> {
    // Defer ios to the validate_ios_binding method
    if target.platform.eq_ignore_ascii_case("ios") {
        if let Some(binding) = target.ios_relay_binding.as_ref() {
            validate_ios_binding(binding)?;
        }
        return Ok(());
    }

    // If it doesn't match ios or android_unified, it doesn't belong here.
    if !target.platform.eq_ignore_ascii_case("android_unified") {
        return Ok(());
    }

    let endpoint_url = target
        .unifiedpush_endpoint_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("UnifiedPush endpoint URL is required."))?;
    let pub_key = target
        .unifiedpush_pub_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("UnifiedPush public key is required."))?;
    let auth = target
        .unifiedpush_auth
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("UnifiedPush auth secret is required."))?;

    unifiedpush_policy.validate_endpoint_url(endpoint_url)?;

    if pub_key.is_empty() || auth.is_empty() {
        anyhow::bail!("UnifiedPush key material is incomplete.");
    }

    Ok(())
}

pub async fn send_notification(
    policy: &UnifiedPushPolicy,
    endpoint_url: &str,
    pub_key: &str,
    auth: &str,
    payload: &[u8],
) -> Result<()> {
    let endpoint_url = policy.validate_endpoint_url(endpoint_url)?.to_string();
    let endpoint = endpoint_url
        .parse()
        .with_context(|| format!("Invalid UnifiedPush endpoint URI: {endpoint_url}"))?;
    let pub_key = Base64UrlUnpadded::decode_vec(pub_key)
        .context("UnifiedPush public key is not valid base64url")?;
    let ua_public = p256::PublicKey::from_sec1_bytes(&pub_key)
        .context("UnifiedPush public key is not a valid P-256 point")?;
    let auth = Base64UrlUnpadded::decode_vec(auth)
        .context("UnifiedPush auth secret is not valid base64url")?;
    let auth: [u8; 16] = auth
        .try_into()
        .map_err(|_| anyhow::anyhow!("UnifiedPush auth secret must decode to 16 bytes."))?;
    let ua_auth: Auth = auth.into();

    let request = WebPushBuilder::new(endpoint, ua_public, ua_auth)
        .with_valid_duration(Duration::from_secs(60))
        .build(payload.to_vec())
        .context("Failed to build UnifiedPush request")?;

    let request_url = request.uri().to_string();
    let method = reqwest::Method::from_bytes(request.method().as_str().as_bytes())
        .context("Failed to convert UnifiedPush HTTP method")?;
    let client = reqwest::Client::new();
    let mut request_builder = client.request(method, request_url);
    for (name, value) in request.headers() {
        request_builder = request_builder.header(name, value);
    }
    let response = request_builder
        .body(request.into_body())
        .send()
        .await
        .context("UnifiedPush request failed")?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read response body>".to_string());
        anyhow::bail!("UnifiedPush endpoint returned {}: {}", status, body);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_notification_target, UnifiedPushPolicy};
    use secluso_server_backbone::types::{IosRelayBinding, NotificationTarget};

    fn android_target(url: &str) -> NotificationTarget {
        NotificationTarget {
            platform: "android_unified".to_string(),
            ios_relay_binding: None,
            unifiedpush_endpoint_url: Some(url.to_string()),
            unifiedpush_pub_key: Some("pub".to_string()),
            unifiedpush_auth: Some("auth".to_string()),
        }
    }

    // A testing helper to build either the pairing-time placeholder iOS target or a fully bound iOS relay target depending on whether a relay base URL is supplied.
    fn ios_target(relay_base_url: Option<&str>) -> NotificationTarget {
        NotificationTarget {
            platform: "ios".to_string(),
            ios_relay_binding: relay_base_url.map(|relay_base_url| IosRelayBinding {
                relay_base_url: relay_base_url.to_string(),
                hub_token: "hub-token".to_string(),
                app_install_id: "install-id".to_string(),
                hub_id: "hub-id".to_string(),
                device_token: "device-token".to_string(),
                expires_at_epoch_ms: 1,
            }),
            unifiedpush_endpoint_url: None,
            unifiedpush_pub_key: None,
            unifiedpush_auth: None,
        }
    }

    #[test]
    fn rejects_endpoints_when_allowlist_is_missing() {
        let policy = UnifiedPushPolicy::default();
        let err =
            validate_notification_target(&policy, &android_target("https://up.example.com/push"))
                .unwrap_err()
                .to_string();
        assert!(err.contains("built-in distributor allowlist"));
    }

    #[test]
    fn accepts_allowlisted_default_https_host() {
        let policy = UnifiedPushPolicy::from_allowlist_csv("up.example.com").unwrap();
        validate_notification_target(
            &policy,
            &android_target("https://up.example.com/push/token"),
        )
        .unwrap();
    }

    #[test]
    fn rejects_unlisted_host() {
        let policy = UnifiedPushPolicy::from_allowlist_csv("up.example.com").unwrap();
        let err =
            validate_notification_target(&policy, &android_target("https://evil.example.net/push"))
                .unwrap_err()
                .to_string();
        assert!(err.contains("allowlist"));
    }

    #[test]
    fn rejects_non_default_port_unless_explicitly_allowlisted() {
        let policy = UnifiedPushPolicy::from_allowlist_csv("up.example.com").unwrap();
        let err = validate_notification_target(
            &policy,
            &android_target("https://up.example.com:8443/push"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("allowlist"));
    }

    #[test]
    fn accepts_explicit_allowlisted_port() {
        let policy = UnifiedPushPolicy::from_allowlist_csv("up.example.com:8443").unwrap();
        validate_notification_target(&policy, &android_target("https://up.example.com:8443/push"))
            .unwrap();
    }

    #[test]
    fn rejects_allowlist_entries_that_are_urls() {
        let err = UnifiedPushPolicy::from_allowlist_csv("https://up.example.com")
            .unwrap_err()
            .to_string();
        assert!(err.contains("host or host:port"));
    }

    #[test]
    fn built_in_ntfy_host_is_allowed() {
        let policy = UnifiedPushPolicy::with_default_allowlist().unwrap();
        validate_notification_target(&policy, &android_target("https://ntfy.sh/example-topic"))
            .unwrap();
    }

    #[test]
    fn built_in_gotify_host_is_allowed() {
        let policy = UnifiedPushPolicy::with_default_allowlist().unwrap();
        validate_notification_target(
            &policy,
            &android_target("https://gotify1.unifiedpush.org/message/example"),
        )
        .unwrap();
    }

    #[test]
    fn built_in_autopush_host_is_allowed() {
        let policy = UnifiedPushPolicy::with_default_allowlist().unwrap();
        validate_notification_target(
            &policy,
            &android_target("https://updates.push.services.mozilla.com/wpush/v1/example"),
        )
        .unwrap();
    }

    #[test]
    fn built_in_push_services_host_is_allowed() {
        let policy = UnifiedPushPolicy::with_default_allowlist().unwrap();
        validate_notification_target(
            &policy,
            &android_target("https://push.services.mozilla.com/wpush/v1/example"),
        )
        .unwrap();
    }

    #[test]
    fn built_in_conversations_proxy_host_is_allowed() {
        let policy = UnifiedPushPolicy::with_default_allowlist().unwrap();
        validate_notification_target(
            &policy,
            &android_target("https://up.conversations.im/push/example"),
        )
        .unwrap();
    }

    #[test]
    fn built_in_google_fcm_host_is_allowed() {
        let policy = UnifiedPushPolicy::with_default_allowlist().unwrap();
        validate_notification_target(
            &policy,
            &android_target("https://fcm.googleapis.com/fcm/send/example"),
        )
        .unwrap();
    }

    #[test]
    // Tests that the pairing-time placeholder target for iOS still passes when no relay binding has been attached yet.
    fn accepts_ios_placeholder_without_binding() {
        let policy = UnifiedPushPolicy::with_default_allowlist().unwrap();
        validate_notification_target(&policy, &ios_target(None))
            .expect("placeholder iOS target should be accepted without a relay binding");
    }

    #[test]
    // Tests that server-side iOS relay checks reject unexpected relay hosts before the target can be persisted to the hub.
    fn rejects_untrusted_ios_relay_host() {
        let policy = UnifiedPushPolicy::with_default_allowlist().unwrap();
        let err = validate_notification_target(&policy, &ios_target(Some("https://evil.example")))
            .expect_err("unexpected relay host should be rejected");

        assert!(err
            .to_string()
            .contains("Refusing unexpected iOS relay host"));
    }
}
