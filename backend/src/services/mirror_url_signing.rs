//! Stateless, time-limited signatures for Terraform/OpenTofu provider
//! network-mirror archive URLs.
//!
//! The provider network mirror protocol splits one install across two kinds of
//! request, and only the first carries the client's credential:
//!
//! ```text
//! GET <base>/<hostname>/<ns>/<type>/index.json     Authorization: Bearer ...
//! GET <base>/<hostname>/<ns>/<type>/<version>.json Authorization: Bearer ...
//! GET <the `url` from that document>               (no credentials, ever)
//! ```
//!
//! That last request is anonymous by design, not by omission. The archive URL
//! is chosen by the mirror and may point at any host, so a client that
//! attached its mirror token to it would hand that token to whatever host the
//! metadata response named. Both engines therefore refuse to: OpenTofu builds
//! the archive request from a bare
//! [`PackageHTTPURL`](https://github.com/opentofu/opentofu/blob/main/internal/getproviders/http_mirror_source.go)
//! with no credential plumbed into it, and Terraform's `PackageHTTPURL` is a
//! plain `string`. The spec spells out the consequence for servers:
//!
//! > OpenTofu does _not_ send credentials when retrieving the archives whose
//! > URLs are given in the "List Available Installation Packages" response
//! > below. If a particular mirror considers the distribution packages
//! > themselves to be sensitive then it must use cryptographically-secure,
//! > user-specific, and time-limited URLs in the metadata response.
//! >
//! > — <https://opentofu.org/docs/internals/provider-network-mirror-protocol/>
//!
//! So a private (`is_public = false`) mirror repository cannot be served to
//! `tofu init` at all unless the archive URL itself carries the authorization:
//! the metadata requests authenticate, the archive request 401s, and the
//! install dies partway through. This module supplies the three properties the
//! spec asks for, as a query string appended to the archive URL:
//!
//! * **cryptographically-secure** — an HMAC-SHA256 over the exact request path
//!   plus the two claims, keyed by material derived from the server's
//!   `jwt_secret` under a domain separator, verified in constant time.
//! * **user-specific** — the signature commits to the `user_id` of the
//!   principal that authenticated the *metadata* request, and verification
//!   resolves that user (and re-checks that they are still active) rather than
//!   granting some ambient identity.
//! * **time-limited** — an absolute expiry, checked on every verification.
//!
//! Unlike a [download ticket](crate::services::auth_config_service), these
//! signatures are stateless and replayable until they expire. Both differences
//! are deliberate: a `<version>.json` document is a *plan* to fetch archives
//! that a client may execute for several platforms, minutes later, and
//! retry — `tofu init` retries an archive fetch on a 5xx — so a single-use
//! row per archive would burn on the first retry and a 30-second TTL would
//! expire mid-install. The cost is that a leaked URL is usable by anyone
//! holding it until it expires, which is exactly the trade the spec's
//! "time-limited" wording contemplates.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Query parameter carrying the absolute expiry, as unix seconds.
pub const EXP_PARAM: &str = "ak_exp";
/// Query parameter carrying the minting principal's user id.
pub const SUB_PARAM: &str = "ak_sub";
/// Query parameter carrying the hex-encoded HMAC-SHA256 signature.
pub const SIG_PARAM: &str = "ak_sig";

/// Domain separator mixed into the derived key. Keeps a signature minted here
/// from being verifiable by — or forgeable from — any other `jwt_secret`
/// consumer, so this feature cannot become a way to mint JWTs and vice versa.
const KEY_DOMAIN: &[u8] = b"artifact-keeper/terraform-mirror-archive-url/v1";

/// Claims recovered from a verified signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedArchiveClaims {
    /// The principal whose authenticated metadata request minted this URL.
    pub user_id: Uuid,
    /// Absolute expiry, unix seconds.
    pub expires_at_unix: i64,
}

/// Derive the signing key from the server secret under [`KEY_DOMAIN`].
fn derive_key(server_secret: &str) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(server_secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(KEY_DOMAIN);
    mac.finalize().into_bytes().into()
}

/// Feed one field into the MAC, length-prefixed.
///
/// Without the length prefix the concatenation is ambiguous: a path ending in
/// digits and a shorter path with a longer expiry could produce the same byte
/// stream, and the signature would transfer between them.
fn absorb(mac: &mut HmacSha256, field: &[u8]) {
    mac.update(&(field.len() as u64).to_be_bytes());
    mac.update(field);
}

fn raw_signature(server_secret: &str, path: &str, user_id: Uuid, exp_unix: i64) -> Vec<u8> {
    let key = derive_key(server_secret);
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
    absorb(&mut mac, path.as_bytes());
    absorb(&mut mac, user_id.as_bytes());
    absorb(&mut mac, exp_unix.to_string().as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Render the query string that authorizes `path` until `exp_unix`.
///
/// `path` must be the absolute request path the client will fetch, exactly as
/// it will appear on the wire (the mirror archive route). Verification compares
/// against `Uri::path()` byte for byte, so the caller must not sign a decoded
/// or otherwise normalized variant of what it emits.
pub fn signed_query(server_secret: &str, path: &str, user_id: Uuid, exp_unix: i64) -> String {
    format!(
        "{}={}&{}={}&{}={}",
        EXP_PARAM,
        exp_unix,
        SUB_PARAM,
        user_id,
        SIG_PARAM,
        hex::encode(raw_signature(server_secret, path, user_id, exp_unix)),
    )
}

/// Look up one query parameter without pulling in a URL parser.
///
/// Every value this module emits is `[0-9a-f-]` or decimal digits, so there is
/// nothing to percent-decode; anything a client mangles in transit simply
/// fails to verify.
fn query_param<'q>(query: &'q str, name: &str) -> Option<&'q str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then_some(v)
    })
}

/// Verify a signed archive URL.
///
/// Returns the claims when the signature is valid for exactly this path and
/// has not expired, and `None` for every failure mode — absent, malformed,
/// tampered, or expired — so callers cannot accidentally distinguish them.
pub fn verify(
    server_secret: &str,
    path: &str,
    query: Option<&str>,
    now_unix: i64,
) -> Option<SignedArchiveClaims> {
    let query = query?;
    let exp: i64 = query_param(query, EXP_PARAM)?.parse().ok()?;
    let user_id: Uuid = query_param(query, SUB_PARAM)?.parse().ok()?;
    let provided = hex::decode(query_param(query, SIG_PARAM)?).ok()?;

    // Expiry first: an expired signature is not worth a MAC computation, and
    // checking it before the comparison keeps the "expired" and "forged" paths
    // indistinguishable to a caller timing us.
    if now_unix > exp {
        return None;
    }

    let key = derive_key(server_secret);
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
    absorb(&mut mac, path.as_bytes());
    absorb(&mut mac, user_id.as_bytes());
    absorb(&mut mac, exp.to_string().as_bytes());
    // `verify_slice` is constant-time and length-checked.
    mac.verify_slice(&provided).ok()?;

    Some(SignedArchiveClaims {
        user_id,
        expires_at_unix: exp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-key-that-is-at-least-32-bytes";
    const PATH: &str =
        "/terraform/tofu-mirror/registry.opentofu.org/hashicorp/aws/6.2.0/download/linux/amd64";

    fn user() -> Uuid {
        Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap()
    }

    #[test]
    fn round_trips_within_the_validity_window() {
        let q = signed_query(SECRET, PATH, user(), 1_800_000_100);
        let claims = verify(SECRET, PATH, Some(&q), 1_800_000_000).expect("valid signature");
        assert_eq!(claims.user_id, user());
        assert_eq!(claims.expires_at_unix, 1_800_000_100);
    }

    #[test]
    fn rejects_after_expiry() {
        let q = signed_query(SECRET, PATH, user(), 1_800_000_100);
        assert!(verify(SECRET, PATH, Some(&q), 1_800_000_101).is_none());
        // The boundary second is still inside the window.
        assert!(verify(SECRET, PATH, Some(&q), 1_800_000_100).is_some());
    }

    #[test]
    fn does_not_transfer_to_another_path() {
        // The whole point of binding the path: a signature minted for one
        // provider archive must not authorize a different repository's.
        let q = signed_query(SECRET, PATH, user(), 1_800_000_100);
        let other = "/terraform/private-repo/registry.opentofu.org/hashicorp/aws/6.2.0/download/linux/amd64";
        assert!(verify(SECRET, other, Some(&q), 1_800_000_000).is_none());
    }

    #[test]
    fn rejects_a_tampered_expiry_or_subject() {
        let q = signed_query(SECRET, PATH, user(), 1_800_000_100);
        let extended = q.replace("1800000100", "1900000000");
        assert!(verify(SECRET, PATH, Some(&extended), 1_800_000_000).is_none());

        let swapped = q.replace(&user().to_string(), "99999999-8888-7777-6666-555555555555");
        assert!(verify(SECRET, PATH, Some(&swapped), 1_800_000_000).is_none());
    }

    #[test]
    fn rejects_a_signature_from_a_different_server_secret() {
        let q = signed_query(
            "some-other-secret-of-sufficient-length",
            PATH,
            user(),
            1_800_000_100,
        );
        assert!(verify(SECRET, PATH, Some(&q), 1_800_000_000).is_none());
    }

    #[test]
    fn length_prefixing_prevents_field_shifting() {
        // Same concatenated bytes, different fields: without length prefixes
        // `path="…/1" exp=800000100` and `path="…/" exp=1800000100` would MAC
        // identically. Assert the two disagree.
        let a = signed_query(SECRET, "/terraform/r/h/n/t/1", user(), 800_000_100);
        let b = signed_query(SECRET, "/terraform/r/h/n/t/", user(), 1_800_000_100);
        let sig_a = query_param(&a, SIG_PARAM).unwrap();
        let sig_b = query_param(&b, SIG_PARAM).unwrap();
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn rejects_absent_or_malformed_query() {
        assert!(verify(SECRET, PATH, None, 1_800_000_000).is_none());
        assert!(verify(SECRET, PATH, Some(""), 1_800_000_000).is_none());
        assert!(verify(SECRET, PATH, Some("ak_exp=nope&ak_sub=x&ak_sig=zz"), 1).is_none());
        let q = signed_query(SECRET, PATH, user(), 1_800_000_100);
        let truncated = q
            .rsplit_once('=')
            .map(|(k, v)| format!("{}={}", k, &v[..8]))
            .unwrap();
        assert!(verify(SECRET, PATH, Some(&truncated), 1_800_000_000).is_none());
    }
}
