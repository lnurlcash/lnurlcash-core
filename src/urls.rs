//! Resolving user input to a URL, and deciding which URLs may be fetched.

use url::Url;

/// these hosts (plus .onion) resolve to http:// rather than https://
const INSECURE_HOSTS: [&str; 3] = ["127.0.0.1", "0.0.0.0", "localhost"];

fn is_insecure_host(host: &str) -> bool {
    INSECURE_HOSTS.contains(&host) || host.ends_with(".onion")
}

pub fn is_bech32_lnurl(data: &str) -> bool {
    data.trim().to_ascii_uppercase().starts_with("LNURL1")
}

pub fn to_bech32_lnurl(url: &str) -> Option<String> {
    use bech32::{ToBase32, Variant};
    bech32::encode("lnurl", url.as_bytes().to_base32(), Variant::Bech32)
        .ok()
        .map(|s| s.to_ascii_uppercase())
}

pub fn from_bech32_lnurl(data: &str) -> Option<String> {
    use bech32::FromBase32;
    let trimmed = data.trim();
    if !trimmed.to_ascii_uppercase().starts_with("LNURL1") {
        return None;
    }
    let (hrp, words, _variant) = bech32::decode(&trimmed.to_ascii_lowercase()).ok()?;
    if hrp != "lnurl" {
        return None;
    }
    let bytes = Vec::<u8>::from_base32(&words).ok()?;
    String::from_utf8(bytes).ok()
}

/// The one admission rule every URL must pass, whether it came from a scanned
/// or pasted note or from a SERVICE's own response (callback, verify,
/// payLink): https anywhere, http only for loopback and .onion.
///
/// Anything else - data:, file:, a bare http:// clearnet host - is rejected, so
/// a crafted note cannot answer its own informational GET (a data: URL
/// carrying withdrawRequest JSON would otherwise mint a self-contained fake
/// note), and a SERVICE cannot redirect a k1-bearing callback onto cleartext.
pub fn is_allowed_service_url(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => url.host_str().map(is_insecure_host).unwrap_or(false),
        _ => false,
    }
}

pub fn from_lud17(url: &str) -> String {
    let lowered = url.to_ascii_lowercase();
    let scheme_end = match ["lnurlw://", "lnurlp://", "lnurlc://", "keyauth://"]
        .iter()
        .find(|prefix| lowered.starts_with(**prefix))
    {
        Some(prefix) => prefix.len(),
        None => return url.to_string(),
    };
    let rest = &url[scheme_end..];
    let host = rest
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    let scheme = if is_insecure_host(&host.to_ascii_lowercase()) {
        "http"
    } else {
        "https"
    };
    format!("{scheme}://{rest}")
}

pub fn to_lud17w(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        format!("lnurlw://{rest}")
    } else if let Some(rest) = url.strip_prefix("http://") {
        format!("lnurlw://{rest}")
    } else {
        url.to_string()
    }
}

/// LUD-16. Strict: a host with no dot is not a domain name.
pub fn is_lightning_address(value: &str) -> bool {
    let trimmed = value.trim();
    let mut parts = trimmed.split('@');
    let (Some(name), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !name.is_empty()
        && !name.contains(char::is_whitespace)
        && !domain.is_empty()
        && !domain.contains(char::is_whitespace)
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

/// A local dev address, "mint@localhost:8000". LUD-16 has no notion of it -
/// [`is_lightning_address`] stays strict - but pointing a wallet at a mint
/// running on this machine is an ordinary thing to want, and the resolution
/// below already handles the port and the cleartext scheme such a host needs.
fn is_loopback_lightning_address(value: &str) -> bool {
    let trimmed = value.trim();
    let mut parts = trimmed.split('@');
    let (Some(name), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if name.is_empty() || domain.is_empty() {
        return false;
    }
    is_insecure_host(&domain.split(':').next().unwrap_or("").to_ascii_lowercase())
}

fn ln_address_to_url(address: &str) -> Option<String> {
    let trimmed = address.trim();
    let (name, domain) = trimmed.split_once('@')?;
    // the domain may carry a port (mint@127.0.0.1:8000) - the insecure-host
    // check is about the host part only
    let host = domain.split(':').next().unwrap_or("").to_ascii_lowercase();
    let scheme = if is_insecure_host(&host) {
        "http"
    } else {
        "https"
    };
    Some(format!("{scheme}://{domain}/.well-known/lnurlp/{name}"))
}

/// A bare mint domain with no local part. Assumes the "mint" username that
/// lnurl-mint itself defaults to, so a mint using a different one simply fails
/// to resolve and must be typed out in full.
fn is_bare_mint_domain(value: &str) -> bool {
    let trimmed = value.trim().trim_start_matches('@');
    if trimmed.is_empty() || trimmed.contains('@') || trimmed.contains('/') {
        return false;
    }
    if trimmed.contains(char::is_whitespace) {
        return false;
    }
    let host = trimmed.split(':').next().unwrap_or("");
    if host.contains('.') && !host.starts_with('.') && !host.ends_with('.') {
        return true;
    }
    is_insecure_host(&host.to_ascii_lowercase())
}

/// A bech32 LNURL, a Lightning Address, or a bare mint domain - all of which
/// point unambiguously at one payRequest.
pub fn resolve_mint_input(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if is_bech32_lnurl(trimmed) {
        let url = from_bech32_lnurl(trimmed)?;
        return is_allowed_service_url(&url).then_some(url);
    }
    if is_lightning_address(trimmed) || is_loopback_lightning_address(trimmed) {
        return ln_address_to_url(trimmed);
    }
    if is_bare_mint_domain(trimmed) {
        return ln_address_to_url(&format!("mint@{}", trimmed.trim_start_matches('@')));
    }
    None
}

/// Arbitrary LNURL-ish input down to a fetchable URL. Every URL-producing
/// branch passes [`is_allowed_service_url`], so a decoded or pasted URL can
/// never smuggle in a non-https scheme or cleartext http to a clearnet host.
pub fn resolve_lnurl_input(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if is_bech32_lnurl(trimmed) {
        let url = from_bech32_lnurl(trimmed)?;
        return is_allowed_service_url(&url).then_some(url);
    }
    let lowered = trimmed.to_ascii_lowercase();
    if ["lnurlw://", "lnurlp://", "lnurlc://", "keyauth://"]
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
    {
        let url = from_lud17(trimmed);
        return is_allowed_service_url(&url).then_some(url);
    }
    if is_lightning_address(trimmed) || is_loopback_lightning_address(trimmed) {
        return ln_address_to_url(trimmed);
    }
    if lowered.starts_with("http://") || lowered.starts_with("https://") {
        return is_allowed_service_url(trimmed).then(|| trimmed.to_string());
    }
    None
}

fn lnurlp_path_parts(pay_url: &str) -> Option<(Url, String, String)> {
    let url = Url::parse(pay_url).ok()?;
    let path = url.path().to_string();
    let marker = "/.well-known/lnurlp/";
    let index = path.rfind(marker)?;
    let prefix = path[..index + "/.well-known/".len()].to_string();
    let name = path[index + marker.len()..].to_string();
    if name.is_empty() || name.contains('/') {
        return None;
    }
    Some((url, prefix, name))
}

/// LUD-25 mint address (experimental): the withdraw-side mirror of a payRequest
/// URL. Derived from the resolved payRequest URL rather than guessed - `None`
/// for anything not at the conventional well-known path.
pub fn mint_address_url(pay_url: &str) -> Option<String> {
    let (url, prefix, name) = lnurlp_path_parts(pay_url)?;
    let origin = format!(
        "{}://{}",
        url.scheme(),
        url.host_str().map(|h| match url.port() {
            Some(port) => format!("{h}:{port}"),
            None => h.to_string(),
        })?
    );
    Some(format!("{origin}{prefix}lnurlw/{name}"))
}

pub fn lightning_address_username(pay_url: &str) -> Option<String> {
    lnurlp_path_parts(pay_url).map(|(_, _, name)| name)
}

pub fn server_of(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(port) => format!("{h}:{port}"),
                None => h.to_string(),
            })
        })
        .unwrap_or_else(|| url.to_string())
}
