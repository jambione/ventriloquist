//! OS proxy resolution for the relay transport (SPEC_V3 §6).
//!
//! The *decision layer* is pure and unit-tested: parsing of PAC results and
//! WinHTTP proxy lists, bypass lists (`NO_PROXY`, WinHTTP `<local>` and
//! wildcards) and the order of precedence
//!
//! 1. `HTTPS_PROXY` / `ALL_PROXY` (and lower-case) from the environment,
//!    filtered by `NO_PROXY`;
//! 2. the OS ([`OsProxyResolver`]): Windows
//!    `WinHttpGetIEProxyConfigForCurrentUser` + `WinHttpGetProxyForUrl` (WPAD
//!    auto-detect and PAC URLs); macOS `CFNetworkCopySystemProxySettings` +
//!    `CFNetworkCopyProxiesForURL`, and for a PAC script
//!    `CFNetworkCopyProxiesForAutoConfigurationScript`;
//! 3. direct.
//!
//! Evaluating a PAC script is delegated to the OS API, never done here.
//! Only HTTP CONNECT proxies are used (`PROXY` / `HTTPS` entries); `SOCKS`
//! entries are skipped. Proxy credentials come only from an `HTTPS_PROXY`
//! URL (`http://user:pass@host:port`, Basic); NTLM/Kerberos challenges
//! (HTTP 407) are reported as `proxy_auth_required`, not answered.

use std::fmt;

use url::Url;

/// One way to reach the relay.
#[derive(Clone, PartialEq, Eq)]
pub enum ProxyEntry {
    /// Connect straight to the relay.
    Direct,
    /// Tunnel through an HTTP proxy with `CONNECT`.
    Http {
        /// Proxy host.
        host: String,
        /// Proxy port.
        port: u16,
        /// Basic credentials (from the environment variable only).
        auth: Option<(String, String)>,
    },
}

impl fmt::Debug for ProxyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => f.write_str("Direct"),
            Self::Http { host, port, auth } => {
                write!(f, "Http({host}:{port}{})", if auth.is_some() { ", auth" } else { "" })
            }
        }
    }
}

impl ProxyEntry {
    /// `http://host:port` for reqwest (credentials included when present).
    pub fn to_url(&self) -> Option<String> {
        match self {
            Self::Direct => None,
            Self::Http { host, port, auth } => {
                let host = if host.contains(':') { format!("[{host}]") } else { host.clone() };
                Some(match auth {
                    Some((u, p)) => {
                        let enc = |s: &str| {
                            percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC)
                                .to_string()
                        };
                        format!("http://{}:{}@{host}:{port}", enc(u), enc(p))
                    }
                    None => format!("http://{host}:{port}"),
                })
            }
        }
    }
}

/// Source of the OS proxy settings. Blocking (it may fetch a PAC script or
/// run WPAD); call it from `spawn_blocking`.
pub trait OsProxyResolver: Send + Sync + 'static {
    /// The proxies to try for `url`, in order. Empty means "no information"
    /// and is treated like direct.
    fn resolve(&self, url: &Url) -> Vec<ProxyEntry>;
}

/// An [`OsProxyResolver`] that always says direct (tests, other platforms).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOsProxy;

impl OsProxyResolver for NoOsProxy {
    fn resolve(&self, _url: &Url) -> Vec<ProxyEntry> {
        Vec::new()
    }
}

/// The resolver of this platform (macOS CFNetwork, Windows WinHTTP);
/// elsewhere it knows nothing and only the environment applies.
pub fn system_resolver() -> Box<dyn OsProxyResolver> {
    #[cfg(target_os = "macos")]
    {
        Box::new(sys::SystemProxy::default())
    }
    #[cfg(windows)]
    {
        Box::new(sys::SystemProxy)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Box::new(NoOsProxy)
    }
}

// ------------------------------------------------------------ pure logic

/// Parse `host:port`, `http://host:port`, `https://host:port` or
/// `http://user:pass@host:port` (a bare host defaults to port 8080).
pub fn parse_proxy_uri(s: &str) -> Option<ProxyEntry> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let has_scheme = s.contains("://");
    let with_scheme = if has_scheme { s.to_owned() } else { format!("http://{s}") };
    let u = Url::parse(&with_scheme).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None; // socks5://… and friends are not supported
    }
    let host = u.host_str()?.trim_matches(['[', ']']).to_owned();
    // `Url::port` drops a port equal to the scheme's default (`a:80`), so
    // read the explicit port from the text.
    let port = explicit_port(s).unwrap_or(if has_scheme { u.port_or_known_default().unwrap_or(8080) } else { 8080 });
    let auth = (!u.username().is_empty()).then(|| {
        let dec = |x: &str| percent_encoding::percent_decode_str(x).decode_utf8_lossy().into_owned();
        (dec(u.username()), dec(u.password().unwrap_or("")))
    });
    Some(ProxyEntry::Http { host, port, auth })
}

/// The `:port` written in a proxy string (`[scheme://][user@]host[:port][/…]`).
fn explicit_port(s: &str) -> Option<u16> {
    let rest = s.split_once("://").map_or(s, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let port = if let Some(end) = hostport.strip_prefix('[').and_then(|h| h.split_once("]:")) {
        end.1
    } else if hostport.starts_with('[') {
        return None;
    } else {
        hostport.rsplit_once(':')?.1
    };
    port.parse().ok()
}

/// Parse a PAC result such as `PROXY a:80; PROXY b:8080; DIRECT`
/// (`HTTP`/`HTTPS` are accepted like `PROXY`; `SOCKS*` entries are skipped).
pub fn parse_pac_result(s: &str) -> Vec<ProxyEntry> {
    let mut out = Vec::new();
    for item in s.split(';') {
        let item = item.trim();
        let mut it = item.splitn(2, char::is_whitespace);
        let kind = it.next().unwrap_or("").to_ascii_uppercase();
        let arg = it.next().unwrap_or("").trim();
        match kind.as_str() {
            "DIRECT" => out.push(ProxyEntry::Direct),
            "PROXY" | "HTTP" | "HTTPS" => {
                if let Some(e) = parse_proxy_uri(arg) {
                    out.push(e);
                }
            }
            _ => {}
        }
    }
    out
}

/// Parse a WinHTTP/WinINet proxy list for `scheme` (`https` for the relay):
/// either `host:port[;host2:port]` for every scheme, or
/// `http=a:80;https=b:81;socks=c:1080` (only entries named after the scheme
/// apply). Entries are separated by `;` or whitespace.
pub fn parse_winhttp_proxy_list(list: &str, scheme: &str) -> Vec<ProxyEntry> {
    let mut scoped = Vec::new();
    let mut plain = Vec::new();
    for item in list.split(|c: char| c == ';' || c.is_whitespace()).filter(|i| !i.is_empty()) {
        let (key, val) = match item.split_once('=') {
            Some((k, v)) => (Some(k.to_ascii_lowercase()), v),
            None => (None, item),
        };
        let Some(entry) = parse_proxy_uri(val) else { continue };
        match key {
            Some(k) if k == scheme => scoped.push(entry),
            Some(_) => {}
            None => plain.push(entry),
        }
    }
    if scoped.is_empty() {
        plain
    } else {
        scoped
    }
}

/// Whether `host` matches a bypass list. Handles both `NO_PROXY`
/// (`localhost,.corp.example,10.0.0.1`) and the WinHTTP form
/// (`*.corp.example;10.*;<local>`): entries are separated by `,`, `;` or
/// whitespace; `*` matches everything; `<local>` matches names without a
/// dot; a leading `.` or `*.` matches the domain and its subdomains; other
/// `*` are wildcards; matching is case-insensitive and ignores any port.
/// CIDR ranges are not supported.
pub fn bypassed(host: &str, list: &str) -> bool {
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    list.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .any(|e| {
            if e == "*" {
                return true;
            }
            if e == "<local>" {
                return !host.contains('.') && !host.contains(':');
            }
            // Strip a trailing :port (but not from a bare IPv6 address).
            let e = match e.rsplit_once(':') {
                Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') => h.to_owned(),
                _ => e,
            };
            let domain = e.strip_prefix("*.").or_else(|| e.strip_prefix('.'));
            if let Some(d) = domain {
                if !d.contains('*') {
                    return host == d || host.ends_with(&format!(".{d}"));
                }
            }
            if e.contains('*') {
                return wildcard_match(&e, &host);
            }
            host == e
        })
}

/// `*` matches any run of characters; everything else is literal.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if parts.len() == 1 {
        return pattern == text;
    }
    if !text.starts_with(first) || !text.ends_with(last) || text.len() < first.len() + last.len() {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(pos) => rest = &rest[pos + mid.len()..],
            None => return false,
        }
    }
    true
}

/// The environment's verdict for `url`: `Some(entries)` when `HTTPS_PROXY` /
/// `ALL_PROXY` (or `NO_PROXY`) decide, `None` to ask the OS.
pub fn env_decision(env: &dyn Fn(&str) -> Option<String>, url: &Url) -> Option<Vec<ProxyEntry>> {
    let get = |upper: &str| {
        env(upper)
            .or_else(|| env(&upper.to_ascii_lowercase()))
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    let host = url.host_str().unwrap_or("");
    let no_proxy = get("NO_PROXY");
    if no_proxy.as_deref().is_some_and(|l| bypassed(host, l)) {
        return Some(vec![ProxyEntry::Direct]);
    }
    let proxy = if matches!(url.scheme(), "https" | "wss") {
        get("HTTPS_PROXY").or_else(|| get("ALL_PROXY"))
    } else {
        get("HTTP_PROXY").or_else(|| get("ALL_PROXY"))
    };
    proxy.and_then(|p| parse_proxy_uri(&p)).map(|e| vec![e])
}

/// The proxies to try for `url`, in order: environment, then the OS, then
/// direct. Never empty.
pub fn resolve_proxies(
    env: &dyn Fn(&str) -> Option<String>,
    os: &dyn OsProxyResolver,
    url: &Url,
) -> Vec<ProxyEntry> {
    if let Some(v) = env_decision(env, url) {
        return v;
    }
    let v = os.resolve(url);
    if v.is_empty() {
        vec![ProxyEntry::Direct]
    } else {
        v
    }
}

// -------------------------------------------------------- OS bindings

#[cfg(any(windows, target_os = "macos"))]
#[allow(unsafe_code)]
mod sys {
    #[cfg(target_os = "macos")]
    pub use self::mac::SystemProxy;
    #[cfg(windows)]
    pub use self::win::SystemProxy;

    #[cfg(target_os = "macos")]
    mod mac {
        use std::sync::Mutex;
        use std::time::{Duration, Instant};

        use core_foundation::array::CFArray;
        use core_foundation::base::{CFType, TCFType};
        use core_foundation::dictionary::CFDictionary;
        use core_foundation::error::CFError;
        use core_foundation::number::CFNumber;
        use core_foundation::string::CFString;
        use core_foundation::url::CFURL;
        use core_foundation_sys::array::CFArrayRef;
        use core_foundation_sys::base::{CFRelease, CFTypeRef};
        use core_foundation_sys::dictionary::CFDictionaryRef;
        use core_foundation_sys::error::CFErrorRef;
        use core_foundation_sys::string::CFStringRef;
        use core_foundation_sys::url::CFURLRef;
        use url::Url;

        use super::super::{OsProxyResolver, ProxyEntry};

        #[link(name = "CFNetwork", kind = "framework")]
        extern "C" {
            fn CFNetworkCopySystemProxySettings() -> CFDictionaryRef;
            fn CFNetworkCopyProxiesForURL(url: CFURLRef, settings: CFDictionaryRef) -> CFArrayRef;
            fn CFNetworkCopyProxiesForAutoConfigurationScript(
                script: CFStringRef,
                url: CFURLRef,
                error: *mut CFErrorRef,
            ) -> CFArrayRef;
            static kCFProxyTypeKey: CFStringRef;
            static kCFProxyHostNameKey: CFStringRef;
            static kCFProxyPortNumberKey: CFStringRef;
            static kCFProxyAutoConfigurationURLKey: CFStringRef;
            static kCFProxyAutoConfigurationJavaScriptKey: CFStringRef;
            static kCFProxyTypeNone: CFStringRef;
            static kCFProxyTypeHTTP: CFStringRef;
            static kCFProxyTypeHTTPS: CFStringRef;
            static kCFProxyTypeAutoConfigurationURL: CFStringRef;
            static kCFProxyTypeAutoConfigurationJavaScript: CFStringRef;
        }

        const PAC_CACHE: Duration = Duration::from_secs(300);
        const PAC_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
        const PAC_MAX_BYTES: usize = 1 << 20;

        /// macOS: CFNetwork (system proxy settings; PAC scripts are run by CFNetwork).
        #[derive(Default)]
        pub struct SystemProxy {
            pac: Mutex<Option<(String, String, Instant)>>,
        }

        fn cfs(r: CFStringRef) -> CFString {
            // SAFETY: the constants are valid, immortal CFStrings.
            unsafe { CFString::wrap_under_get_rule(r) }
        }

        fn dict_string(d: &CFDictionary<CFString, CFType>, key: CFStringRef) -> Option<String> {
            let v = d.find(cfs(key))?;
            v.downcast::<CFString>().map(|x| x.to_string())
        }

        /// One element of a CFNetwork proxy array.
        enum Item {
            Entry(ProxyEntry),
            PacUrl(String),
            PacScript(String),
        }

        fn items(array: CFArray<CFType>) -> Vec<Item> {
            let mut out = Vec::new();
            for v in array.iter() {
                let Some(d) = v.downcast::<CFDictionary>() else { continue };
                // SAFETY: CFNetwork proxy dictionaries map CFString keys to CFTypes.
                let d: CFDictionary<CFString, CFType> =
                    unsafe { CFDictionary::wrap_under_get_rule(d.as_concrete_TypeRef()) };
                // SAFETY: the extern statics are valid immortal CFStrings.
                unsafe {
                    let Some(kind) = dict_string(&d, kCFProxyTypeKey) else { continue };
                    let is = |c: CFStringRef| kind == cfs(c);
                    if is(kCFProxyTypeNone) {
                        out.push(Item::Entry(ProxyEntry::Direct));
                    } else if is(kCFProxyTypeHTTP) || is(kCFProxyTypeHTTPS) {
                        let host = dict_string(&d, kCFProxyHostNameKey);
                        let port = d
                            .find(cfs(kCFProxyPortNumberKey))
                            .and_then(|n| n.downcast::<CFNumber>())
                            .and_then(|n| n.to_i32())
                            .and_then(|n| u16::try_from(n).ok());
                        if let (Some(host), Some(port)) = (host, port) {
                            out.push(Item::Entry(ProxyEntry::Http { host, port, auth: None }));
                        }
                    } else if is(kCFProxyTypeAutoConfigurationURL) {
                        if let Some(u) = dict_string(&d, kCFProxyAutoConfigurationURLKey) {
                            out.push(Item::PacUrl(u));
                        }
                    } else if is(kCFProxyTypeAutoConfigurationJavaScript) {
                        if let Some(u) = dict_string(&d, kCFProxyAutoConfigurationJavaScriptKey) {
                            out.push(Item::PacScript(u));
                        }
                    }
                    // SOCKS and FTP entries are skipped.
                }
            }
            out
        }

        impl SystemProxy {
            fn fetch_pac(&self, pac_url: &str) -> Option<String> {
                {
                    let g = self.pac.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some((u, script, at)) = g.as_ref() {
                        if u == pac_url && at.elapsed() < PAC_CACHE {
                            return Some(script.clone());
                        }
                    }
                }
                // Like a browser, the PAC file itself is fetched without a proxy.
                let client = reqwest::blocking::Client::builder()
                    .no_proxy()
                    .timeout(PAC_FETCH_TIMEOUT)
                    .build()
                    .ok()?;
                let resp = client.get(pac_url).send().ok()?.error_for_status().ok()?;
                let bytes = resp.bytes().ok()?;
                if bytes.len() > PAC_MAX_BYTES {
                    return None;
                }
                let script = String::from_utf8_lossy(&bytes).into_owned();
                *self.pac.lock().unwrap_or_else(|p| p.into_inner()) =
                    Some((pac_url.to_owned(), script.clone(), Instant::now()));
                Some(script)
            }

            fn run_script(script: &str, url: &CFURL) -> Vec<ProxyEntry> {
                let script = CFString::new(script);
                let mut err: CFErrorRef = std::ptr::null_mut();
                // SAFETY: valid CFString/CFURL; the result follows the Create rule.
                let arr = unsafe {
                    CFNetworkCopyProxiesForAutoConfigurationScript(
                        script.as_concrete_TypeRef(),
                        url.as_concrete_TypeRef(),
                        &mut err,
                    )
                };
                if !err.is_null() {
                    // SAFETY: Create rule: we own the error.
                    drop(unsafe { CFError::wrap_under_create_rule(err) });
                }
                if arr.is_null() {
                    return Vec::new();
                }
                // SAFETY: non-null CFArray, Create rule.
                let arr = unsafe { CFArray::<CFType>::wrap_under_create_rule(arr) };
                items(arr)
                    .into_iter()
                    .filter_map(|i| match i {
                        Item::Entry(e) => Some(e),
                        _ => None,
                    })
                    .collect()
            }
        }

        fn cf_url(u: &Url) -> Option<CFURL> {
            let s = CFString::new(u.as_str());
            // SAFETY: valid CFString; returns null for an unparsable URL.
            let r = unsafe {
                core_foundation_sys::url::CFURLCreateWithString(
                    core_foundation_sys::base::kCFAllocatorDefault,
                    s.as_concrete_TypeRef(),
                    std::ptr::null(),
                )
            };
            // SAFETY: Create rule.
            (!r.is_null()).then(|| unsafe { CFURL::wrap_under_create_rule(r) })
        }

        impl OsProxyResolver for SystemProxy {
            fn resolve(&self, target: &Url) -> Vec<ProxyEntry> {
                let Some(cfurl) = cf_url(target) else { return Vec::new() };
                // SAFETY: Create rule on both results; `settings` is released below.
                let settings = unsafe { CFNetworkCopySystemProxySettings() };
                if settings.is_null() {
                    return Vec::new();
                }
                let proxies = unsafe { CFNetworkCopyProxiesForURL(cfurl.as_concrete_TypeRef(), settings) };
                unsafe { CFRelease(settings as CFTypeRef) };
                if proxies.is_null() {
                    return Vec::new();
                }
                // SAFETY: non-null CFArray, Create rule.
                let first = items(unsafe { CFArray::<CFType>::wrap_under_create_rule(proxies) });
                let mut out = Vec::new();
                for item in first {
                    match item {
                        Item::Entry(e) => out.push(e),
                        Item::PacScript(script) => out.extend(Self::run_script(&script, &cfurl)),
                        Item::PacUrl(pac_url) => match self.fetch_pac(&pac_url) {
                            Some(script) => out.extend(Self::run_script(&script, &cfurl)),
                            None => log::warn!("relay: cannot fetch the PAC script"),
                        },
                    }
                }
                out
            }
        }
    }

    #[cfg(windows)]
    mod win {
        use url::Url;
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::Foundation::{GlobalFree, HGLOBAL, TRUE};
        use windows::Win32::Networking::WinHttp::*;

        use super::super::{
            bypassed, parse_winhttp_proxy_list, OsProxyResolver, ProxyEntry,
        };

        /// Windows: WinHTTP (per-user IE/WinINet settings, WPAD and PAC).
        pub struct SystemProxy;

        fn take(p: PWSTR) -> Option<String> {
            if p.is_null() {
                return None;
            }
            // SAFETY: WinHTTP returns NUL-terminated strings allocated with
            // GlobalAlloc, which the caller frees with GlobalFree.
            let s = unsafe { p.to_string().ok() };
            unsafe {
                let _ = GlobalFree(Some(HGLOBAL(p.0.cast())));
            }
            s.filter(|s| !s.is_empty())
        }

        fn scheme_of(u: &Url) -> &'static str {
            if matches!(u.scheme(), "http" | "ws") {
                "http"
            } else {
                "https"
            }
        }

        impl OsProxyResolver for SystemProxy {
            fn resolve(&self, target: &Url) -> Vec<ProxyEntry> {
                let host = target.host_str().unwrap_or("");
                let mut ie = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
                // SAFETY: `ie` is a valid out-structure.
                if unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut ie) }.is_err() {
                    return Vec::new();
                }
                let auto_detect = ie.fAutoDetect.as_bool();
                let pac_url = take(ie.lpszAutoConfigUrl);
                let static_proxy = take(ie.lpszProxy);
                let bypass = take(ie.lpszProxyBypass);

                if auto_detect || pac_url.is_some() {
                    if let Some(entries) = auto_proxy(target, auto_detect, pac_url.as_deref()) {
                        return entries;
                    }
                }
                match static_proxy {
                    Some(list) => {
                        if bypass.as_deref().is_some_and(|b| bypassed(host, b)) {
                            vec![ProxyEntry::Direct]
                        } else {
                            parse_winhttp_proxy_list(&list, scheme_of(target))
                        }
                    }
                    None => Vec::new(),
                }
            }
        }

        /// `WinHttpGetProxyForUrl`; `None` if it failed (fall back to the
        /// static settings).
        fn auto_proxy(target: &Url, auto_detect: bool, pac_url: Option<&str>) -> Option<Vec<ProxyEntry>> {
            let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
            let agent = wide("Ventriloquist");
            // SAFETY: valid NUL-terminated wide string; null proxy arguments.
            let session = unsafe {
                WinHttpOpen(
                    PCWSTR(agent.as_ptr()),
                    WINHTTP_ACCESS_TYPE_NO_PROXY,
                    PCWSTR::null(),
                    PCWSTR::null(),
                    0,
                )
            };
            if session.is_null() {
                return None;
            }
            let pac_w = pac_url.map(wide);
            let mut opts = WINHTTP_AUTOPROXY_OPTIONS::default();
            if auto_detect {
                opts.dwFlags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
                opts.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
            }
            if let Some(p) = &pac_w {
                opts.dwFlags |= WINHTTP_AUTOPROXY_CONFIG_URL;
                opts.lpszAutoConfigUrl = PCWSTR(p.as_ptr());
            }
            opts.fAutoLogonIfChallenged = TRUE;
            let url_w = wide(target.as_str());
            let mut info = WINHTTP_PROXY_INFO::default();
            // SAFETY: all pointers outlive the call; `info` is an out-structure.
            let ok = unsafe { WinHttpGetProxyForUrl(session, PCWSTR(url_w.as_ptr()), &mut opts, &mut info) };
            // SAFETY: `session` came from WinHttpOpen.
            unsafe {
                let _ = WinHttpCloseHandle(session);
            }
            if ok.is_err() {
                return None;
            }
            let list = take(info.lpszProxy);
            let _ = take(info.lpszProxyBypass);
            if info.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY {
                return Some(vec![ProxyEntry::Direct]);
            }
            Some(list.map(|l| parse_winhttp_proxy_list(&l, scheme_of(target))).unwrap_or_default())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(host: &str, port: u16) -> ProxyEntry {
        ProxyEntry::Http { host: host.into(), port, auth: None }
    }

    fn url() -> Url {
        Url::parse("https://relay.example.com/v1/x").unwrap()
    }

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| (*v).to_owned())
    }

    #[test]
    fn pac_results() {
        assert_eq!(
            parse_pac_result("PROXY a.corp:8080; PROXY b:81; DIRECT"),
            vec![http("a.corp", 8080), http("b", 81), ProxyEntry::Direct]
        );
        assert_eq!(parse_pac_result("direct"), vec![ProxyEntry::Direct]);
        assert_eq!(parse_pac_result("SOCKS s:1080; HTTPS p:443"), vec![http("p", 443)]);
        assert_eq!(parse_pac_result(""), vec![]);
        assert_eq!(parse_pac_result("PROXY"), vec![]);
    }

    #[test]
    fn proxy_uris() {
        assert_eq!(parse_proxy_uri("proxy.corp:3128"), Some(http("proxy.corp", 3128)));
        assert_eq!(parse_proxy_uri("http://proxy.corp:3128/"), Some(http("proxy.corp", 3128)));
        assert_eq!(parse_proxy_uri("http://proxy.corp"), Some(http("proxy.corp", 80)));
        assert_eq!(parse_proxy_uri("proxy.corp"), Some(http("proxy.corp", 8080)));
        assert_eq!(parse_proxy_uri("socks5://x:1"), None);
        assert_eq!(parse_proxy_uri(""), None);
        assert_eq!(
            parse_proxy_uri("http://me%40x:p%3Aw@proxy.corp:3128"),
            Some(ProxyEntry::Http {
                host: "proxy.corp".into(),
                port: 3128,
                auth: Some(("me@x".into(), "p:w".into()))
            })
        );
        // The password never shows up in Debug output.
        let dbg = format!("{:?}", parse_proxy_uri("http://u:secret@h:1").unwrap());
        assert!(!dbg.contains("secret"), "{dbg}");
    }

    #[test]
    fn winhttp_lists() {
        assert_eq!(parse_winhttp_proxy_list("a:80", "https"), vec![http("a", 80)]);
        assert_eq!(
            parse_winhttp_proxy_list("a:80;b:81", "https"),
            vec![http("a", 80), http("b", 81)]
        );
        assert_eq!(
            parse_winhttp_proxy_list("http=a:80;https=b:81;socks=c:1080", "https"),
            vec![http("b", 81)]
        );
        // Only an http= entry: nothing applies to https (WinINet semantics).
        assert_eq!(parse_winhttp_proxy_list("http=a:80", "https"), vec![]);
        assert_eq!(parse_winhttp_proxy_list("a:80 b:81", "https").len(), 2);
        assert_eq!(parse_winhttp_proxy_list("", "https"), vec![]);
    }

    #[test]
    fn bypass_lists() {
        assert!(bypassed("localhost", "localhost,127.0.0.1"));
        assert!(bypassed("relay.corp.example", ".corp.example"));
        assert!(bypassed("corp.example", ".corp.example"));
        assert!(bypassed("a.corp.example", "*.corp.example"));
        assert!(!bypassed("notcorp.example", ".corp.example"));
        assert!(bypassed("10.1.2.3", "10.*"));
        assert!(!bypassed("110.1.2.3", "10.*"));
        assert!(bypassed("intranet", "<local>"));
        assert!(!bypassed("relay.example.com", "<local>"));
        assert!(bypassed("anything", "*"));
        assert!(bypassed("Relay.Example.COM", "relay.example.com;other"));
        assert!(bypassed("relay.example.com", "relay.example.com:443"));
        assert!(!bypassed("relay.example.com", ""));
        assert!(bypassed("a.b.example.com", "a.*.example.com"));
        assert!(!bypassed("a.example.com", "a.*.example.com"));
    }

    #[test]
    fn environment_overrides_the_os() {
        struct Os;
        impl OsProxyResolver for Os {
            fn resolve(&self, _: &Url) -> Vec<ProxyEntry> {
                vec![http("os-proxy", 1)]
            }
        }
        let none = env_of(&[]);
        assert_eq!(resolve_proxies(&none, &Os, &url()), vec![http("os-proxy", 1)]);
        let env = env_of(&[("HTTPS_PROXY", "http://env-proxy:8888")]);
        assert_eq!(resolve_proxies(&env, &Os, &url()), vec![http("env-proxy", 8888)]);
        let lower = env_of(&[("https_proxy", "env-proxy:8888")]);
        assert_eq!(resolve_proxies(&lower, &Os, &url()), vec![http("env-proxy", 8888)]);
        let all = env_of(&[("ALL_PROXY", "all:1")]);
        assert_eq!(resolve_proxies(&all, &Os, &url()), vec![http("all", 1)]);
        // NO_PROXY wins over HTTPS_PROXY and over the OS.
        let np = env_of(&[("HTTPS_PROXY", "p:1"), ("NO_PROXY", ".example.com")]);
        assert_eq!(resolve_proxies(&np, &Os, &url()), vec![ProxyEntry::Direct]);
        let only_np = env_of(&[("NO_PROXY", "relay.example.com")]);
        assert_eq!(resolve_proxies(&only_np, &Os, &url()), vec![ProxyEntry::Direct]);
        // Another host's NO_PROXY does not matter.
        let other = env_of(&[("NO_PROXY", "other.test")]);
        assert_eq!(resolve_proxies(&other, &Os, &url()), vec![http("os-proxy", 1)]);
        // An empty value is unset.
        let empty = env_of(&[("HTTPS_PROXY", "  ")]);
        assert_eq!(resolve_proxies(&empty, &Os, &url()), vec![http("os-proxy", 1)]);
    }

    #[test]
    fn no_information_means_direct() {
        assert_eq!(resolve_proxies(&env_of(&[]), &NoOsProxy, &url()), vec![ProxyEntry::Direct]);
    }

    #[test]
    fn reqwest_proxy_urls() {
        assert_eq!(http("p", 8).to_url().as_deref(), Some("http://p:8"));
        assert_eq!(ProxyEntry::Direct.to_url(), None);
        let a = ProxyEntry::Http { host: "p".into(), port: 8, auth: Some(("u@x".into(), "p w".into())) };
        assert_eq!(a.to_url().as_deref(), Some("http://u%40x:p%20w@p:8"));
    }

    /// The real OS resolver must at least not crash and return something
    /// sensible for a plain URL (CI has no proxy configured).
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn system_resolver_smoke() {
        let v = system_resolver().resolve(&url());
        eprintln!("system proxies for the relay URL: {v:?}");
    }
}
