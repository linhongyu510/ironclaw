//! Bounded translation from one intercepted HTTP/1.1 credentialed request to
//! the canonical host-owned [`RuntimeHttpEgress`] service.
//!
//! This adapter is deliberately concrete. It owns framing and translation,
//! while the existing host service remains the sole owner of secret
//! materialization, network policy enforcement, origin I/O, redirects, and
//! response sanitization.

use std::{fmt::Write as _, time::Instant};

use ironclaw_host_api::{
    action::NetworkPolicy,
    http::{
        RuntimeCredentialInjection, RuntimeCredentialSource, RuntimeCredentialTarget,
        RuntimeHttpEgress, RuntimeHttpEgressError, RuntimeHttpEgressRequest,
        RuntimeHttpEgressResponse, valid_http_field_name,
    },
    runtime::RuntimeKind,
};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{
    SandboxCredentialRuntime, SandboxCredentialSwap, StaticCredentialAuthorizationError,
    placeholder_candidates,
};
use crate::sandbox_process::credential_firewall::SandboxCredentialConnectionIdentity;

const REQUEST_HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";
const MAX_CREDENTIALED_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_CREDENTIALED_RESPONSE_BODY_BYTES: u64 = 16 * 1024 * 1024;
const SANDBOX_HTTP_TIMEOUT_MS: u32 = 30_000;

/// One bounded, credentialed HTTP/1.1 request translator for the sandbox
/// proxy. Constructing it grants no authority: every dispatch still needs a
/// live firewall window and the runtime's exactly-once host-egress attachment.
pub(crate) struct SandboxProxyHttpAdapter {
    runtime: SandboxCredentialRuntime,
    credential_swap: SandboxCredentialSwap,
}

impl SandboxProxyHttpAdapter {
    pub(crate) fn new(runtime: SandboxCredentialRuntime) -> Self {
        let credential_swap = runtime.credential_swap();
        Self {
            runtime,
            credential_swap,
        }
    }

    /// Executes exactly one complete HTTP/1.1 request and returns exactly one
    /// serialized HTTP/1.1 response. Keep-alive, chunked request bodies,
    /// upgrades, and ambiguous framing are rejected before host egress runs.
    pub(super) async fn execute(
        &self,
        request_bytes: &[u8],
        connect_host: &str,
        identity: Option<SandboxCredentialConnectionIdentity<'_>>,
        deadline: Instant,
    ) -> Result<Vec<u8>, SandboxProxyHttpAdapterError> {
        let parsed = ParsedCredentialedRequest::parse(request_bytes, connect_host)?;
        let authority = self.credential_swap.authorize_static_http_request(
            &parsed.head,
            connect_host,
            identity,
            deadline,
        )?;

        let host_egress = self
            .runtime
            .attached_http_egress()
            .ok_or(SandboxProxyHttpAdapterError::HostEgressUnbound)?;
        let request = RuntimeHttpEgressRequest {
            runtime: RuntimeKind::Sandbox,
            scope: authority.scope,
            capability_id: authority.capability_id.clone(),
            method: authority.method,
            url: authority.url,
            headers: parsed.headers,
            body: parsed.body,
            // Production host egress resolves the staged policy by exact
            // scope+capability. The request-local fallback is intentionally
            // deny-all so this adapter can never invent permissive authority.
            network_policy: NetworkPolicy::default(),
            credential_injections: vec![RuntimeCredentialInjection {
                handle: authority.secret_handle,
                source: RuntimeCredentialSource::StagedObligation {
                    capability_id: authority.capability_id,
                },
                target: RuntimeCredentialTarget::Header {
                    name: "Authorization".to_string(),
                    prefix: Some(authority.authorization_prefix.to_string()),
                },
                required: true,
            }],
            response_body_limit: Some(MAX_CREDENTIALED_RESPONSE_BODY_BYTES),
            save_body_to: None,
            timeout_ms: Some(SANDBOX_HTTP_TIMEOUT_MS),
        };

        let response = host_egress.execute(request).await?;
        serialize_response(response)
    }

    /// Reads the remainder of one already-framed intercepted request body,
    /// rejects bytes beyond its declared `Content-Length`, and dispatches the
    /// complete request through [`Self::execute`]. The body read is bounded by
    /// both size and time before any host egress call occurs.
    pub(crate) async fn execute_intercepted<R>(
        &self,
        head: Vec<u8>,
        trailing: Vec<u8>,
        client: &mut R,
        connect_host: &str,
        identity: Option<SandboxCredentialConnectionIdentity<'_>>,
        deadline: Instant,
    ) -> Result<Vec<u8>, SandboxProxyHttpAdapterError>
    where
        R: AsyncRead + Unpin,
    {
        let content_length = declared_content_length(&head)?;
        if content_length > MAX_CREDENTIALED_REQUEST_BODY_BYTES {
            return Err(SandboxProxyHttpAdapterError::BodyTooLarge);
        }
        if trailing.len() > content_length {
            return Err(SandboxProxyHttpAdapterError::Malformed(
                "bytes follow the complete V1 request body",
            ));
        }

        let remaining = content_length - trailing.len();
        let mut body = trailing;
        if remaining > 0 {
            let original_len = body.len();
            body.resize(content_length, 0);
            tokio::time::timeout(
                std::time::Duration::from_millis(u64::from(SANDBOX_HTTP_TIMEOUT_MS)),
                client.read_exact(&mut body[original_len..]),
            )
            .await
            .map_err(|_| SandboxProxyHttpAdapterError::BodyReadTimedOut)?
            .map_err(|_| {
                SandboxProxyHttpAdapterError::Malformed(
                    "stream ended before the declared request body was complete",
                )
            })?;
        }

        let mut request = head;
        request.extend_from_slice(&body);
        self.execute(&request, connect_host, identity, deadline)
            .await
    }
}

#[derive(Debug, thiserror::Error)]
pub(in crate::sandbox_process) enum SandboxProxyHttpAdapterError {
    #[error("sandbox credentialed HTTP request is malformed: {0}")]
    Malformed(&'static str),
    #[error("sandbox credentialed HTTP request body exceeds the bounded V1 limit")]
    BodyTooLarge,
    #[error("sandbox credentialed HTTP request body read timed out")]
    BodyReadTimedOut,
    #[error("sandbox credentialed HTTP response is malformed: {0}")]
    MalformedResponse(&'static str),
    #[error("sandbox credentialed HTTP response exceeds the bounded V1 limit")]
    ResponseTooLarge,
    #[error("sandbox credentialed HTTP dispatch has no attached host egress service")]
    HostEgressUnbound,
    #[error(transparent)]
    Authorization(#[from] StaticCredentialAuthorizationError),
    #[error("sandbox host HTTP egress denied the request: {0}")]
    HostEgress(&'static str),
}

fn declared_content_length(head: &[u8]) -> Result<usize, SandboxProxyHttpAdapterError> {
    let terminator = head.strip_suffix(REQUEST_HEAD_TERMINATOR).ok_or(
        SandboxProxyHttpAdapterError::Malformed("missing request-head terminator"),
    )?;
    let text = std::str::from_utf8(terminator)
        .map_err(|_| SandboxProxyHttpAdapterError::Malformed("request head is not valid UTF-8"))?;
    let mut content_length = None;
    for line in text.split("\r\n").skip(1) {
        if line.starts_with([' ', '\t']) {
            return Err(SandboxProxyHttpAdapterError::Malformed(
                "obsolete folded headers are unsupported",
            ));
        }
        let (name, raw_value) =
            line.split_once(':')
                .ok_or(SandboxProxyHttpAdapterError::Malformed(
                    "request header is missing a colon",
                ))?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(SandboxProxyHttpAdapterError::Malformed(
                "Transfer-Encoding is unsupported",
            ));
        }
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        let value = raw_value.trim_matches([' ', '\t']);
        if content_length.is_some()
            || value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(SandboxProxyHttpAdapterError::Malformed(
                "Content-Length is duplicated or malformed",
            ));
        }
        content_length = Some(value.parse::<usize>().map_err(|_| {
            SandboxProxyHttpAdapterError::Malformed("Content-Length is out of range")
        })?);
    }
    Ok(content_length.unwrap_or(0))
}

impl From<RuntimeHttpEgressError> for SandboxProxyHttpAdapterError {
    fn from(error: RuntimeHttpEgressError) -> Self {
        Self::HostEgress(error.stable_runtime_reason())
    }
}

struct ParsedCredentialedRequest {
    head: Vec<u8>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl ParsedCredentialedRequest {
    fn parse(bytes: &[u8], connect_host: &str) -> Result<Self, SandboxProxyHttpAdapterError> {
        let head_end = bytes
            .windows(REQUEST_HEAD_TERMINATOR.len())
            .position(|window| window == REQUEST_HEAD_TERMINATOR)
            .and_then(|offset| offset.checked_add(REQUEST_HEAD_TERMINATOR.len()))
            .ok_or(SandboxProxyHttpAdapterError::Malformed(
                "missing request-head terminator",
            ))?;
        if head_end > super::super::egress_proxy::MAX_TOTAL_HEADER_BYTES {
            return Err(SandboxProxyHttpAdapterError::Malformed(
                "request head exceeds the proxy limit",
            ));
        }
        let head = &bytes[..head_end];
        let body = &bytes[head_end..];
        if body.len() > MAX_CREDENTIALED_REQUEST_BODY_BYTES {
            return Err(SandboxProxyHttpAdapterError::BodyTooLarge);
        }

        let head_text = std::str::from_utf8(head).map_err(|_| {
            SandboxProxyHttpAdapterError::Malformed("request head is not valid UTF-8")
        })?;
        let mut lines = head_text[..head_text.len() - REQUEST_HEAD_TERMINATOR.len()].split("\r\n");
        let request_line = lines.next().ok_or(SandboxProxyHttpAdapterError::Malformed(
            "missing request line",
        ))?;
        if request_line.len() > super::super::egress_proxy::MAX_HEADER_LINE_BYTES {
            return Err(SandboxProxyHttpAdapterError::Malformed(
                "request line exceeds the proxy limit",
            ));
        }
        parse_request_line(request_line)?;

        let syntactic_placeholders = placeholder_candidates(head);
        if syntactic_placeholders.len() != 1 {
            return Err(SandboxProxyHttpAdapterError::Malformed(
                "request must carry exactly one credential placeholder",
            ));
        }

        let mut headers = Vec::new();
        let mut host_header: Option<String> = None;
        let mut content_length: Option<usize> = None;
        let mut authorization_fields = 0usize;
        for (index, line) in lines.enumerate() {
            if index >= super::super::egress_proxy::MAX_HEADER_LINES {
                return Err(SandboxProxyHttpAdapterError::Malformed(
                    "too many request headers",
                ));
            }
            if line.len() > super::super::egress_proxy::MAX_HEADER_LINE_BYTES {
                return Err(SandboxProxyHttpAdapterError::Malformed(
                    "request header line exceeds the proxy limit",
                ));
            }
            if line.starts_with([' ', '\t']) {
                return Err(SandboxProxyHttpAdapterError::Malformed(
                    "obsolete folded headers are unsupported",
                ));
            }
            let (name, raw_value) =
                line.split_once(':')
                    .ok_or(SandboxProxyHttpAdapterError::Malformed(
                        "request header is missing a colon",
                    ))?;
            if !valid_http_field_name(name) {
                return Err(SandboxProxyHttpAdapterError::Malformed(
                    "request header name is invalid",
                ));
            }
            let value = raw_value.trim_matches([' ', '\t']);
            if value
                .chars()
                .any(|character| character.is_control() && character != '\t')
            {
                return Err(SandboxProxyHttpAdapterError::Malformed(
                    "request header value contains a control character",
                ));
            }

            if name.eq_ignore_ascii_case("host") {
                if host_header.replace(value.to_string()).is_some() {
                    return Err(SandboxProxyHttpAdapterError::Malformed(
                        "duplicate Host header",
                    ));
                }
                continue;
            }
            if name.eq_ignore_ascii_case("authorization") {
                authorization_fields += 1;
                continue;
            }
            if name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some()
                    || value.is_empty()
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(SandboxProxyHttpAdapterError::Malformed(
                        "Content-Length is duplicated or malformed",
                    ));
                }
                let declared = value.parse::<usize>().map_err(|_| {
                    SandboxProxyHttpAdapterError::Malformed("Content-Length is out of range")
                })?;
                if declared > MAX_CREDENTIALED_REQUEST_BODY_BYTES {
                    return Err(SandboxProxyHttpAdapterError::BodyTooLarge);
                }
                content_length = Some(declared);
                continue;
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(SandboxProxyHttpAdapterError::Malformed(
                    "Transfer-Encoding is unsupported",
                ));
            }
            if name.eq_ignore_ascii_case("expect") {
                return Err(SandboxProxyHttpAdapterError::Malformed(
                    "interim response framing is unsupported",
                ));
            }
            if name.eq_ignore_ascii_case("upgrade")
                || (name.eq_ignore_ascii_case("connection")
                    && value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("upgrade")))
            {
                return Err(SandboxProxyHttpAdapterError::Malformed(
                    "protocol upgrades are unsupported",
                ));
            }
            if name.eq_ignore_ascii_case("connection")
                && !value.split(',').all(|token| {
                    matches!(
                        token.trim().to_ascii_lowercase().as_str(),
                        "close" | "keep-alive"
                    )
                })
            {
                return Err(SandboxProxyHttpAdapterError::Malformed(
                    "Connection names unsupported hop-by-hop fields",
                ));
            }
            if is_hop_by_hop_request_header(name) {
                continue;
            }
            headers.push((name.to_string(), value.to_string()));
        }

        if authorization_fields != 1 {
            return Err(SandboxProxyHttpAdapterError::Malformed(
                "request must contain exactly one Authorization header",
            ));
        }
        let host_header = host_header.ok_or(SandboxProxyHttpAdapterError::Malformed(
            "missing Host header",
        ))?;
        if !host_matches_connect_authority(&host_header, connect_host) {
            return Err(SandboxProxyHttpAdapterError::Malformed(
                "Host header does not match CONNECT authority",
            ));
        }
        if content_length.unwrap_or(0) != body.len() {
            return Err(SandboxProxyHttpAdapterError::Malformed(
                "Content-Length does not match the complete request body",
            ));
        }

        Ok(Self {
            head: head.to_vec(),
            headers,
            body: body.to_vec(),
        })
    }
}

fn parse_request_line(line: &str) -> Result<(), SandboxProxyHttpAdapterError> {
    let mut fields = line.split(' ');
    let method = fields.next();
    let target = fields.next();
    let version = fields.next();
    if method.is_none()
        || target.is_none()
        || version != Some("HTTP/1.1")
        || fields.next().is_some()
    {
        return Err(SandboxProxyHttpAdapterError::Malformed(
            "unsupported HTTP request line",
        ));
    }
    Ok(())
}

fn host_matches_connect_authority(header: &str, connect_host: &str) -> bool {
    let header_host = header.strip_suffix(":443").unwrap_or(header);
    super::super::ca::normalize_host(header_host)
        .zip(super::super::ca::normalize_host(connect_host))
        .is_some_and(|(header_host, connect_host)| header_host == connect_host)
}

fn is_hop_by_hop_request_header(name: &str) -> bool {
    [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn serialize_response(
    response: RuntimeHttpEgressResponse,
) -> Result<Vec<u8>, SandboxProxyHttpAdapterError> {
    if !(200..=599).contains(&response.status) {
        return Err(SandboxProxyHttpAdapterError::MalformedResponse(
            "status code is unsupported",
        ));
    }
    if response.body.len() as u64 > MAX_CREDENTIALED_RESPONSE_BODY_BYTES {
        return Err(SandboxProxyHttpAdapterError::ResponseTooLarge);
    }

    let mut head = String::new();
    write!(
        &mut head,
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason_phrase(response.status)
    )
    .map_err(|_| SandboxProxyHttpAdapterError::MalformedResponse("could not format status"))?;
    for (index, (name, value)) in response.headers.into_iter().enumerate() {
        if index >= super::super::egress_proxy::MAX_HEADER_LINES {
            return Err(SandboxProxyHttpAdapterError::ResponseTooLarge);
        }
        if !valid_http_field_name(&name)
            || value.contains(['\r', '\n', '\0'])
            || value.chars().any(char::is_control)
        {
            return Err(SandboxProxyHttpAdapterError::MalformedResponse(
                "response header is invalid",
            ));
        }
        let line_len = name
            .len()
            .checked_add(value.len())
            .and_then(|length| length.checked_add(4))
            .ok_or(SandboxProxyHttpAdapterError::ResponseTooLarge)?;
        if line_len > super::super::egress_proxy::MAX_HEADER_LINE_BYTES {
            return Err(SandboxProxyHttpAdapterError::ResponseTooLarge);
        }
        if is_replaced_response_header(&name) {
            continue;
        }
        write!(&mut head, "{name}: {value}\r\n").map_err(|_| {
            SandboxProxyHttpAdapterError::MalformedResponse("could not format header")
        })?;
        if head.len() > super::super::egress_proxy::MAX_TOTAL_HEADER_BYTES {
            return Err(SandboxProxyHttpAdapterError::ResponseTooLarge);
        }
    }
    write!(
        &mut head,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        response.body.len()
    )
    .map_err(|_| SandboxProxyHttpAdapterError::MalformedResponse("could not finish response"))?;
    if head.len() > super::super::egress_proxy::MAX_TOTAL_HEADER_BYTES {
        return Err(SandboxProxyHttpAdapterError::ResponseTooLarge);
    }

    let mut serialized = Vec::with_capacity(head.len().saturating_add(response.body.len()));
    serialized.extend_from_slice(head.as_bytes());
    serialized.extend_from_slice(&response.body);
    Ok(serialized)
}

fn is_replaced_response_header(name: &str) -> bool {
    [
        "connection",
        "content-length",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests;
