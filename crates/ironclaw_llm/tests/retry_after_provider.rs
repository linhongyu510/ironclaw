use std::sync::Arc;
use std::time::Duration;

use ironclaw_llm::{
    ChatMessage, CompletionRequest, LlmError, LlmProvider, NearAiChatProvider, NearAiConfig,
    SessionConfig, SessionManager,
};
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);

fn test_config(base_url: String) -> NearAiConfig {
    NearAiConfig {
        model: "test-model".to_string(),
        base_url,
        api_key: Some(SecretString::from("test-key".to_string())),
        cheap_model: None,
        fallback_model: None,
        max_retries: 0,
        circuit_breaker_threshold: None,
        circuit_breaker_recovery_secs: 30,
        response_cache_enabled: false,
        response_cache_ttl_secs: 3600,
        response_cache_max_entries: 1000,
        failover_cooldown_secs: 300,
        failover_cooldown_threshold: 3,
        smart_routing_cascade: true,
    }
}

async fn read_request_head(socket: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let bytes_read = socket.read(&mut chunk).await.expect("read request");
        assert!(bytes_read > 0, "connection closed before request headers");
        request.extend_from_slice(&chunk[..bytes_read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return String::from_utf8_lossy(&request).into_owned();
        }
    }
}

async fn serve_provider_error(listener: TcpListener, status_line: &'static str) {
    loop {
        let (mut socket, _) = listener.accept().await.expect("accept request");
        let request = read_request_head(&mut socket).await;
        if !request.starts_with("POST /v1/chat/completions ") {
            let body = r#"{"models":[]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\n\r\n{body}",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write pricing response");
            continue;
        }

        let body = r#"{"error":"upstream unavailable"}"#;
        let response = format!(
            "HTTP/1.1 {status_line}\r\ncontent-type: application/json\r\n\
             retry-after: 999999\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        socket
            .write_all(response.as_bytes())
            .await
            .expect("write provider error response");
        return;
    }
}

async fn complete_against(status_line: &'static str) -> LlmError {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("test server address")
    );
    let server_task = tokio::spawn(serve_provider_error(listener, status_line));
    let provider = NearAiChatProvider::new(
        test_config(base_url),
        Arc::new(SessionManager::new(SessionConfig::default())),
    )
    .expect("provider");

    let error = provider
        .complete(CompletionRequest::new(vec![ChatMessage::user("hello")]))
        .await
        .expect_err("provider error response should fail completion");
    server_task.await.expect("server task");
    error
}

#[tokio::test]
async fn retry_after_header_is_capped_across_provider_error_branches() {
    match complete_against("429 Too Many Requests").await {
        LlmError::RateLimited {
            provider,
            retry_after,
        } => {
            assert_eq!(provider, "nearai_chat");
            assert_eq!(retry_after, Some(MAX_RETRY_AFTER));
        }
        other => panic!("expected rate-limit error, got {other:?}"),
    }

    match complete_against("503 Service Unavailable").await {
        LlmError::BadGateway {
            provider,
            status,
            retry_after,
        } => {
            assert_eq!(provider, "nearai_chat");
            assert_eq!(status, 503);
            assert_eq!(retry_after, Some(MAX_RETRY_AFTER));
        }
        other => panic!("expected bad-gateway error, got {other:?}"),
    }
}
