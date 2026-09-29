// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 内置 HTTPS 支持（`tls` feature）。

use std::future::Future;
use std::sync::Arc;

use axum::Router;
use crbs_core::config::ServerTlsConfig;
use crbs_core::error::CrbsError;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

/// 从 `server.toml` 的 `[tls]` 段构造 `TlsAcceptor`。
pub(super) async fn build_tls_acceptor(tls: &ServerTlsConfig) -> crbs_core::Result<TlsAcceptor> {
    let cert_pem = tokio::fs::read(&tls.cert)
        .await
        .map_err(|e| CrbsError::from_io_context("read tls cert", e))?;
    let key_pem = tokio::fs::read(&tls.key)
        .await
        .map_err(|e| CrbsError::from_io_context("read tls key", e))?;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<_, _>>()
            .map_err(|e| CrbsError::io_message(format!("parse tls cert pem: {e}")))?;

    if certs.is_empty() {
        return Err(CrbsError::io_message(
            "no certificates found in tls cert pem",
        ));
    }

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| CrbsError::io_message(format!("parse tls key pem: {e}")))?
        .ok_or_else(|| CrbsError::io_message("no private key found in tls key pem"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| CrbsError::io_message(format!("build tls server config: {e}")))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// TLS 版 `axum::serve`：accept → TLS handshake → serve connection。
/// graceful shutdown：收到 `shutdown` 后停 accept、通知活跃连接 graceful_shutdown；
/// 排空限时 `drain_timeout_secs`（只限信号后排空阶段，与 `lifecycle::serve_http` 同语义），超时 abort 残留。
pub(super) async fn serve_tls(
    listener: TcpListener,
    app: Router,
    acceptor: TlsAcceptor,
    shutdown: impl Future<Output = ()> + Send + 'static,
    drain_timeout_secs: u64,
) -> crbs_core::Result<()> {
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        shutdown.await;
        cancel_clone.cancel();
    });

    let conn_handles: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));

    loop {
        let (tcp_stream, remote_addr) = tokio::select! {
            res = listener.accept() => match res {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, "tls accept failed");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            },
            _ = cancel.cancelled() => break,
        };

        let acceptor = acceptor.clone();
        let app = app.clone();
        let conn_cancel = cancel.child_token();

        let handle = tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(error = %e, peer = %remote_addr, "tls handshake failed");
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            // 注入 ConnectInfo（真连对端地址）供登录/注册限流取真 IP：手动走
            // make-service 协议，先 call(remote_addr) 得逐连接 service 再包
            // TowerToHyperService；错误类型 Infallible，`match err {}` 消掉即可。
            let mut make = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
            let with_connect_info = match tower::Service::call(&mut make, remote_addr).await {
                Ok(svc) => svc,
                Err(err) => match err {},
            };
            let service = TowerToHyperService::new(with_connect_info);

            // 连接层防线（仅此 TLS 路径；明文路径 lifecycle::serve_http 用 axum::serve 无
            // 同等定制口，已知限制）：http1 header_read_timeout 30s 治慢速攻击（读头发
            // 一半挂住）；http2 keep_alive_interval 30s / timeout 20s PING 探测空闲死链
            //（NAT 超时、VM 挂起），连续丢 1~2 个 PING（≈30s+20s）即断开。
            let mut builder = Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::default())
                .header_read_timeout(std::time::Duration::from_secs(30));
            builder
                .http2()
                .timer(TokioTimer::default())
                .keep_alive_interval(std::time::Duration::from_secs(30))
                .keep_alive_timeout(std::time::Duration::from_secs(20));
            let mut conn = std::pin::pin!(builder.serve_connection_with_upgrades(io, service));

            loop {
                tokio::select! {
                    res = conn.as_mut() => {
                        if let Err(e) = res {
                            tracing::debug!(error = %e, peer = %remote_addr, "serve connection failed");
                        }
                        break;
                    }
                    _ = conn_cancel.cancelled() => {
                        conn.as_mut().graceful_shutdown();
                    }
                }
            }
        });

        // Mutex poison 恢复：句柄表非关键状态（句柄丢失只影响 shutdown 等待，不影响连接本身），毒化后抢救继续。
        let mut handles = conn_handles.lock().unwrap_or_else(|p| p.into_inner());
        // accept 路径顺手清理已完成句柄：只增不减的 Vec 会随连接数缓慢泄漏内存（代价 O(当前句柄数)）。
        handles.retain(|h| !h.is_finished());
        handles.push(handle);
    }

    let handles: Vec<_> = conn_handles
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .drain(..)
        .collect();
    if !handles.is_empty() {
        tracing::info!(
            connections = handles.len(),
            "Waiting for TLS connections to close"
        );
        let grace = tokio::time::sleep(std::time::Duration::from_secs(drain_timeout_secs));
        tokio::pin!(grace);
        for mut h in handles {
            tokio::select! {
                _ = &mut grace => {
                    tracing::warn!("TLS connection graceful shutdown timed out, aborting remaining");
                    h.abort();
                }
                _ = &mut h => {}
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // 100 年有效期的自签证书（CN=localhost, SAN=localhost/127.0.0.1），仅用于测试。
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIDJzCCAg+gAwIBAgIUezHg83qvf32MRDPxcYNARoVpdMkwDQYJKoZIhvcNAQEL\n\
        BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDcwNjA3MDkzOVoYDzIxMjYw\n\
        NjEyMDcwOTM5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB\n\
        AQUAA4IBDwAwggEKAoIBAQDldTF1/W9rsaO7mI+Nm9Zf0aEakCZxIES4xlUrXAKd\n\
        4Jb7f6GQNZz6qEuTVHuZHERZMIjEfNuVTs7g5Efgea/kNePYSYYItyzJUjSNtb9g\n\
        /tUz7y/RYbmap1bEV9ZXLzsJTZv9+2ams0wUN36jGg0WwsY5vmsfbgN5cPzHxeCY\n\
        +Lmv5EVt48KZvaNT8UmylCbKyCkL2xzvB83fVs/pZHZA3yNMy5sJI4BMvlDAsPrj\n\
        MvB/uimUM69sbGxZlQwIBQTBnGHPXLUDxQLBmW9vmH2vDa9e59t+/1IbhHkN7QHt\n\
        AiDk2vrjYKtikPS+JsXelqgXpOnDm/HWx2p/rh8z/WStAgMBAAGjbzBtMB0GA1Ud\n\
        DgQWBBSQ9k+XTXuViKP+slByO1GxuHBhgjAfBgNVHSMEGDAWgBSQ9k+XTXuViKP+\n\
        slByO1GxuHBhgjAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQTMBGCCWxvY2FsaG9z\n\
        dIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAtsaCx1xB4ZTsedbdOWgI+NoyRFql\n\
        K0eAVGsEJuTxCb+PlvbOnwPxc3sqoVE3lSWvEzv/bnNOph3AHtnjVTSqkDzpLo0+\n\
        vcnYKKBIw14Eqy3S8efbJ29zxkkaH0XxAxqOpu1bykBAwshGOITfYs6s1Xr8A6br\n\
        sAoDWlBbT3iUUO9dnz3Hu7TdimmTF1jQAxshE5xr+7PnspVWVA4u0nuj8axKtDvP\n\
        zCo5epnavT62ZGTxqACEoAhGf80uXh5kbialzOequkUSEgiibuTPIoskriuVQsro\n\
        I9AdBbRqMNoK8k6DeSz91+wT+M8RvSR284u5yKUfTjRWAMZCGO+BG+Cykw==\n\
        -----END CERTIFICATE-----";

    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDldTF1/W9rsaO7\n\
        mI+Nm9Zf0aEakCZxIES4xlUrXAKd4Jb7f6GQNZz6qEuTVHuZHERZMIjEfNuVTs7g\n\
        5Efgea/kNePYSYYItyzJUjSNtb9g/tUz7y/RYbmap1bEV9ZXLzsJTZv9+2ams0wU\n\
        N36jGg0WwsY5vmsfbgN5cPzHxeCY+Lmv5EVt48KZvaNT8UmylCbKyCkL2xzvB83f\n\
        Vs/pZHZA3yNMy5sJI4BMvlDAsPrjMvB/uimUM69sbGxZlQwIBQTBnGHPXLUDxQLB\n\
        mW9vmH2vDa9e59t+/1IbhHkN7QHtAiDk2vrjYKtikPS+JsXelqgXpOnDm/HWx2p/\n\
        rh8z/WStAgMBAAECggEAIWmrmmYdfbXoJQbd7o3BDYJp3oObqXD8uNheqhnzophD\n\
        /Br1hJmeAo0TtkBA4EaSuFceL1iMJCWN8Acl5Uzq/UUQqNvp+eZsjeNb1j/fPqlV\n\
        FAMyOB/uJlRUSPKOenMc+mmT+8vKQp+Mxkvfc7I1MjmKInn1QOYk+N/oW1HX9wZI\n\
        ZN2htxnDdJ6yPC03XHgSYUlYZ0HL5eLD53pU5hsZQOkU5uTC3k+jjsR+UOwjZR6t\n\
        HCMhhF1vJBadsZ+AcNvwdDvjWSwAycz6RAUh4bEMpzXD2gBWqasBN3XpIySdvQOn\n\
        PItjPqgiVgIrUms2bWMMCHiFyHq27FCavYz6ulNYCQKBgQD8b1I9I+H3PyKJLhIs\n\
        ZcQAlsYLCaCHiJhIJzemTs4WA2sGJOto6dv4bs6H1Ijhh2p2O1VxYXR98XCeDCNF\n\
        fCkNUUtnKB2xUdQDpel5lAI/LIYamL0TFjnTUzyz7mOpFWyeVslMLWdwaSa6ifW4\n\
        UwUBenRycdY2z0zH+utp4TAspQKBgQDossxgBznkIVK8/L44D1n+qqMJaS97AYPC\n\
        yzVRF6BrR0TyXQu0vTMNnQgXzetKh2tOsBcflTQY995MF9Q1hq2w+kM+DNSj1yCh\n\
        MWskkmqLFsgRP94++74TD09n525xyvV9nSKDpf7kBDSMQorNBx64YOlYdrDQ84wR\n\
        2/vRh1mxaQKBgDqAQfrRWgjGpOZNuwB3BRlt16+vJ3jBeykdjZQJJ1GKsT7XR4ck\n\
        y0mjxFFOO/qoO0/zKDYCc9DMJ2E5RuNPhuQDNwpNDbSOVigSRy1Z07t4Qgvf4dGO\n\
        kRAcdjDsykPhJy76xePVkedHNyZ72mpBMyPIkTwEjbReDlk6GVyMR3HRAoGAbMRO\n\
        RUB7bceprc6RdxCt5xyJUnfJCrzdgqqLRFk/0YUhlAur0hJxj5Zr1vyYU2DS5pfm\n\
        ZwvNqzIIxRaKSW6nN0bzMUi8B80hYlcAFrsdc9/1KiLpVhVDdhM88Xs6o5PThaBy\n\
        JojriFby3PCpgkYmtNYPnBr2cOS1/w8NOJYEdakCgYEAk88F1blE9lzPXf4CWpGf\n\
        Squ+wjc2WZ7OJJnWoXQpusv10P+tb/UmR9uCGLtYzqbnMfUH3nhnagWLa/Tlp31Q\n\
        2BUZt/kr4zNHcvcUEDY32gjNPaujOuWoVbHtgO0IbeoW+gT/n9mls7YIXCMKQccT\n\
        YGhtEb/GNoTXIzJ9GFPDWbI=\n\
        -----END PRIVATE KEY-----";

    #[tokio::test]
    async fn build_tls_acceptor_accepts_valid_pem() {
        let tmp = tempfile::tempdir().unwrap();
        let cert_path = tmp.path().join("server.crt");
        let key_path = tmp.path().join("server.key");
        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();
        std::fs::write(&key_path, TEST_KEY_PEM).unwrap();

        let acceptor = build_tls_acceptor(&ServerTlsConfig {
            cert: cert_path,
            key: key_path,
        })
        .await;
        assert!(acceptor.is_ok(), "{}", acceptor.err().unwrap());
    }

    #[tokio::test]
    async fn build_tls_acceptor_rejects_missing_cert() {
        let tmp = tempfile::tempdir().unwrap();
        let acceptor = build_tls_acceptor(&ServerTlsConfig {
            cert: tmp.path().join("missing.crt"),
            key: tmp.path().join("missing.key"),
        })
        .await;
        assert!(acceptor.is_err());
    }

    /// 空 cert / 垃圾 key 的启动期 fail-closed 文案契约（"no certificates" /
    /// "no private key"）：TLS 不得在缺证书/缺私钥时静默回退明文。
    #[tokio::test]
    async fn build_tls_acceptor_rejects_empty_cert_and_garbage_key() {
        let tmp = tempfile::tempdir().unwrap();
        let cert_path = tmp.path().join("server.crt");
        let key_path = tmp.path().join("server.key");

        std::fs::write(&cert_path, "").unwrap();
        std::fs::write(&key_path, TEST_KEY_PEM).unwrap();
        let err = match build_tls_acceptor(&ServerTlsConfig {
            cert: cert_path.clone(),
            key: key_path.clone(),
        })
        .await
        {
            Err(e) => e,
            Ok(_) => panic!("empty cert pem must be rejected"),
        };
        assert!(
            err.to_string().contains("no certificates"),
            "unexpected error: {err}"
        );

        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();
        std::fs::write(&key_path, "not a pem key").unwrap();
        let err = match build_tls_acceptor(&ServerTlsConfig {
            cert: cert_path,
            key: key_path,
        })
        .await
        {
            Err(e) => e,
            Ok(_) => panic!("garbage key pem must be rejected"),
        };
        assert!(
            err.to_string().contains("no private key"),
            "unexpected error: {err}"
        );
    }

    /// 排空超时兜底：卡在 TLS 握手的在途连接（不发握手字节、永不完成）无法响应 graceful shutdown，应在 drain_timeout_secs 后 abort 并返回 Ok 继续停机。
    #[tokio::test]
    async fn serve_tls_drain_timeout_continues_shutdown_with_hanging_connection() {
        let tmp = tempfile::tempdir().unwrap();
        let cert_path = tmp.path().join("server.crt");
        let key_path = tmp.path().join("server.key");
        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();
        std::fs::write(&key_path, TEST_KEY_PEM).unwrap();
        let acceptor = build_tls_acceptor(&ServerTlsConfig {
            cert: cert_path,
            key: key_path,
        })
        .await
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = Router::new().route(
            "/hang",
            axum::routing::get(|| async { std::future::pending::<()>().await }),
        );

        // 只完成 TCP 三次握手、不发送任何字节：连接任务卡在 acceptor.accept() 等 ClientHello。
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // 给 accept 循环时间把连接任务入表，确保 drain 路径真的在等它。
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let shutdown = async { tokio::time::sleep(std::time::Duration::from_millis(100)).await };
        let start = std::time::Instant::now();
        let res = serve_tls(listener, app, acceptor, shutdown, 1).await;

        assert!(
            res.is_ok(),
            "drain timeout should return Ok to continue shutdown"
        );
        assert!(
            start.elapsed() >= std::time::Duration::from_secs(1),
            "serve_tls should have waited the drain timeout before aborting"
        );
    }
}
