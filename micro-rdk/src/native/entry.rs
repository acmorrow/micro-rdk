#[cfg(test)]
mod tests {
    use crate::common::app_client::AppClientBuilder;

    use crate::common::credentials_storage::RobotCredentials;
    use crate::common::grpc_client::GrpcClient;

    use crate::common::exec::Executor;
    use crate::native::tcp::NativeStream;
    use crate::native::tls::NativeTls;

    use futures_lite::future::block_on;

    #[test_log::test]
    #[ignore]
    fn test_app_client() {
        let exec = Executor::new();
        exec.block_on(async { test_app_client_inner().await });
    }
    async fn test_app_client_inner() {
        let tls = Box::new(NativeTls::new_client());
        let conn = tls.open_ssl_context(None);
        let conn = block_on(conn);
        assert!(conn.is_ok());

        let conn = conn.unwrap();

        let conn = NativeStream::TLSStream(Box::new(conn));

        let exec = Executor::new();

        let grpc_client = GrpcClient::new(conn, exec, "https://app.viam.com:443").await;

        assert!(grpc_client.is_ok());

        let grpc_client = Box::new(grpc_client.unwrap());

        let config = RobotCredentials::new("".to_string(), "".to_string());

        let builder = AppClientBuilder::new(grpc_client, config);

        let client = builder.build().await;

        assert!(client.is_ok());

        let _ = client.unwrap();
    }
}
