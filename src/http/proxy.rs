use std::sync::Arc;

use axum::{body::Body, extract::Request, response::Response};
use url::Url;

use super::{
    body::{HintBody, SyncBody},
    headers::strip_connection_headers,
    Client, Error,
};

/// Proxies provided Axum request to a given URL using Client trait object and returns Axum response
pub async fn proxy(
    url: Url,
    request: Request,
    http_client: &Arc<dyn Client>,
) -> Result<Response, Error> {
    // Convert Axum request into Reqwest one
    let (mut parts, body) = request.into_parts();

    // Strip connection-related headers so that the request fits HTTP/2
    strip_connection_headers(&mut parts.headers);

    let mut request = reqwest::Request::new(parts.method.clone(), url);
    *request.headers_mut() = parts.headers;

    // Use SyncBody wrapper that is Sync (Axum body is !Sync)
    *request.body_mut() = Some(reqwest::Body::wrap(SyncBody::new(body)));

    // Execute the request
    let response = http_client.execute(request).await?;

    // Convert Reqwest response into Axum one
    let content_length = response.content_length();
    let response: http::Response<_> = response.into();
    let (parts, body) = response.into_parts();
    let body = HintBody::new(body, content_length);

    Ok(Response::from_parts(parts, Body::new(body)))
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use axum::{body::Body, extract::Request};
    use http_body::Body as _;

    use crate::http::proxy::proxy;

    #[derive(Debug)]
    struct HttpClient;

    #[async_trait::async_trait]
    impl crate::http::Client for HttpClient {
        async fn execute(&self, _: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
            Ok(reqwest::Response::from(
                http::response::Builder::new()
                    .status(200)
                    .body(reqwest::Body::from("foobarbaz"))
                    .unwrap(),
            ))
        }
    }

    #[tokio::test]
    async fn test_size_hint() {
        let cli = Arc::new(HttpClient) as Arc<dyn crate::http::Client>;
        let url = url::Url::parse("http://foo.bar").unwrap();
        let request = Request::new(Body::empty());
        let resp = proxy(url, request, &cli).await.unwrap();

        assert_eq!(resp.body().size_hint().exact(), Some(9));
    }
}
