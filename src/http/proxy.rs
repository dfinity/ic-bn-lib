use std::sync::Arc;

use axum::{body::Body, extract::Request, response::Response};
use url::Url;

use super::{body::SyncBodyDataStream, Client, Error};

/// Proxies provided Axum request to a given URL using Reqwest Client trait object and returns Axum response
pub async fn proxy(
    url: Url,
    request: Request,
    http_client: &Arc<dyn Client>,
) -> Result<Response, Error> {
    // Convert Axum request into Reqwest one
    let (parts, body) = request.into_parts();
    let mut request = reqwest::Request::new(parts.method.clone(), url);
    *request.headers_mut() = parts.headers;
    // Use SyncBodyDataStream wrapper that is Sync (Axum body is !Sync)
    *request.body_mut() = Some(reqwest::Body::wrap_stream(SyncBodyDataStream::new(body)));

    // Execute the request
    let response = http_client.execute(request).await?;
    let headers = response.headers().clone();

    // Convert the Reqwest response back to the Axum one
    let mut response = Response::builder()
        .status(response.status())
        .body(Body::from_stream(response.bytes_stream()))?;

    // Copy the headers
    *response.headers_mut() = headers;

    Ok(response)
}
