use axum::{body::Body, extract::Request, response::Response};
use url::Url;

use super::{body::SyncBodyDataStream, headers::strip_connection_headers, Client, Error};

/// Proxies provided Axum request to a given URL using Client trait object and returns Axum response
pub async fn proxy(
    url: Url,
    request: Request,
    http_client: &impl Client,
) -> Result<Response, Error> {
    // Convert Axum request into Reqwest one
    let (mut parts, body) = request.into_parts();

    // Strip connection-related headers so that the request fits HTTP/2
    strip_connection_headers(&mut parts.headers);

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

    // Assign the headers
    *response.headers_mut() = headers;

    Ok(response)
}
