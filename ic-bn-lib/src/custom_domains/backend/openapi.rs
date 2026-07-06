use utoipa::OpenApi;

use super::handlers::{
    __path_create_handler, __path_delete_handler, __path_get_handler, __path_update_handler,
    __path_validate_handler,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        create_handler,
        get_handler,
        update_handler,
        delete_handler,
        validate_handler,
    ),
    tags(
        (name = "domains", description = "Domain registration and management endpoints")
    ),
    info(
        title = "Custom Domains API",
        version = "1.0.0",
        description = "API for managing custom domain registrations and SSL certificates",
    ),
    servers(
        (url = "/", description = "Local server")
    )
)]
pub struct ApiDoc;

pub fn get_openapi_json() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}
