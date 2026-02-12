use agenet_types::AgenetError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Relay-specific error wrapper that maps to HTTP responses.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error(transparent)]
    Agenet(#[from] AgenetError),
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            RelayError::Agenet(AgenetError::InvalidSignature) => {
                (StatusCode::FORBIDDEN, "invalid signature")
            }
            RelayError::Agenet(AgenetError::InvalidPow) => {
                (StatusCode::FORBIDDEN, "invalid proof-of-work")
            }
            RelayError::Agenet(AgenetError::PowExpired) => {
                (StatusCode::GONE, "proof-of-work challenge expired")
            }
            RelayError::Agenet(AgenetError::UnknownSchema(_)) => {
                (StatusCode::BAD_REQUEST, "unknown schema")
            }
            RelayError::Agenet(AgenetError::SchemaValidation(_)) => {
                (StatusCode::BAD_REQUEST, "schema validation failed")
            }
            RelayError::Agenet(AgenetError::NotFound(_)) => {
                (StatusCode::NOT_FOUND, "object not found")
            }
            RelayError::Agenet(AgenetError::Duplicate(_)) => (StatusCode::OK, "duplicate object"),
            RelayError::Agenet(AgenetError::InsufficientCredits) => {
                (StatusCode::PAYMENT_REQUIRED, "insufficient credits")
            }
            RelayError::Agenet(AgenetError::Unauthorized(_)) => {
                (StatusCode::FORBIDDEN, "unauthorized")
            }
            RelayError::Agenet(AgenetError::Storage(_)) | RelayError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            RelayError::Agenet(AgenetError::Serialization(_)) => {
                (StatusCode::BAD_REQUEST, "serialization error")
            }
        };

        let body = json!({
            "error": message,
            "detail": self.to_string(),
        });

        (status, axum::Json(body)).into_response()
    }
}
