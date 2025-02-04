use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

#[derive(Debug, PartialEq)]
pub enum ErrorMessage {
    EmptyPassword,
    ExceededMaxPasswordLength(usize),
    InvalidHashFormat,
    HashingError,
    InvalidToken,
    ServerError,
    WrongCredentials,
    EmailExist,
    UserNoLongerExist,
    TokenNotProvided,
    PermissionDenied,
    UserNotAuthenticated,
}

impl ErrorMessage {
    fn to_str(&self) -> &str {
        match self {
            ErrorMessage::ServerError => "Server Error. Please try again later",
            ErrorMessage::WrongCredentials => "Email or password is wrong",
            ErrorMessage::EmailExist => "A user with this email already exists",
            ErrorMessage::UserNoLongerExist => "User belonging to this token no longer exists",
            ErrorMessage::EmptyPassword => "Password cannot be empty",
            ErrorMessage::HashingError => "Error while hashing password",
            ErrorMessage::InvalidHashFormat => "Invalid password hash format",
            ErrorMessage::InvalidToken => "Authentication token is invalid or expired",
            ErrorMessage::TokenNotProvided => "You are not logged in, please provide a token",
            ErrorMessage::PermissionDenied => "You are not allowed to perform this action",
            ErrorMessage::UserNotAuthenticated => "Authentication required. Please log in.",
            ErrorMessage::ExceededMaxPasswordLength(_) => "",
        }
    }

    fn to_string(&self) -> String {
        match self {
            ErrorMessage::ExceededMaxPasswordLength(max_length) => {
                format!("Password must not be more than {} characters", max_length)
            }
            _ => self.to_str().to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpError {
    pub message: String,
    pub status: StatusCode,
}

impl HttpError {
    pub fn new(message: impl Into<String>, status: StatusCode) -> Self {
        HttpError {
            message: message.into(),
            status,
        }
    }

    pub fn server_error(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::BAD_REQUEST,
        }
    }

    pub fn unique_constraint_violation(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::CONFLICT,
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::UNAUTHORIZED,
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::FORBIDDEN,
        }
    }

    pub fn into_http_response(self) -> Response {
        let json_response = Json(ErrorResponse {
            status: "fail".to_string(),
            message: self.message,
        });

        (self.status, json_response).into_response()
    }
}

impl From<ErrorMessage> for HttpError {
    fn from(error: ErrorMessage) -> Self {
        match error {
            ErrorMessage::WrongCredentials => HttpError::unauthorized(error.to_string()),
            ErrorMessage::EmailExist => HttpError::unique_constraint_violation(error.to_string()),
            ErrorMessage::UserNoLongerExist => HttpError::unauthorized(error.to_string()),
            ErrorMessage::TokenNotProvided => HttpError::unauthorized(error.to_string()),
            ErrorMessage::PermissionDenied => HttpError::forbidden(error.to_string()),
            ErrorMessage::UserNotAuthenticated => HttpError::unauthorized(error.to_string()),
            ErrorMessage::EmptyPassword
            | ErrorMessage::HashingError
            | ErrorMessage::InvalidHashFormat
            | ErrorMessage::ExceededMaxPasswordLength(_) => HttpError::bad_request(error.to_string()),
            ErrorMessage::InvalidToken => HttpError::unauthorized(error.to_string()),
            ErrorMessage::ServerError => HttpError::server_error(error.to_string()),
        }
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HttpError: message: {}, status: {}",
            self.message, self.status
        )
    }
}

impl std::error::Error for HttpError {}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        self.into_http_response()
    }
}
