from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class AppError(Exception):
    """Base class for expected errors exposed through the API."""

    status_code = 500
    code = "internal_error"
    default_message = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        details: Any = None,
    ) -> None:
        super().__init__(message or self.default_message)
        self.message = message or self.default_message
        self.details = details


class ValidationError(AppError):
    status_code = 422
    code = "validation_error"
    default_message = "The supplied input is invalid."


class UpstreamUnavailable(AppError):
    status_code = 503
    code = "upstream_unavailable"
    default_message = "An external service is unavailable."


class NotConfigured(AppError):
    status_code = 503
    code = "not_configured"
    default_message = "API key not configured."


class NotFound(AppError):
    status_code = 404
    code = "not_found"
    default_message = "The requested resource was not found."


def register_exception_handlers(app: FastAPI) -> None:
    """Register the shared JSON error envelope for expected failures."""

    @app.exception_handler(AppError)
    async def handle_app_error(_: Request, error: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content={
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                }
            },
        )

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation(
        _: Request,
        error: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "The supplied input is invalid.",
                    "details": error.errors(),
                }
            },
        )
