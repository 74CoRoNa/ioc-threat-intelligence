import logging
import re


_SECRET_PATTERNS = (
    re.compile(
        r"(?i)(authorization)(\s*[:=]\s*)(?:bearer\s+)?([^\s,;]+)"
    ),
    re.compile(r"(?i)(x-apikey|api[_-]?key|auth[_-]?key)(\s*[:=]\s*)([^\s,;]+)"),
    re.compile(r"(?i)(bearer\s+)([a-z0-9._~+/=-]{8,})"),
)


class SecretRedactionFilter(logging.Filter):
    """Remove likely API credentials from formatted log messages."""

    @staticmethod
    def _redact(value: str) -> str:
        redacted = value
        for pattern in _SECRET_PATTERNS:
            redacted = pattern.sub(lambda match: f"{match.group(1)}{match.group(2) if match.lastindex and match.lastindex >= 3 else ''}[REDACTED]", redacted)
        return redacted

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._redact(record.getMessage())
        record.args = ()
        return True


def configure_logging() -> None:
    """Configure a concise application logger with credential redaction."""

    handler = logging.StreamHandler()
    handler.addFilter(SecretRedactionFilter())
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )

    logger = logging.getLogger("cyberip")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
