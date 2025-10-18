import logging
import os
from datetime import datetime
from flask import request

class SecurityLogger:
    def __init__(self):
        # Default directory (for Docker) and fallback (for local tests)
        default_dir = "/app/logs"
        fallback_dir = "./logs"

        # Try Docker path first; if permission denied, fall back safely
        try:
            os.makedirs(default_dir, exist_ok=True)
            log_dir = default_dir
        except PermissionError:
            log_dir = fallback_dir
            os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(log_dir, "security.log")

        # Setup logger
        self.logger = logging.getLogger("security")
        self.logger.setLevel(logging.INFO)

        # Avoid duplicate handlers (important in tests)
        if not self.logger.handlers:
            fh = logging.FileHandler(log_file)
            formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)

    def log_event(self, event_type, user_info, details, success=True):
        """Enhanced logging with structured data"""
        status = "SUCCESS" if success else "FAILED"
        ip = getattr(request, "remote_addr", "unknown")
        message = f"{event_type} | User:{user_info} | IP:{ip} | {details} | Status:{status}"

        if not success:
            self.logger.warning(f"SECURITY_ALERT - {message}")
        else:
            self.logger.info(message)


# Global instance
security_logger = SecurityLogger()

def log_success(message):
    security_logger.log_event("SUCCESS", "system", message, True)

def log_failure(message):
    security_logger.log_event("FAILURE", "system", message, False)

def log_event(message):
    # Simple auto-detection as fallback
    if any(word in message.upper() for word in ["FAILED", "ERROR", "UNAUTHORIZED"]):
        log_failure(message)
    else:
        log_success(message)
