"""email_after_eof.py

This watermarking method that appends an authenticated payload *after* the
PDF's final EOF marker.

This intentionally simple scheme demonstrates the required
:class:`~watermarking_method.WatermarkingMethod` interface without
modifying PDF object structures. Most PDF readers ignore trailing bytes
beyond ``%%EOF``, so the original document remains renderable.

Security note
-------------
This method **does not encrypt** the secret; it stores it Base64-encoded
and protected with an HMAC (using the provided key) to prevent accidental
or unauthorized *verification*. Anyone who has access to the bytes can
recover the secret content, but only callers with the correct key will be
able to validate it via :meth:`read_secret`.

No third‑party libraries are required here; only the standard library is
used. (Other watermarking methods may use PyMuPDF / ``fitz``.)
"""
from __future__ import annotations

from typing import Final
import base64
import hashlib
import hmac
import json
import email
import smtplib
from email.message import EmailMessage
import re

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)
from inspect import signature as _mutmut_signature
from typing import Annotated
from typing import Callable
from typing import ClassVar


MutantDict = Annotated[dict[str, Callable], "Mutant"]


def _mutmut_trampoline(orig, mutants, call_args, call_kwargs, self_arg = None):
    """Forward call to original or mutated function, depending on the environment"""
    import os
    mutant_under_test = os.environ['MUTANT_UNDER_TEST']
    if mutant_under_test == 'fail':
        from mutmut.__main__ import MutmutProgrammaticFailException
        raise MutmutProgrammaticFailException('Failed programmatically')      
    elif mutant_under_test == 'stats':
        from mutmut.__main__ import record_trampoline_hit
        record_trampoline_hit(orig.__module__ + '.' + orig.__name__)
        result = orig(*call_args, **call_kwargs)
        return result
    prefix = orig.__module__ + '.' + orig.__name__ + '__mutmut_'
    if not mutant_under_test.startswith(prefix):
        result = orig(*call_args, **call_kwargs)
        return result
    mutant_name = mutant_under_test.rpartition('.')[-1]
    if self_arg:
        # call to a class method where self is not bound
        result = mutants[mutant_name](self_arg, *call_args, **call_kwargs)
    else:
        result = mutants[mutant_name](*call_args, **call_kwargs)
    return result

#from watermarking_utils import send_email_with_pdf

class EmailAfterEOF(WatermarkingMethod):
    """Toy method that appends a watermark record after the PDF EOF.

    Format (all ASCII/UTF‑8):

    .. code-block:: text

        <original PDF bytes ...>%%EOF\n
        %%WM-ADD-AFTER-EOF:v1\n
        <base64url(JSON payload)>\n
    The JSON payload schema (version 1):

    ``{"v":1,"alg":"HMAC-SHA256","mac":"<hex>","secret":"<b64>"}``

    The MAC is computed over ``b"wm:add-after-eof:v1:" + secret_bytes``
    using the caller-provided ``key`` (UTF‑8) and HMAC‑SHA256.
    """

    name: Final[str] = "email-eof"

    # Constants
    _MAGIC: Final[bytes] = b"\n%%WM-ADD-AFTER-EOF:v1\n"
    _CONTEXT: Final[bytes] = b"wm:add-after-eof:v1:"

    # ---------------------
    # Public API overrides
    # ---------------------
    
    @staticmethod
    def get_usage() -> str:
        return "Toy method that appends a watermark record after the PDF EOF. Position is ignored."

    def xǁEmailAfterEOFǁadd_watermark__mutmut_orig(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_1(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = None
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_2(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(None)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_3(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_4(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError(None)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_5(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("XXSecret must be a non-empty stringXX")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_6(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_7(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("SECRET MUST BE A NON-EMPTY STRING")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_8(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) and not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_9(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_10(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_11(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError(None)
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_12(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("XXKey must be a non-empty stringXX")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_13(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_14(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("KEY MUST BE A NON-EMPTY STRING")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_15(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_16(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(None):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_17(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError(None)

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_18(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("XXInvalid secretXX")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_19(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_20(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("INVALID SECRET")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_21(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = None

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_22(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(None, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_23(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, None)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_24(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_25(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, )

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_26(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = None
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_27(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_28(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(None):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_29(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"XX\nXX"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_30(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_31(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_32(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out = b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_33(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out -= b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_34(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"XX\nXX"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_35(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_36(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_37(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out = self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_38(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out -= self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_39(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload - b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_40(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC - payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_41(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"XX\nXX"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_42(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        

    def xǁEmailAfterEOFǁadd_watermark__mutmut_43(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` parameter is accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out
        
    
    xǁEmailAfterEOFǁadd_watermark__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailAfterEOFǁadd_watermark__mutmut_1': xǁEmailAfterEOFǁadd_watermark__mutmut_1, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_2': xǁEmailAfterEOFǁadd_watermark__mutmut_2, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_3': xǁEmailAfterEOFǁadd_watermark__mutmut_3, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_4': xǁEmailAfterEOFǁadd_watermark__mutmut_4, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_5': xǁEmailAfterEOFǁadd_watermark__mutmut_5, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_6': xǁEmailAfterEOFǁadd_watermark__mutmut_6, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_7': xǁEmailAfterEOFǁadd_watermark__mutmut_7, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_8': xǁEmailAfterEOFǁadd_watermark__mutmut_8, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_9': xǁEmailAfterEOFǁadd_watermark__mutmut_9, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_10': xǁEmailAfterEOFǁadd_watermark__mutmut_10, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_11': xǁEmailAfterEOFǁadd_watermark__mutmut_11, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_12': xǁEmailAfterEOFǁadd_watermark__mutmut_12, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_13': xǁEmailAfterEOFǁadd_watermark__mutmut_13, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_14': xǁEmailAfterEOFǁadd_watermark__mutmut_14, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_15': xǁEmailAfterEOFǁadd_watermark__mutmut_15, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_16': xǁEmailAfterEOFǁadd_watermark__mutmut_16, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_17': xǁEmailAfterEOFǁadd_watermark__mutmut_17, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_18': xǁEmailAfterEOFǁadd_watermark__mutmut_18, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_19': xǁEmailAfterEOFǁadd_watermark__mutmut_19, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_20': xǁEmailAfterEOFǁadd_watermark__mutmut_20, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_21': xǁEmailAfterEOFǁadd_watermark__mutmut_21, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_22': xǁEmailAfterEOFǁadd_watermark__mutmut_22, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_23': xǁEmailAfterEOFǁadd_watermark__mutmut_23, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_24': xǁEmailAfterEOFǁadd_watermark__mutmut_24, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_25': xǁEmailAfterEOFǁadd_watermark__mutmut_25, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_26': xǁEmailAfterEOFǁadd_watermark__mutmut_26, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_27': xǁEmailAfterEOFǁadd_watermark__mutmut_27, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_28': xǁEmailAfterEOFǁadd_watermark__mutmut_28, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_29': xǁEmailAfterEOFǁadd_watermark__mutmut_29, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_30': xǁEmailAfterEOFǁadd_watermark__mutmut_30, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_31': xǁEmailAfterEOFǁadd_watermark__mutmut_31, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_32': xǁEmailAfterEOFǁadd_watermark__mutmut_32, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_33': xǁEmailAfterEOFǁadd_watermark__mutmut_33, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_34': xǁEmailAfterEOFǁadd_watermark__mutmut_34, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_35': xǁEmailAfterEOFǁadd_watermark__mutmut_35, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_36': xǁEmailAfterEOFǁadd_watermark__mutmut_36, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_37': xǁEmailAfterEOFǁadd_watermark__mutmut_37, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_38': xǁEmailAfterEOFǁadd_watermark__mutmut_38, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_39': xǁEmailAfterEOFǁadd_watermark__mutmut_39, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_40': xǁEmailAfterEOFǁadd_watermark__mutmut_40, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_41': xǁEmailAfterEOFǁadd_watermark__mutmut_41, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_42': xǁEmailAfterEOFǁadd_watermark__mutmut_42, 
        'xǁEmailAfterEOFǁadd_watermark__mutmut_43': xǁEmailAfterEOFǁadd_watermark__mutmut_43
    }
    
    def add_watermark(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailAfterEOFǁadd_watermark__mutmut_orig"), object.__getattribute__(self, "xǁEmailAfterEOFǁadd_watermark__mutmut_mutants"), args, kwargs, self)
        return result 
    
    add_watermark.__signature__ = _mutmut_signature(xǁEmailAfterEOFǁadd_watermark__mutmut_orig)
    xǁEmailAfterEOFǁadd_watermark__mutmut_orig.__name__ = 'xǁEmailAfterEOFǁadd_watermark'
    def xǁEmailAfterEOFǁis_watermark_applicable__mutmut_orig(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return True
    def xǁEmailAfterEOFǁis_watermark_applicable__mutmut_1(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return False
    
    xǁEmailAfterEOFǁis_watermark_applicable__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailAfterEOFǁis_watermark_applicable__mutmut_1': xǁEmailAfterEOFǁis_watermark_applicable__mutmut_1
    }
    
    def is_watermark_applicable(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailAfterEOFǁis_watermark_applicable__mutmut_orig"), object.__getattribute__(self, "xǁEmailAfterEOFǁis_watermark_applicable__mutmut_mutants"), args, kwargs, self)
        return result 
    
    is_watermark_applicable.__signature__ = _mutmut_signature(xǁEmailAfterEOFǁis_watermark_applicable__mutmut_orig)
    xǁEmailAfterEOFǁis_watermark_applicable__mutmut_orig.__name__ = 'xǁEmailAfterEOFǁis_watermark_applicable'
    

    def xǁEmailAfterEOFǁread_secret__mutmut_orig(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_1(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = None
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_2(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(None)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_3(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) and not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_4(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_5(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_6(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError(None)

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_7(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("XXKey must be a non-empty stringXX")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_8(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_9(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("KEY MUST BE A NON-EMPTY STRING")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_10(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = None
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_11(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(None)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_12(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.find(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_13(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx != -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_14(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == +1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_15(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -2:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_16(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError(None)

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_17(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("XXNo AddAfterEOF watermark foundXX")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_18(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("no addaftereof watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_19(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("NO ADDAFTEREOF WATERMARK FOUND")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_20(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = None
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_21(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx - len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_22(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = None
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_23(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(None, start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_24(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", None)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_25(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_26(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", )
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_27(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.rfind(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_28(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"XX\nXX", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_29(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_30(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_31(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = None
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_32(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl != -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_33(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == +1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_34(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -2 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_35(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = None
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_36(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_37(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError(None)

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_38(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("XXFound marker but empty payloadXX")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_39(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_40(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("FOUND MARKER BUT EMPTY PAYLOAD")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_41(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = None
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_42(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(None)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_43(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = None
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_44(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(None)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_45(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError(None) from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_46(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("XXMalformed watermark payloadXX") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_47(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_48(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("MALFORMED WATERMARK PAYLOAD") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_49(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_50(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) or payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_51(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get(None) == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_52(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("XXvXX") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_53(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("V") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_54(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") != 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_55(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 2):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_56(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError(None)
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_57(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("XXUnsupported watermark version or formatXX")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_58(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_59(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("UNSUPPORTED WATERMARK VERSION OR FORMAT")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_60(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get(None) != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_61(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("XXalgXX") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_62(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("ALG") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_63(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") == "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_64(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "XXHMAC-SHA256XX":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_65(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "hmac-sha256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_66(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError(None)

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_67(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" / payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_68(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("XXUnsupported MAC algorithm: %rXX" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_69(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("unsupported mac algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_70(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("UNSUPPORTED MAC ALGORITHM: %R" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_71(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get(None))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_72(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("XXalgXX"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_73(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("ALG"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_74(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = None  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_75(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(None)  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_76(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["XXmacXX"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_77(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["MAC"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_78(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = None
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_79(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode(None)
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_80(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(None).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_81(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["XXsecretXX"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_82(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["SECRET"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_83(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("XXasciiXX")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_84(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ASCII")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_85(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = None
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_86(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(None)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_87(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError(None) from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_88(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("XXInvalid payload fieldsXX") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_89(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_90(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("INVALID PAYLOAD FIELDS") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_91(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = None
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_92(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(None, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_93(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, None)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_94(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_95(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, )
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_96(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_97(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(None, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_98(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, None):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_99(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_100(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, ):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_101(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError(None)

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_102(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("XXProvided key failed to authenticate the watermarkXX")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_103(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("provided key failed to authenticate the watermark")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_104(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("PROVIDED KEY FAILED TO AUTHENTICATE THE WATERMARK")

        return secret_bytes.decode("utf-8")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_105(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode(None)
    

    def xǁEmailAfterEOFǁread_secret__mutmut_106(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("XXutf-8XX")
    

    def xǁEmailAfterEOFǁread_secret__mutmut_107(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No AddAfterEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:  # broad: malformed or tampered
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        try:
            mac_hex = str(payload["mac"])  # stored as hex string
            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_bytes.decode("UTF-8")
    
    xǁEmailAfterEOFǁread_secret__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailAfterEOFǁread_secret__mutmut_1': xǁEmailAfterEOFǁread_secret__mutmut_1, 
        'xǁEmailAfterEOFǁread_secret__mutmut_2': xǁEmailAfterEOFǁread_secret__mutmut_2, 
        'xǁEmailAfterEOFǁread_secret__mutmut_3': xǁEmailAfterEOFǁread_secret__mutmut_3, 
        'xǁEmailAfterEOFǁread_secret__mutmut_4': xǁEmailAfterEOFǁread_secret__mutmut_4, 
        'xǁEmailAfterEOFǁread_secret__mutmut_5': xǁEmailAfterEOFǁread_secret__mutmut_5, 
        'xǁEmailAfterEOFǁread_secret__mutmut_6': xǁEmailAfterEOFǁread_secret__mutmut_6, 
        'xǁEmailAfterEOFǁread_secret__mutmut_7': xǁEmailAfterEOFǁread_secret__mutmut_7, 
        'xǁEmailAfterEOFǁread_secret__mutmut_8': xǁEmailAfterEOFǁread_secret__mutmut_8, 
        'xǁEmailAfterEOFǁread_secret__mutmut_9': xǁEmailAfterEOFǁread_secret__mutmut_9, 
        'xǁEmailAfterEOFǁread_secret__mutmut_10': xǁEmailAfterEOFǁread_secret__mutmut_10, 
        'xǁEmailAfterEOFǁread_secret__mutmut_11': xǁEmailAfterEOFǁread_secret__mutmut_11, 
        'xǁEmailAfterEOFǁread_secret__mutmut_12': xǁEmailAfterEOFǁread_secret__mutmut_12, 
        'xǁEmailAfterEOFǁread_secret__mutmut_13': xǁEmailAfterEOFǁread_secret__mutmut_13, 
        'xǁEmailAfterEOFǁread_secret__mutmut_14': xǁEmailAfterEOFǁread_secret__mutmut_14, 
        'xǁEmailAfterEOFǁread_secret__mutmut_15': xǁEmailAfterEOFǁread_secret__mutmut_15, 
        'xǁEmailAfterEOFǁread_secret__mutmut_16': xǁEmailAfterEOFǁread_secret__mutmut_16, 
        'xǁEmailAfterEOFǁread_secret__mutmut_17': xǁEmailAfterEOFǁread_secret__mutmut_17, 
        'xǁEmailAfterEOFǁread_secret__mutmut_18': xǁEmailAfterEOFǁread_secret__mutmut_18, 
        'xǁEmailAfterEOFǁread_secret__mutmut_19': xǁEmailAfterEOFǁread_secret__mutmut_19, 
        'xǁEmailAfterEOFǁread_secret__mutmut_20': xǁEmailAfterEOFǁread_secret__mutmut_20, 
        'xǁEmailAfterEOFǁread_secret__mutmut_21': xǁEmailAfterEOFǁread_secret__mutmut_21, 
        'xǁEmailAfterEOFǁread_secret__mutmut_22': xǁEmailAfterEOFǁread_secret__mutmut_22, 
        'xǁEmailAfterEOFǁread_secret__mutmut_23': xǁEmailAfterEOFǁread_secret__mutmut_23, 
        'xǁEmailAfterEOFǁread_secret__mutmut_24': xǁEmailAfterEOFǁread_secret__mutmut_24, 
        'xǁEmailAfterEOFǁread_secret__mutmut_25': xǁEmailAfterEOFǁread_secret__mutmut_25, 
        'xǁEmailAfterEOFǁread_secret__mutmut_26': xǁEmailAfterEOFǁread_secret__mutmut_26, 
        'xǁEmailAfterEOFǁread_secret__mutmut_27': xǁEmailAfterEOFǁread_secret__mutmut_27, 
        'xǁEmailAfterEOFǁread_secret__mutmut_28': xǁEmailAfterEOFǁread_secret__mutmut_28, 
        'xǁEmailAfterEOFǁread_secret__mutmut_29': xǁEmailAfterEOFǁread_secret__mutmut_29, 
        'xǁEmailAfterEOFǁread_secret__mutmut_30': xǁEmailAfterEOFǁread_secret__mutmut_30, 
        'xǁEmailAfterEOFǁread_secret__mutmut_31': xǁEmailAfterEOFǁread_secret__mutmut_31, 
        'xǁEmailAfterEOFǁread_secret__mutmut_32': xǁEmailAfterEOFǁread_secret__mutmut_32, 
        'xǁEmailAfterEOFǁread_secret__mutmut_33': xǁEmailAfterEOFǁread_secret__mutmut_33, 
        'xǁEmailAfterEOFǁread_secret__mutmut_34': xǁEmailAfterEOFǁread_secret__mutmut_34, 
        'xǁEmailAfterEOFǁread_secret__mutmut_35': xǁEmailAfterEOFǁread_secret__mutmut_35, 
        'xǁEmailAfterEOFǁread_secret__mutmut_36': xǁEmailAfterEOFǁread_secret__mutmut_36, 
        'xǁEmailAfterEOFǁread_secret__mutmut_37': xǁEmailAfterEOFǁread_secret__mutmut_37, 
        'xǁEmailAfterEOFǁread_secret__mutmut_38': xǁEmailAfterEOFǁread_secret__mutmut_38, 
        'xǁEmailAfterEOFǁread_secret__mutmut_39': xǁEmailAfterEOFǁread_secret__mutmut_39, 
        'xǁEmailAfterEOFǁread_secret__mutmut_40': xǁEmailAfterEOFǁread_secret__mutmut_40, 
        'xǁEmailAfterEOFǁread_secret__mutmut_41': xǁEmailAfterEOFǁread_secret__mutmut_41, 
        'xǁEmailAfterEOFǁread_secret__mutmut_42': xǁEmailAfterEOFǁread_secret__mutmut_42, 
        'xǁEmailAfterEOFǁread_secret__mutmut_43': xǁEmailAfterEOFǁread_secret__mutmut_43, 
        'xǁEmailAfterEOFǁread_secret__mutmut_44': xǁEmailAfterEOFǁread_secret__mutmut_44, 
        'xǁEmailAfterEOFǁread_secret__mutmut_45': xǁEmailAfterEOFǁread_secret__mutmut_45, 
        'xǁEmailAfterEOFǁread_secret__mutmut_46': xǁEmailAfterEOFǁread_secret__mutmut_46, 
        'xǁEmailAfterEOFǁread_secret__mutmut_47': xǁEmailAfterEOFǁread_secret__mutmut_47, 
        'xǁEmailAfterEOFǁread_secret__mutmut_48': xǁEmailAfterEOFǁread_secret__mutmut_48, 
        'xǁEmailAfterEOFǁread_secret__mutmut_49': xǁEmailAfterEOFǁread_secret__mutmut_49, 
        'xǁEmailAfterEOFǁread_secret__mutmut_50': xǁEmailAfterEOFǁread_secret__mutmut_50, 
        'xǁEmailAfterEOFǁread_secret__mutmut_51': xǁEmailAfterEOFǁread_secret__mutmut_51, 
        'xǁEmailAfterEOFǁread_secret__mutmut_52': xǁEmailAfterEOFǁread_secret__mutmut_52, 
        'xǁEmailAfterEOFǁread_secret__mutmut_53': xǁEmailAfterEOFǁread_secret__mutmut_53, 
        'xǁEmailAfterEOFǁread_secret__mutmut_54': xǁEmailAfterEOFǁread_secret__mutmut_54, 
        'xǁEmailAfterEOFǁread_secret__mutmut_55': xǁEmailAfterEOFǁread_secret__mutmut_55, 
        'xǁEmailAfterEOFǁread_secret__mutmut_56': xǁEmailAfterEOFǁread_secret__mutmut_56, 
        'xǁEmailAfterEOFǁread_secret__mutmut_57': xǁEmailAfterEOFǁread_secret__mutmut_57, 
        'xǁEmailAfterEOFǁread_secret__mutmut_58': xǁEmailAfterEOFǁread_secret__mutmut_58, 
        'xǁEmailAfterEOFǁread_secret__mutmut_59': xǁEmailAfterEOFǁread_secret__mutmut_59, 
        'xǁEmailAfterEOFǁread_secret__mutmut_60': xǁEmailAfterEOFǁread_secret__mutmut_60, 
        'xǁEmailAfterEOFǁread_secret__mutmut_61': xǁEmailAfterEOFǁread_secret__mutmut_61, 
        'xǁEmailAfterEOFǁread_secret__mutmut_62': xǁEmailAfterEOFǁread_secret__mutmut_62, 
        'xǁEmailAfterEOFǁread_secret__mutmut_63': xǁEmailAfterEOFǁread_secret__mutmut_63, 
        'xǁEmailAfterEOFǁread_secret__mutmut_64': xǁEmailAfterEOFǁread_secret__mutmut_64, 
        'xǁEmailAfterEOFǁread_secret__mutmut_65': xǁEmailAfterEOFǁread_secret__mutmut_65, 
        'xǁEmailAfterEOFǁread_secret__mutmut_66': xǁEmailAfterEOFǁread_secret__mutmut_66, 
        'xǁEmailAfterEOFǁread_secret__mutmut_67': xǁEmailAfterEOFǁread_secret__mutmut_67, 
        'xǁEmailAfterEOFǁread_secret__mutmut_68': xǁEmailAfterEOFǁread_secret__mutmut_68, 
        'xǁEmailAfterEOFǁread_secret__mutmut_69': xǁEmailAfterEOFǁread_secret__mutmut_69, 
        'xǁEmailAfterEOFǁread_secret__mutmut_70': xǁEmailAfterEOFǁread_secret__mutmut_70, 
        'xǁEmailAfterEOFǁread_secret__mutmut_71': xǁEmailAfterEOFǁread_secret__mutmut_71, 
        'xǁEmailAfterEOFǁread_secret__mutmut_72': xǁEmailAfterEOFǁread_secret__mutmut_72, 
        'xǁEmailAfterEOFǁread_secret__mutmut_73': xǁEmailAfterEOFǁread_secret__mutmut_73, 
        'xǁEmailAfterEOFǁread_secret__mutmut_74': xǁEmailAfterEOFǁread_secret__mutmut_74, 
        'xǁEmailAfterEOFǁread_secret__mutmut_75': xǁEmailAfterEOFǁread_secret__mutmut_75, 
        'xǁEmailAfterEOFǁread_secret__mutmut_76': xǁEmailAfterEOFǁread_secret__mutmut_76, 
        'xǁEmailAfterEOFǁread_secret__mutmut_77': xǁEmailAfterEOFǁread_secret__mutmut_77, 
        'xǁEmailAfterEOFǁread_secret__mutmut_78': xǁEmailAfterEOFǁread_secret__mutmut_78, 
        'xǁEmailAfterEOFǁread_secret__mutmut_79': xǁEmailAfterEOFǁread_secret__mutmut_79, 
        'xǁEmailAfterEOFǁread_secret__mutmut_80': xǁEmailAfterEOFǁread_secret__mutmut_80, 
        'xǁEmailAfterEOFǁread_secret__mutmut_81': xǁEmailAfterEOFǁread_secret__mutmut_81, 
        'xǁEmailAfterEOFǁread_secret__mutmut_82': xǁEmailAfterEOFǁread_secret__mutmut_82, 
        'xǁEmailAfterEOFǁread_secret__mutmut_83': xǁEmailAfterEOFǁread_secret__mutmut_83, 
        'xǁEmailAfterEOFǁread_secret__mutmut_84': xǁEmailAfterEOFǁread_secret__mutmut_84, 
        'xǁEmailAfterEOFǁread_secret__mutmut_85': xǁEmailAfterEOFǁread_secret__mutmut_85, 
        'xǁEmailAfterEOFǁread_secret__mutmut_86': xǁEmailAfterEOFǁread_secret__mutmut_86, 
        'xǁEmailAfterEOFǁread_secret__mutmut_87': xǁEmailAfterEOFǁread_secret__mutmut_87, 
        'xǁEmailAfterEOFǁread_secret__mutmut_88': xǁEmailAfterEOFǁread_secret__mutmut_88, 
        'xǁEmailAfterEOFǁread_secret__mutmut_89': xǁEmailAfterEOFǁread_secret__mutmut_89, 
        'xǁEmailAfterEOFǁread_secret__mutmut_90': xǁEmailAfterEOFǁread_secret__mutmut_90, 
        'xǁEmailAfterEOFǁread_secret__mutmut_91': xǁEmailAfterEOFǁread_secret__mutmut_91, 
        'xǁEmailAfterEOFǁread_secret__mutmut_92': xǁEmailAfterEOFǁread_secret__mutmut_92, 
        'xǁEmailAfterEOFǁread_secret__mutmut_93': xǁEmailAfterEOFǁread_secret__mutmut_93, 
        'xǁEmailAfterEOFǁread_secret__mutmut_94': xǁEmailAfterEOFǁread_secret__mutmut_94, 
        'xǁEmailAfterEOFǁread_secret__mutmut_95': xǁEmailAfterEOFǁread_secret__mutmut_95, 
        'xǁEmailAfterEOFǁread_secret__mutmut_96': xǁEmailAfterEOFǁread_secret__mutmut_96, 
        'xǁEmailAfterEOFǁread_secret__mutmut_97': xǁEmailAfterEOFǁread_secret__mutmut_97, 
        'xǁEmailAfterEOFǁread_secret__mutmut_98': xǁEmailAfterEOFǁread_secret__mutmut_98, 
        'xǁEmailAfterEOFǁread_secret__mutmut_99': xǁEmailAfterEOFǁread_secret__mutmut_99, 
        'xǁEmailAfterEOFǁread_secret__mutmut_100': xǁEmailAfterEOFǁread_secret__mutmut_100, 
        'xǁEmailAfterEOFǁread_secret__mutmut_101': xǁEmailAfterEOFǁread_secret__mutmut_101, 
        'xǁEmailAfterEOFǁread_secret__mutmut_102': xǁEmailAfterEOFǁread_secret__mutmut_102, 
        'xǁEmailAfterEOFǁread_secret__mutmut_103': xǁEmailAfterEOFǁread_secret__mutmut_103, 
        'xǁEmailAfterEOFǁread_secret__mutmut_104': xǁEmailAfterEOFǁread_secret__mutmut_104, 
        'xǁEmailAfterEOFǁread_secret__mutmut_105': xǁEmailAfterEOFǁread_secret__mutmut_105, 
        'xǁEmailAfterEOFǁread_secret__mutmut_106': xǁEmailAfterEOFǁread_secret__mutmut_106, 
        'xǁEmailAfterEOFǁread_secret__mutmut_107': xǁEmailAfterEOFǁread_secret__mutmut_107
    }
    
    def read_secret(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailAfterEOFǁread_secret__mutmut_orig"), object.__getattribute__(self, "xǁEmailAfterEOFǁread_secret__mutmut_mutants"), args, kwargs, self)
        return result 
    
    read_secret.__signature__ = _mutmut_signature(xǁEmailAfterEOFǁread_secret__mutmut_orig)
    xǁEmailAfterEOFǁread_secret__mutmut_orig.__name__ = 'xǁEmailAfterEOFǁread_secret'

    def xǁEmailAfterEOFǁis_email__mutmut_orig(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern,s) is not None

    def xǁEmailAfterEOFǁis_email__mutmut_1(self,s: str) -> bool:
        # sample regex for email validation
        pattern = None
        return re.match(pattern,s) is not None

    def xǁEmailAfterEOFǁis_email__mutmut_2(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'XX^[\w\.-]+@[\w\.-]+\.\w+$XX'
        return re.match(pattern,s) is not None

    def xǁEmailAfterEOFǁis_email__mutmut_3(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern,s) is not None

    def xǁEmailAfterEOFǁis_email__mutmut_4(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern,s) is not None

    def xǁEmailAfterEOFǁis_email__mutmut_5(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(None,s) is not None

    def xǁEmailAfterEOFǁis_email__mutmut_6(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern,None) is not None

    def xǁEmailAfterEOFǁis_email__mutmut_7(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(s) is not None

    def xǁEmailAfterEOFǁis_email__mutmut_8(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern,) is not None

    def xǁEmailAfterEOFǁis_email__mutmut_9(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern,s) is None
    
    xǁEmailAfterEOFǁis_email__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailAfterEOFǁis_email__mutmut_1': xǁEmailAfterEOFǁis_email__mutmut_1, 
        'xǁEmailAfterEOFǁis_email__mutmut_2': xǁEmailAfterEOFǁis_email__mutmut_2, 
        'xǁEmailAfterEOFǁis_email__mutmut_3': xǁEmailAfterEOFǁis_email__mutmut_3, 
        'xǁEmailAfterEOFǁis_email__mutmut_4': xǁEmailAfterEOFǁis_email__mutmut_4, 
        'xǁEmailAfterEOFǁis_email__mutmut_5': xǁEmailAfterEOFǁis_email__mutmut_5, 
        'xǁEmailAfterEOFǁis_email__mutmut_6': xǁEmailAfterEOFǁis_email__mutmut_6, 
        'xǁEmailAfterEOFǁis_email__mutmut_7': xǁEmailAfterEOFǁis_email__mutmut_7, 
        'xǁEmailAfterEOFǁis_email__mutmut_8': xǁEmailAfterEOFǁis_email__mutmut_8, 
        'xǁEmailAfterEOFǁis_email__mutmut_9': xǁEmailAfterEOFǁis_email__mutmut_9
    }
    
    def is_email(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailAfterEOFǁis_email__mutmut_orig"), object.__getattribute__(self, "xǁEmailAfterEOFǁis_email__mutmut_mutants"), args, kwargs, self)
        return result 
    
    is_email.__signature__ = _mutmut_signature(xǁEmailAfterEOFǁis_email__mutmut_orig)
    xǁEmailAfterEOFǁis_email__mutmut_orig.__name__ = 'xǁEmailAfterEOFǁis_email'

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_orig(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_1(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = None
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_2(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(None)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_3(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = None
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_4(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret - secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_5(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print(None,final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_6(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",None)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_7(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print(final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_8(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_9(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("XXfinal secret :XX",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_10(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("FINAL SECRET :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_11(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = None
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_12(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode(None)
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_13(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("XXutf-8XX")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_14(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("UTF-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_15(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = None
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_16(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(None, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_17(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, None)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_18(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_19(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, )
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_20(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = None
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_21(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "XXvXX": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_22(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "V": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_23(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 2,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_24(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "XXalgXX": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_25(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "ALG": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_26(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "XXHMAC-SHA256XX",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_27(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "hmac-sha256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_28(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "XXmacXX": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_29(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "MAC": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_30(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "XXsecretXX": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_31(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "SECRET": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_32(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode(None),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_33(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(None).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_34(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("XXasciiXX"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_35(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ASCII"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_36(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = None
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_37(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode(None)
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_38(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(None, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_39(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=None, ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_40(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=None).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_41(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_42(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_43(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_44(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=("XX,XX", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_45(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", "XX:XX"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_46(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_47(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("XXutf-8XX")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_48(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("UTF-8")
        return base64.urlsafe_b64encode(j)

    # Internal helpers
    # ---------------------

    def xǁEmailAfterEOFǁ_build_payload__mutmut_49(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""

#        from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract
        print("final secret :",final_secret)

#        store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(None)
    
    xǁEmailAfterEOFǁ_build_payload__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailAfterEOFǁ_build_payload__mutmut_1': xǁEmailAfterEOFǁ_build_payload__mutmut_1, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_2': xǁEmailAfterEOFǁ_build_payload__mutmut_2, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_3': xǁEmailAfterEOFǁ_build_payload__mutmut_3, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_4': xǁEmailAfterEOFǁ_build_payload__mutmut_4, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_5': xǁEmailAfterEOFǁ_build_payload__mutmut_5, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_6': xǁEmailAfterEOFǁ_build_payload__mutmut_6, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_7': xǁEmailAfterEOFǁ_build_payload__mutmut_7, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_8': xǁEmailAfterEOFǁ_build_payload__mutmut_8, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_9': xǁEmailAfterEOFǁ_build_payload__mutmut_9, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_10': xǁEmailAfterEOFǁ_build_payload__mutmut_10, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_11': xǁEmailAfterEOFǁ_build_payload__mutmut_11, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_12': xǁEmailAfterEOFǁ_build_payload__mutmut_12, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_13': xǁEmailAfterEOFǁ_build_payload__mutmut_13, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_14': xǁEmailAfterEOFǁ_build_payload__mutmut_14, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_15': xǁEmailAfterEOFǁ_build_payload__mutmut_15, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_16': xǁEmailAfterEOFǁ_build_payload__mutmut_16, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_17': xǁEmailAfterEOFǁ_build_payload__mutmut_17, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_18': xǁEmailAfterEOFǁ_build_payload__mutmut_18, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_19': xǁEmailAfterEOFǁ_build_payload__mutmut_19, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_20': xǁEmailAfterEOFǁ_build_payload__mutmut_20, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_21': xǁEmailAfterEOFǁ_build_payload__mutmut_21, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_22': xǁEmailAfterEOFǁ_build_payload__mutmut_22, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_23': xǁEmailAfterEOFǁ_build_payload__mutmut_23, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_24': xǁEmailAfterEOFǁ_build_payload__mutmut_24, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_25': xǁEmailAfterEOFǁ_build_payload__mutmut_25, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_26': xǁEmailAfterEOFǁ_build_payload__mutmut_26, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_27': xǁEmailAfterEOFǁ_build_payload__mutmut_27, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_28': xǁEmailAfterEOFǁ_build_payload__mutmut_28, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_29': xǁEmailAfterEOFǁ_build_payload__mutmut_29, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_30': xǁEmailAfterEOFǁ_build_payload__mutmut_30, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_31': xǁEmailAfterEOFǁ_build_payload__mutmut_31, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_32': xǁEmailAfterEOFǁ_build_payload__mutmut_32, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_33': xǁEmailAfterEOFǁ_build_payload__mutmut_33, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_34': xǁEmailAfterEOFǁ_build_payload__mutmut_34, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_35': xǁEmailAfterEOFǁ_build_payload__mutmut_35, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_36': xǁEmailAfterEOFǁ_build_payload__mutmut_36, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_37': xǁEmailAfterEOFǁ_build_payload__mutmut_37, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_38': xǁEmailAfterEOFǁ_build_payload__mutmut_38, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_39': xǁEmailAfterEOFǁ_build_payload__mutmut_39, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_40': xǁEmailAfterEOFǁ_build_payload__mutmut_40, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_41': xǁEmailAfterEOFǁ_build_payload__mutmut_41, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_42': xǁEmailAfterEOFǁ_build_payload__mutmut_42, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_43': xǁEmailAfterEOFǁ_build_payload__mutmut_43, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_44': xǁEmailAfterEOFǁ_build_payload__mutmut_44, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_45': xǁEmailAfterEOFǁ_build_payload__mutmut_45, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_46': xǁEmailAfterEOFǁ_build_payload__mutmut_46, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_47': xǁEmailAfterEOFǁ_build_payload__mutmut_47, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_48': xǁEmailAfterEOFǁ_build_payload__mutmut_48, 
        'xǁEmailAfterEOFǁ_build_payload__mutmut_49': xǁEmailAfterEOFǁ_build_payload__mutmut_49
    }
    
    def _build_payload(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailAfterEOFǁ_build_payload__mutmut_orig"), object.__getattribute__(self, "xǁEmailAfterEOFǁ_build_payload__mutmut_mutants"), args, kwargs, self)
        return result 
    
    _build_payload.__signature__ = _mutmut_signature(xǁEmailAfterEOFǁ_build_payload__mutmut_orig)
    xǁEmailAfterEOFǁ_build_payload__mutmut_orig.__name__ = 'xǁEmailAfterEOFǁ_build_payload'

    def xǁEmailAfterEOFǁ_mac_hex__mutmut_orig(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailAfterEOFǁ_mac_hex__mutmut_1(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = None
        return hm.hexdigest()

    def xǁEmailAfterEOFǁ_mac_hex__mutmut_2(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(None, self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailAfterEOFǁ_mac_hex__mutmut_3(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), None, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailAfterEOFǁ_mac_hex__mutmut_4(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT + secret_bytes, None)
        return hm.hexdigest()

    def xǁEmailAfterEOFǁ_mac_hex__mutmut_5(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailAfterEOFǁ_mac_hex__mutmut_6(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailAfterEOFǁ_mac_hex__mutmut_7(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT + secret_bytes, )
        return hm.hexdigest()

    def xǁEmailAfterEOFǁ_mac_hex__mutmut_8(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode(None), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailAfterEOFǁ_mac_hex__mutmut_9(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("XXutf-8XX"), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailAfterEOFǁ_mac_hex__mutmut_10(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("UTF-8"), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailAfterEOFǁ_mac_hex__mutmut_11(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT - secret_bytes, hashlib.sha256)
        return hm.hexdigest()
    
    xǁEmailAfterEOFǁ_mac_hex__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailAfterEOFǁ_mac_hex__mutmut_1': xǁEmailAfterEOFǁ_mac_hex__mutmut_1, 
        'xǁEmailAfterEOFǁ_mac_hex__mutmut_2': xǁEmailAfterEOFǁ_mac_hex__mutmut_2, 
        'xǁEmailAfterEOFǁ_mac_hex__mutmut_3': xǁEmailAfterEOFǁ_mac_hex__mutmut_3, 
        'xǁEmailAfterEOFǁ_mac_hex__mutmut_4': xǁEmailAfterEOFǁ_mac_hex__mutmut_4, 
        'xǁEmailAfterEOFǁ_mac_hex__mutmut_5': xǁEmailAfterEOFǁ_mac_hex__mutmut_5, 
        'xǁEmailAfterEOFǁ_mac_hex__mutmut_6': xǁEmailAfterEOFǁ_mac_hex__mutmut_6, 
        'xǁEmailAfterEOFǁ_mac_hex__mutmut_7': xǁEmailAfterEOFǁ_mac_hex__mutmut_7, 
        'xǁEmailAfterEOFǁ_mac_hex__mutmut_8': xǁEmailAfterEOFǁ_mac_hex__mutmut_8, 
        'xǁEmailAfterEOFǁ_mac_hex__mutmut_9': xǁEmailAfterEOFǁ_mac_hex__mutmut_9, 
        'xǁEmailAfterEOFǁ_mac_hex__mutmut_10': xǁEmailAfterEOFǁ_mac_hex__mutmut_10, 
        'xǁEmailAfterEOFǁ_mac_hex__mutmut_11': xǁEmailAfterEOFǁ_mac_hex__mutmut_11
    }
    
    def _mac_hex(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailAfterEOFǁ_mac_hex__mutmut_orig"), object.__getattribute__(self, "xǁEmailAfterEOFǁ_mac_hex__mutmut_mutants"), args, kwargs, self)
        return result 
    
    _mac_hex.__signature__ = _mutmut_signature(xǁEmailAfterEOFǁ_mac_hex__mutmut_orig)
    xǁEmailAfterEOFǁ_mac_hex__mutmut_orig.__name__ = 'xǁEmailAfterEOFǁ_mac_hex'
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_orig(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_1(self, secret) -> str:

        # Split email into local and domain
        local, domain = None
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_2(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split(None, 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_3(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", None)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_4(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split(1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_5(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", )
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_6(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.rsplit("@", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_7(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("XX@XX", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_8(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", 2)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_9(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = None

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_10(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(None)[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_11(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split("XX.XX")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_12(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[1]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_13(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = None

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_14(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:3]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_15(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = None

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_16(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[+2:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_17(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-3:]

        # Concatenate
        result = first_two + last_two
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_18(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = None
        return result
    
    def xǁEmailAfterEOFǁextract_email_parts__mutmut_19(self, secret) -> str:

        # Split email into local and domain
        local, domain = secret.split("@", 1)
        
        # Take only the first part of the domain (before first dot)
        domain_name = domain.split(".")[0]

        # Extract first 2 characters of local part
        first_two = local[:2]

        # Extract last 2 characters of domain_name
        last_two = domain_name[-2:]

        # Concatenate
        result = first_two - last_two
        return result
    
    xǁEmailAfterEOFǁextract_email_parts__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailAfterEOFǁextract_email_parts__mutmut_1': xǁEmailAfterEOFǁextract_email_parts__mutmut_1, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_2': xǁEmailAfterEOFǁextract_email_parts__mutmut_2, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_3': xǁEmailAfterEOFǁextract_email_parts__mutmut_3, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_4': xǁEmailAfterEOFǁextract_email_parts__mutmut_4, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_5': xǁEmailAfterEOFǁextract_email_parts__mutmut_5, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_6': xǁEmailAfterEOFǁextract_email_parts__mutmut_6, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_7': xǁEmailAfterEOFǁextract_email_parts__mutmut_7, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_8': xǁEmailAfterEOFǁextract_email_parts__mutmut_8, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_9': xǁEmailAfterEOFǁextract_email_parts__mutmut_9, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_10': xǁEmailAfterEOFǁextract_email_parts__mutmut_10, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_11': xǁEmailAfterEOFǁextract_email_parts__mutmut_11, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_12': xǁEmailAfterEOFǁextract_email_parts__mutmut_12, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_13': xǁEmailAfterEOFǁextract_email_parts__mutmut_13, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_14': xǁEmailAfterEOFǁextract_email_parts__mutmut_14, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_15': xǁEmailAfterEOFǁextract_email_parts__mutmut_15, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_16': xǁEmailAfterEOFǁextract_email_parts__mutmut_16, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_17': xǁEmailAfterEOFǁextract_email_parts__mutmut_17, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_18': xǁEmailAfterEOFǁextract_email_parts__mutmut_18, 
        'xǁEmailAfterEOFǁextract_email_parts__mutmut_19': xǁEmailAfterEOFǁextract_email_parts__mutmut_19
    }
    
    def extract_email_parts(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailAfterEOFǁextract_email_parts__mutmut_orig"), object.__getattribute__(self, "xǁEmailAfterEOFǁextract_email_parts__mutmut_mutants"), args, kwargs, self)
        return result 
    
    extract_email_parts.__signature__ = _mutmut_signature(xǁEmailAfterEOFǁextract_email_parts__mutmut_orig)
    xǁEmailAfterEOFǁextract_email_parts__mutmut_orig.__name__ = 'xǁEmailAfterEOFǁextract_email_parts'

__all__ = ["AddAfterEOF"]

