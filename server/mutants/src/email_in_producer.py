"""email_in_producer.py

This watermarking method that appends an authenticated payload in the file header.

This intentionally simple scheme demonstrates the required
:class:`~watermarking_method.WatermarkingMethod` interface without
modifying PDF object structures. Most PDF readers ignore file header, so the original document remains renderable.

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
import pikepdf
import os
from pathlib import Path

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

class EmailInProducer(WatermarkingMethod):
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

    name: Final[str] = "email-producer"

    # Constants
    _MAGIC: Final[bytes] = b"\n%%WM-ADD-AFTER-EOF:v1\n"
    _CONTEXT: Final[bytes] = b"wm:add-after-eof:v1:"

    # ---------------------
    # Public API overrides
    # ---------------------
    
    @staticmethod
    def get_usage() -> str:
        return "Toy method that appends a watermark record after the PDF EOF. Position is ignored."

    def xǁEmailInProducerǁadd_watermark__mutmut_orig(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_1(
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
        #data = load_pdf_bytes(pdf)
        if secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_2(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError(None)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_3(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("XXSecret must be a non-empty stringXX")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_4(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_5(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("SECRET MUST BE A NON-EMPTY STRING")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_6(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) and not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_7(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_8(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_9(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError(None)
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_10(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("XXKey must be a non-empty stringXX")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_11(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_12(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("KEY MUST BE A NON-EMPTY STRING")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_13(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_14(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(None):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_15(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError(None)

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_16(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("XXInvalid secretXX")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_17(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_18(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("INVALID SECRET")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_19(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = None

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_20(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(None, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_21(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, None)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_22(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_23(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, )

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_24(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(None, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_25(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=None) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_26(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_27(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, ) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_28(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=False) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_29(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = None
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_30(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["XX/ProducerXX"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_31(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_32(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/PRODUCER"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_33(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(None)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_34(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = None
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_35(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(None)
        out = data
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        

    def xǁEmailInProducerǁadd_watermark__mutmut_36(
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
        #data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        if not self.is_email(secret):
            raise ValueError("Invalid secret")

        payload = self._build_payload(secret, key)

        with pikepdf.open(pdf, allow_overwriting_input=True) as input_pdf:
        # Asign the payload in the document header
            input_pdf.docinfo["/Producer"] = payload
            input_pdf.save(pdf)
        # Append after the last EOF marker; if none is found (rare in
        # malformed PDFs), we still append at the end, since most parsers
        # will stop at the first '%%EOF' they encounter.
        # We do not alter the original bytes to preserve determinism and
        # avoid invalidating existing xref tables.
        data = load_pdf_bytes(pdf)
        out = None
        #if not out.endswith(b"\n"):
         #   out += b"\n"
        #out += self._MAGIC + payload + b"\n"
        #self.send_email_with_pdf("kumarrakeshsingh2003@gmail.com","ases ydct ehgs rtod",secret,"your version of pdf","please find the pdf",".\output.pdf")    
        return out
        
    
    xǁEmailInProducerǁadd_watermark__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailInProducerǁadd_watermark__mutmut_1': xǁEmailInProducerǁadd_watermark__mutmut_1, 
        'xǁEmailInProducerǁadd_watermark__mutmut_2': xǁEmailInProducerǁadd_watermark__mutmut_2, 
        'xǁEmailInProducerǁadd_watermark__mutmut_3': xǁEmailInProducerǁadd_watermark__mutmut_3, 
        'xǁEmailInProducerǁadd_watermark__mutmut_4': xǁEmailInProducerǁadd_watermark__mutmut_4, 
        'xǁEmailInProducerǁadd_watermark__mutmut_5': xǁEmailInProducerǁadd_watermark__mutmut_5, 
        'xǁEmailInProducerǁadd_watermark__mutmut_6': xǁEmailInProducerǁadd_watermark__mutmut_6, 
        'xǁEmailInProducerǁadd_watermark__mutmut_7': xǁEmailInProducerǁadd_watermark__mutmut_7, 
        'xǁEmailInProducerǁadd_watermark__mutmut_8': xǁEmailInProducerǁadd_watermark__mutmut_8, 
        'xǁEmailInProducerǁadd_watermark__mutmut_9': xǁEmailInProducerǁadd_watermark__mutmut_9, 
        'xǁEmailInProducerǁadd_watermark__mutmut_10': xǁEmailInProducerǁadd_watermark__mutmut_10, 
        'xǁEmailInProducerǁadd_watermark__mutmut_11': xǁEmailInProducerǁadd_watermark__mutmut_11, 
        'xǁEmailInProducerǁadd_watermark__mutmut_12': xǁEmailInProducerǁadd_watermark__mutmut_12, 
        'xǁEmailInProducerǁadd_watermark__mutmut_13': xǁEmailInProducerǁadd_watermark__mutmut_13, 
        'xǁEmailInProducerǁadd_watermark__mutmut_14': xǁEmailInProducerǁadd_watermark__mutmut_14, 
        'xǁEmailInProducerǁadd_watermark__mutmut_15': xǁEmailInProducerǁadd_watermark__mutmut_15, 
        'xǁEmailInProducerǁadd_watermark__mutmut_16': xǁEmailInProducerǁadd_watermark__mutmut_16, 
        'xǁEmailInProducerǁadd_watermark__mutmut_17': xǁEmailInProducerǁadd_watermark__mutmut_17, 
        'xǁEmailInProducerǁadd_watermark__mutmut_18': xǁEmailInProducerǁadd_watermark__mutmut_18, 
        'xǁEmailInProducerǁadd_watermark__mutmut_19': xǁEmailInProducerǁadd_watermark__mutmut_19, 
        'xǁEmailInProducerǁadd_watermark__mutmut_20': xǁEmailInProducerǁadd_watermark__mutmut_20, 
        'xǁEmailInProducerǁadd_watermark__mutmut_21': xǁEmailInProducerǁadd_watermark__mutmut_21, 
        'xǁEmailInProducerǁadd_watermark__mutmut_22': xǁEmailInProducerǁadd_watermark__mutmut_22, 
        'xǁEmailInProducerǁadd_watermark__mutmut_23': xǁEmailInProducerǁadd_watermark__mutmut_23, 
        'xǁEmailInProducerǁadd_watermark__mutmut_24': xǁEmailInProducerǁadd_watermark__mutmut_24, 
        'xǁEmailInProducerǁadd_watermark__mutmut_25': xǁEmailInProducerǁadd_watermark__mutmut_25, 
        'xǁEmailInProducerǁadd_watermark__mutmut_26': xǁEmailInProducerǁadd_watermark__mutmut_26, 
        'xǁEmailInProducerǁadd_watermark__mutmut_27': xǁEmailInProducerǁadd_watermark__mutmut_27, 
        'xǁEmailInProducerǁadd_watermark__mutmut_28': xǁEmailInProducerǁadd_watermark__mutmut_28, 
        'xǁEmailInProducerǁadd_watermark__mutmut_29': xǁEmailInProducerǁadd_watermark__mutmut_29, 
        'xǁEmailInProducerǁadd_watermark__mutmut_30': xǁEmailInProducerǁadd_watermark__mutmut_30, 
        'xǁEmailInProducerǁadd_watermark__mutmut_31': xǁEmailInProducerǁadd_watermark__mutmut_31, 
        'xǁEmailInProducerǁadd_watermark__mutmut_32': xǁEmailInProducerǁadd_watermark__mutmut_32, 
        'xǁEmailInProducerǁadd_watermark__mutmut_33': xǁEmailInProducerǁadd_watermark__mutmut_33, 
        'xǁEmailInProducerǁadd_watermark__mutmut_34': xǁEmailInProducerǁadd_watermark__mutmut_34, 
        'xǁEmailInProducerǁadd_watermark__mutmut_35': xǁEmailInProducerǁadd_watermark__mutmut_35, 
        'xǁEmailInProducerǁadd_watermark__mutmut_36': xǁEmailInProducerǁadd_watermark__mutmut_36
    }
    
    def add_watermark(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailInProducerǁadd_watermark__mutmut_orig"), object.__getattribute__(self, "xǁEmailInProducerǁadd_watermark__mutmut_mutants"), args, kwargs, self)
        return result 
    
    add_watermark.__signature__ = _mutmut_signature(xǁEmailInProducerǁadd_watermark__mutmut_orig)
    xǁEmailInProducerǁadd_watermark__mutmut_orig.__name__ = 'xǁEmailInProducerǁadd_watermark'
    def xǁEmailInProducerǁis_watermark_applicable__mutmut_orig(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return True
    def xǁEmailInProducerǁis_watermark_applicable__mutmut_1(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return False
    
    xǁEmailInProducerǁis_watermark_applicable__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailInProducerǁis_watermark_applicable__mutmut_1': xǁEmailInProducerǁis_watermark_applicable__mutmut_1
    }
    
    def is_watermark_applicable(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailInProducerǁis_watermark_applicable__mutmut_orig"), object.__getattribute__(self, "xǁEmailInProducerǁis_watermark_applicable__mutmut_mutants"), args, kwargs, self)
        return result 
    
    is_watermark_applicable.__signature__ = _mutmut_signature(xǁEmailInProducerǁis_watermark_applicable__mutmut_orig)
    xǁEmailInProducerǁis_watermark_applicable__mutmut_orig.__name__ = 'xǁEmailInProducerǁis_watermark_applicable'
    

    def xǁEmailInProducerǁread_secret__mutmut_orig(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_1(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) and not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_2(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_3(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_4(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError(None)
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_5(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("XXKey must be a non-empty stringXX")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_6(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_7(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("KEY MUST BE A NON-EMPTY STRING")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_8(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(None) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_9(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = None
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_10(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(None)
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_11(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get(None))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_12(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("XX/ProducerXX"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_13(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_14(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/PRODUCER"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_15(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = None
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_16(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(None).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_17(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get(None, "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_18(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", None)).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_19(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_20(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", )).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_21(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("XXSECRET_DIRXX", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_22(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("secret_dir", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_23(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "XX./storageXX")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_24(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./STORAGE")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_25(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = None

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_26(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir * "secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_27(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"XXsecret.txtXX"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_28(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"SECRET.TXT"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_29(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(None, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_30(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, None) as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_31(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open("r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_32(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, ) as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_33(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "XXrXX") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_34(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "R") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_35(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = None
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_36(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError(None) from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_37(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("XXFailed to read secret.txtXX") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_38(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_39(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("FAILED TO READ SECRET.TXT") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_40(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = None
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_41(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode(None)
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_42(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("XXutf-8XX")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_43(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("UTF-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_44(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = None

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_45(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(None, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_46(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, None)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_47(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_48(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, )

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_49(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_50(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(None, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_51(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, None):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_52(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_53(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, ):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_54(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError(None)

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_55(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("XXProvided key failed to authenticate the watermarkXX")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_56(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("provided key failed to authenticate the watermark")

        return final_secret
    

    def xǁEmailInProducerǁread_secret__mutmut_57(self, pdf, key: str) -> str:
        """Extract the secret if present and authenticated by ``key``.

        Raises :class:`SecretNotFoundError` when the marker/payload is not
        found or is malformed. Raises :class:`InvalidKeyError` if the MAC
        does not validate under the given key.
        """
        #data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with pikepdf.open(pdf) as out_pdf:
            mac_hex = str(out_pdf.docinfo.get("/Producer"))
        #idx = data.rfind(self._MAGIC)
        #if idx == -1:
         #   raise SecretNotFoundError("No AddAfterEOF watermark found")

        #start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        #end_nl = data.find(b"\n", start)
        #end = len(data) if end_nl == -1 else end_nl
        #b64_payload = data[start:end].strip()
        #if not b64_payload:
         #   raise SecretNotFoundError("Found marker but empty payload")

        #try:
         #   payload_json = base64.urlsafe_b64decode(b64_payload)
          #  payload = json.loads(payload_json)
        #except Exception as exc:  # broad: malformed or tampered
         #   raise SecretNotFoundError("Malformed watermark payload") from exc

        #if not (isinstance(payload, dict) and payload.get("v") == 1):
         #   raise SecretNotFoundError("Unsupported watermark version or format")
        #if payload.get("alg") != "HMAC-SHA256":
         #   raise WatermarkingError("Unsupported MAC algorithm: %r" % payload.get("alg"))

        #try:
         #   mac_hex = str(payload["mac"])  # stored as hex string
          #  secret_b64 = str(payload["secret"]).encode("ascii")
           # secret_bytes = base64.b64decode(secret_b64)
        #except Exception as exc:
         #   raise SecretNotFoundError("Invalid payload fields") from exc

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        try:
            with open(filename, "r") as f:
                final_secret = f.read().strip()
        except Exception as exc:
            raise SecretNotFoundError("Failed to read secret.txt") from exc

        final_secret_bytes = final_secret.encode("utf-8")
        expected = self._mac_hex(final_secret_bytes, key)

        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("PROVIDED KEY FAILED TO AUTHENTICATE THE WATERMARK")

        return final_secret
    
    xǁEmailInProducerǁread_secret__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailInProducerǁread_secret__mutmut_1': xǁEmailInProducerǁread_secret__mutmut_1, 
        'xǁEmailInProducerǁread_secret__mutmut_2': xǁEmailInProducerǁread_secret__mutmut_2, 
        'xǁEmailInProducerǁread_secret__mutmut_3': xǁEmailInProducerǁread_secret__mutmut_3, 
        'xǁEmailInProducerǁread_secret__mutmut_4': xǁEmailInProducerǁread_secret__mutmut_4, 
        'xǁEmailInProducerǁread_secret__mutmut_5': xǁEmailInProducerǁread_secret__mutmut_5, 
        'xǁEmailInProducerǁread_secret__mutmut_6': xǁEmailInProducerǁread_secret__mutmut_6, 
        'xǁEmailInProducerǁread_secret__mutmut_7': xǁEmailInProducerǁread_secret__mutmut_7, 
        'xǁEmailInProducerǁread_secret__mutmut_8': xǁEmailInProducerǁread_secret__mutmut_8, 
        'xǁEmailInProducerǁread_secret__mutmut_9': xǁEmailInProducerǁread_secret__mutmut_9, 
        'xǁEmailInProducerǁread_secret__mutmut_10': xǁEmailInProducerǁread_secret__mutmut_10, 
        'xǁEmailInProducerǁread_secret__mutmut_11': xǁEmailInProducerǁread_secret__mutmut_11, 
        'xǁEmailInProducerǁread_secret__mutmut_12': xǁEmailInProducerǁread_secret__mutmut_12, 
        'xǁEmailInProducerǁread_secret__mutmut_13': xǁEmailInProducerǁread_secret__mutmut_13, 
        'xǁEmailInProducerǁread_secret__mutmut_14': xǁEmailInProducerǁread_secret__mutmut_14, 
        'xǁEmailInProducerǁread_secret__mutmut_15': xǁEmailInProducerǁread_secret__mutmut_15, 
        'xǁEmailInProducerǁread_secret__mutmut_16': xǁEmailInProducerǁread_secret__mutmut_16, 
        'xǁEmailInProducerǁread_secret__mutmut_17': xǁEmailInProducerǁread_secret__mutmut_17, 
        'xǁEmailInProducerǁread_secret__mutmut_18': xǁEmailInProducerǁread_secret__mutmut_18, 
        'xǁEmailInProducerǁread_secret__mutmut_19': xǁEmailInProducerǁread_secret__mutmut_19, 
        'xǁEmailInProducerǁread_secret__mutmut_20': xǁEmailInProducerǁread_secret__mutmut_20, 
        'xǁEmailInProducerǁread_secret__mutmut_21': xǁEmailInProducerǁread_secret__mutmut_21, 
        'xǁEmailInProducerǁread_secret__mutmut_22': xǁEmailInProducerǁread_secret__mutmut_22, 
        'xǁEmailInProducerǁread_secret__mutmut_23': xǁEmailInProducerǁread_secret__mutmut_23, 
        'xǁEmailInProducerǁread_secret__mutmut_24': xǁEmailInProducerǁread_secret__mutmut_24, 
        'xǁEmailInProducerǁread_secret__mutmut_25': xǁEmailInProducerǁread_secret__mutmut_25, 
        'xǁEmailInProducerǁread_secret__mutmut_26': xǁEmailInProducerǁread_secret__mutmut_26, 
        'xǁEmailInProducerǁread_secret__mutmut_27': xǁEmailInProducerǁread_secret__mutmut_27, 
        'xǁEmailInProducerǁread_secret__mutmut_28': xǁEmailInProducerǁread_secret__mutmut_28, 
        'xǁEmailInProducerǁread_secret__mutmut_29': xǁEmailInProducerǁread_secret__mutmut_29, 
        'xǁEmailInProducerǁread_secret__mutmut_30': xǁEmailInProducerǁread_secret__mutmut_30, 
        'xǁEmailInProducerǁread_secret__mutmut_31': xǁEmailInProducerǁread_secret__mutmut_31, 
        'xǁEmailInProducerǁread_secret__mutmut_32': xǁEmailInProducerǁread_secret__mutmut_32, 
        'xǁEmailInProducerǁread_secret__mutmut_33': xǁEmailInProducerǁread_secret__mutmut_33, 
        'xǁEmailInProducerǁread_secret__mutmut_34': xǁEmailInProducerǁread_secret__mutmut_34, 
        'xǁEmailInProducerǁread_secret__mutmut_35': xǁEmailInProducerǁread_secret__mutmut_35, 
        'xǁEmailInProducerǁread_secret__mutmut_36': xǁEmailInProducerǁread_secret__mutmut_36, 
        'xǁEmailInProducerǁread_secret__mutmut_37': xǁEmailInProducerǁread_secret__mutmut_37, 
        'xǁEmailInProducerǁread_secret__mutmut_38': xǁEmailInProducerǁread_secret__mutmut_38, 
        'xǁEmailInProducerǁread_secret__mutmut_39': xǁEmailInProducerǁread_secret__mutmut_39, 
        'xǁEmailInProducerǁread_secret__mutmut_40': xǁEmailInProducerǁread_secret__mutmut_40, 
        'xǁEmailInProducerǁread_secret__mutmut_41': xǁEmailInProducerǁread_secret__mutmut_41, 
        'xǁEmailInProducerǁread_secret__mutmut_42': xǁEmailInProducerǁread_secret__mutmut_42, 
        'xǁEmailInProducerǁread_secret__mutmut_43': xǁEmailInProducerǁread_secret__mutmut_43, 
        'xǁEmailInProducerǁread_secret__mutmut_44': xǁEmailInProducerǁread_secret__mutmut_44, 
        'xǁEmailInProducerǁread_secret__mutmut_45': xǁEmailInProducerǁread_secret__mutmut_45, 
        'xǁEmailInProducerǁread_secret__mutmut_46': xǁEmailInProducerǁread_secret__mutmut_46, 
        'xǁEmailInProducerǁread_secret__mutmut_47': xǁEmailInProducerǁread_secret__mutmut_47, 
        'xǁEmailInProducerǁread_secret__mutmut_48': xǁEmailInProducerǁread_secret__mutmut_48, 
        'xǁEmailInProducerǁread_secret__mutmut_49': xǁEmailInProducerǁread_secret__mutmut_49, 
        'xǁEmailInProducerǁread_secret__mutmut_50': xǁEmailInProducerǁread_secret__mutmut_50, 
        'xǁEmailInProducerǁread_secret__mutmut_51': xǁEmailInProducerǁread_secret__mutmut_51, 
        'xǁEmailInProducerǁread_secret__mutmut_52': xǁEmailInProducerǁread_secret__mutmut_52, 
        'xǁEmailInProducerǁread_secret__mutmut_53': xǁEmailInProducerǁread_secret__mutmut_53, 
        'xǁEmailInProducerǁread_secret__mutmut_54': xǁEmailInProducerǁread_secret__mutmut_54, 
        'xǁEmailInProducerǁread_secret__mutmut_55': xǁEmailInProducerǁread_secret__mutmut_55, 
        'xǁEmailInProducerǁread_secret__mutmut_56': xǁEmailInProducerǁread_secret__mutmut_56, 
        'xǁEmailInProducerǁread_secret__mutmut_57': xǁEmailInProducerǁread_secret__mutmut_57
    }
    
    def read_secret(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailInProducerǁread_secret__mutmut_orig"), object.__getattribute__(self, "xǁEmailInProducerǁread_secret__mutmut_mutants"), args, kwargs, self)
        return result 
    
    read_secret.__signature__ = _mutmut_signature(xǁEmailInProducerǁread_secret__mutmut_orig)
    xǁEmailInProducerǁread_secret__mutmut_orig.__name__ = 'xǁEmailInProducerǁread_secret'

    def xǁEmailInProducerǁis_email__mutmut_orig(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern,s) is not None

    def xǁEmailInProducerǁis_email__mutmut_1(self,s: str) -> bool:
        # sample regex for email validation
        pattern = None
        return re.match(pattern,s) is not None

    def xǁEmailInProducerǁis_email__mutmut_2(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'XX^[\w\.-]+@[\w\.-]+\.\w+$XX'
        return re.match(pattern,s) is not None

    def xǁEmailInProducerǁis_email__mutmut_3(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern,s) is not None

    def xǁEmailInProducerǁis_email__mutmut_4(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern,s) is not None

    def xǁEmailInProducerǁis_email__mutmut_5(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(None,s) is not None

    def xǁEmailInProducerǁis_email__mutmut_6(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern,None) is not None

    def xǁEmailInProducerǁis_email__mutmut_7(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(s) is not None

    def xǁEmailInProducerǁis_email__mutmut_8(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern,) is not None

    def xǁEmailInProducerǁis_email__mutmut_9(self,s: str) -> bool:
        # sample regex for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern,s) is None
    
    xǁEmailInProducerǁis_email__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailInProducerǁis_email__mutmut_1': xǁEmailInProducerǁis_email__mutmut_1, 
        'xǁEmailInProducerǁis_email__mutmut_2': xǁEmailInProducerǁis_email__mutmut_2, 
        'xǁEmailInProducerǁis_email__mutmut_3': xǁEmailInProducerǁis_email__mutmut_3, 
        'xǁEmailInProducerǁis_email__mutmut_4': xǁEmailInProducerǁis_email__mutmut_4, 
        'xǁEmailInProducerǁis_email__mutmut_5': xǁEmailInProducerǁis_email__mutmut_5, 
        'xǁEmailInProducerǁis_email__mutmut_6': xǁEmailInProducerǁis_email__mutmut_6, 
        'xǁEmailInProducerǁis_email__mutmut_7': xǁEmailInProducerǁis_email__mutmut_7, 
        'xǁEmailInProducerǁis_email__mutmut_8': xǁEmailInProducerǁis_email__mutmut_8, 
        'xǁEmailInProducerǁis_email__mutmut_9': xǁEmailInProducerǁis_email__mutmut_9
    }
    
    def is_email(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailInProducerǁis_email__mutmut_orig"), object.__getattribute__(self, "xǁEmailInProducerǁis_email__mutmut_mutants"), args, kwargs, self)
        return result 
    
    is_email.__signature__ = _mutmut_signature(xǁEmailInProducerǁis_email__mutmut_orig)
    xǁEmailInProducerǁis_email__mutmut_orig.__name__ = 'xǁEmailInProducerǁis_email'

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_orig(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_1(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = None
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_2(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(None)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_3(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = None

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_4(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret - secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_5(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = None
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_6(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode(None)
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_7(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("XXutf-8XX")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_8(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("UTF-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_9(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = None

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_10(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = None
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_11(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(None).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_12(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get(None, "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_13(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", None)).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_14(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_15(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", )).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_16(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("XXSECRET_DIRXX", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_17(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("secret_dir", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_18(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "XX./storageXX")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_19(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./STORAGE")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_20(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = None

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_21(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir * "secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_22(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"XXsecret.txtXX"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_23(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"SECRET.TXT"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_24(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(None, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_25(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, None) as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_26(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open("w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_27(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, ) as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_28(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "XXwXX") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_29(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "W") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_30(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(None)
        mac_hex = self._mac_hex(secret_bytes, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_31(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = None
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_32(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(None, key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_33(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, None)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_34(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(key)
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex

    # Internal helpers
    # ---------------------

    def xǁEmailInProducerǁ_build_payload__mutmut_35(self, secret: str, key: str) -> str:
        
        """Build the base64url-encoded JSON payload to append."""
       # from watermarking_utils import store_recipient_credentials

        secret_extract = self.extract_email_parts(secret)
        final_secret = secret + secret_extract

       # store_recipient_credentials(secret,final_secret,key)

        secret_bytes = final_secret.encode("utf-8")
        final_secret_bytes = secret_bytes

        secret_dir = Path(os.environ.get("SECRET_DIR", "./storage")).resolve()
        filename = secret_dir/"secret.txt"

        with open(filename, "w") as f:
            f.write(final_secret)
        mac_hex = self._mac_hex(secret_bytes, )
        #obj = {
         #   "v": 1,
          #  "alg": "HMAC-SHA256",
           # "mac": mac_hex,
            #"secret": base64.b64encode(secret_bytes).decode("ascii"),
        #}
        # Compact JSON for determinism
        #j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        #return base64.urlsafe_b64encode(j)
        return mac_hex
    
    xǁEmailInProducerǁ_build_payload__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailInProducerǁ_build_payload__mutmut_1': xǁEmailInProducerǁ_build_payload__mutmut_1, 
        'xǁEmailInProducerǁ_build_payload__mutmut_2': xǁEmailInProducerǁ_build_payload__mutmut_2, 
        'xǁEmailInProducerǁ_build_payload__mutmut_3': xǁEmailInProducerǁ_build_payload__mutmut_3, 
        'xǁEmailInProducerǁ_build_payload__mutmut_4': xǁEmailInProducerǁ_build_payload__mutmut_4, 
        'xǁEmailInProducerǁ_build_payload__mutmut_5': xǁEmailInProducerǁ_build_payload__mutmut_5, 
        'xǁEmailInProducerǁ_build_payload__mutmut_6': xǁEmailInProducerǁ_build_payload__mutmut_6, 
        'xǁEmailInProducerǁ_build_payload__mutmut_7': xǁEmailInProducerǁ_build_payload__mutmut_7, 
        'xǁEmailInProducerǁ_build_payload__mutmut_8': xǁEmailInProducerǁ_build_payload__mutmut_8, 
        'xǁEmailInProducerǁ_build_payload__mutmut_9': xǁEmailInProducerǁ_build_payload__mutmut_9, 
        'xǁEmailInProducerǁ_build_payload__mutmut_10': xǁEmailInProducerǁ_build_payload__mutmut_10, 
        'xǁEmailInProducerǁ_build_payload__mutmut_11': xǁEmailInProducerǁ_build_payload__mutmut_11, 
        'xǁEmailInProducerǁ_build_payload__mutmut_12': xǁEmailInProducerǁ_build_payload__mutmut_12, 
        'xǁEmailInProducerǁ_build_payload__mutmut_13': xǁEmailInProducerǁ_build_payload__mutmut_13, 
        'xǁEmailInProducerǁ_build_payload__mutmut_14': xǁEmailInProducerǁ_build_payload__mutmut_14, 
        'xǁEmailInProducerǁ_build_payload__mutmut_15': xǁEmailInProducerǁ_build_payload__mutmut_15, 
        'xǁEmailInProducerǁ_build_payload__mutmut_16': xǁEmailInProducerǁ_build_payload__mutmut_16, 
        'xǁEmailInProducerǁ_build_payload__mutmut_17': xǁEmailInProducerǁ_build_payload__mutmut_17, 
        'xǁEmailInProducerǁ_build_payload__mutmut_18': xǁEmailInProducerǁ_build_payload__mutmut_18, 
        'xǁEmailInProducerǁ_build_payload__mutmut_19': xǁEmailInProducerǁ_build_payload__mutmut_19, 
        'xǁEmailInProducerǁ_build_payload__mutmut_20': xǁEmailInProducerǁ_build_payload__mutmut_20, 
        'xǁEmailInProducerǁ_build_payload__mutmut_21': xǁEmailInProducerǁ_build_payload__mutmut_21, 
        'xǁEmailInProducerǁ_build_payload__mutmut_22': xǁEmailInProducerǁ_build_payload__mutmut_22, 
        'xǁEmailInProducerǁ_build_payload__mutmut_23': xǁEmailInProducerǁ_build_payload__mutmut_23, 
        'xǁEmailInProducerǁ_build_payload__mutmut_24': xǁEmailInProducerǁ_build_payload__mutmut_24, 
        'xǁEmailInProducerǁ_build_payload__mutmut_25': xǁEmailInProducerǁ_build_payload__mutmut_25, 
        'xǁEmailInProducerǁ_build_payload__mutmut_26': xǁEmailInProducerǁ_build_payload__mutmut_26, 
        'xǁEmailInProducerǁ_build_payload__mutmut_27': xǁEmailInProducerǁ_build_payload__mutmut_27, 
        'xǁEmailInProducerǁ_build_payload__mutmut_28': xǁEmailInProducerǁ_build_payload__mutmut_28, 
        'xǁEmailInProducerǁ_build_payload__mutmut_29': xǁEmailInProducerǁ_build_payload__mutmut_29, 
        'xǁEmailInProducerǁ_build_payload__mutmut_30': xǁEmailInProducerǁ_build_payload__mutmut_30, 
        'xǁEmailInProducerǁ_build_payload__mutmut_31': xǁEmailInProducerǁ_build_payload__mutmut_31, 
        'xǁEmailInProducerǁ_build_payload__mutmut_32': xǁEmailInProducerǁ_build_payload__mutmut_32, 
        'xǁEmailInProducerǁ_build_payload__mutmut_33': xǁEmailInProducerǁ_build_payload__mutmut_33, 
        'xǁEmailInProducerǁ_build_payload__mutmut_34': xǁEmailInProducerǁ_build_payload__mutmut_34, 
        'xǁEmailInProducerǁ_build_payload__mutmut_35': xǁEmailInProducerǁ_build_payload__mutmut_35
    }
    
    def _build_payload(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailInProducerǁ_build_payload__mutmut_orig"), object.__getattribute__(self, "xǁEmailInProducerǁ_build_payload__mutmut_mutants"), args, kwargs, self)
        return result 
    
    _build_payload.__signature__ = _mutmut_signature(xǁEmailInProducerǁ_build_payload__mutmut_orig)
    xǁEmailInProducerǁ_build_payload__mutmut_orig.__name__ = 'xǁEmailInProducerǁ_build_payload'

    def xǁEmailInProducerǁ_mac_hex__mutmut_orig(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailInProducerǁ_mac_hex__mutmut_1(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = None
        return hm.hexdigest()

    def xǁEmailInProducerǁ_mac_hex__mutmut_2(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(None, self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailInProducerǁ_mac_hex__mutmut_3(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), None, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailInProducerǁ_mac_hex__mutmut_4(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT + secret_bytes, None)
        return hm.hexdigest()

    def xǁEmailInProducerǁ_mac_hex__mutmut_5(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailInProducerǁ_mac_hex__mutmut_6(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailInProducerǁ_mac_hex__mutmut_7(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT + secret_bytes, )
        return hm.hexdigest()

    def xǁEmailInProducerǁ_mac_hex__mutmut_8(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode(None), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailInProducerǁ_mac_hex__mutmut_9(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("XXutf-8XX"), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailInProducerǁ_mac_hex__mutmut_10(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("UTF-8"), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def xǁEmailInProducerǁ_mac_hex__mutmut_11(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT - secret_bytes, hashlib.sha256)
        return hm.hexdigest()
    
    xǁEmailInProducerǁ_mac_hex__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailInProducerǁ_mac_hex__mutmut_1': xǁEmailInProducerǁ_mac_hex__mutmut_1, 
        'xǁEmailInProducerǁ_mac_hex__mutmut_2': xǁEmailInProducerǁ_mac_hex__mutmut_2, 
        'xǁEmailInProducerǁ_mac_hex__mutmut_3': xǁEmailInProducerǁ_mac_hex__mutmut_3, 
        'xǁEmailInProducerǁ_mac_hex__mutmut_4': xǁEmailInProducerǁ_mac_hex__mutmut_4, 
        'xǁEmailInProducerǁ_mac_hex__mutmut_5': xǁEmailInProducerǁ_mac_hex__mutmut_5, 
        'xǁEmailInProducerǁ_mac_hex__mutmut_6': xǁEmailInProducerǁ_mac_hex__mutmut_6, 
        'xǁEmailInProducerǁ_mac_hex__mutmut_7': xǁEmailInProducerǁ_mac_hex__mutmut_7, 
        'xǁEmailInProducerǁ_mac_hex__mutmut_8': xǁEmailInProducerǁ_mac_hex__mutmut_8, 
        'xǁEmailInProducerǁ_mac_hex__mutmut_9': xǁEmailInProducerǁ_mac_hex__mutmut_9, 
        'xǁEmailInProducerǁ_mac_hex__mutmut_10': xǁEmailInProducerǁ_mac_hex__mutmut_10, 
        'xǁEmailInProducerǁ_mac_hex__mutmut_11': xǁEmailInProducerǁ_mac_hex__mutmut_11
    }
    
    def _mac_hex(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailInProducerǁ_mac_hex__mutmut_orig"), object.__getattribute__(self, "xǁEmailInProducerǁ_mac_hex__mutmut_mutants"), args, kwargs, self)
        return result 
    
    _mac_hex.__signature__ = _mutmut_signature(xǁEmailInProducerǁ_mac_hex__mutmut_orig)
    xǁEmailInProducerǁ_mac_hex__mutmut_orig.__name__ = 'xǁEmailInProducerǁ_mac_hex'
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_orig(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_1(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_2(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_3(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_4(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_5(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_6(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_7(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_8(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_9(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_10(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_11(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_12(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_13(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_14(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_15(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_16(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_17(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_18(self, secret) -> str:

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
    
    def xǁEmailInProducerǁextract_email_parts__mutmut_19(self, secret) -> str:

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
    
    xǁEmailInProducerǁextract_email_parts__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁEmailInProducerǁextract_email_parts__mutmut_1': xǁEmailInProducerǁextract_email_parts__mutmut_1, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_2': xǁEmailInProducerǁextract_email_parts__mutmut_2, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_3': xǁEmailInProducerǁextract_email_parts__mutmut_3, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_4': xǁEmailInProducerǁextract_email_parts__mutmut_4, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_5': xǁEmailInProducerǁextract_email_parts__mutmut_5, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_6': xǁEmailInProducerǁextract_email_parts__mutmut_6, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_7': xǁEmailInProducerǁextract_email_parts__mutmut_7, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_8': xǁEmailInProducerǁextract_email_parts__mutmut_8, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_9': xǁEmailInProducerǁextract_email_parts__mutmut_9, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_10': xǁEmailInProducerǁextract_email_parts__mutmut_10, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_11': xǁEmailInProducerǁextract_email_parts__mutmut_11, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_12': xǁEmailInProducerǁextract_email_parts__mutmut_12, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_13': xǁEmailInProducerǁextract_email_parts__mutmut_13, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_14': xǁEmailInProducerǁextract_email_parts__mutmut_14, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_15': xǁEmailInProducerǁextract_email_parts__mutmut_15, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_16': xǁEmailInProducerǁextract_email_parts__mutmut_16, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_17': xǁEmailInProducerǁextract_email_parts__mutmut_17, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_18': xǁEmailInProducerǁextract_email_parts__mutmut_18, 
        'xǁEmailInProducerǁextract_email_parts__mutmut_19': xǁEmailInProducerǁextract_email_parts__mutmut_19
    }
    
    def extract_email_parts(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁEmailInProducerǁextract_email_parts__mutmut_orig"), object.__getattribute__(self, "xǁEmailInProducerǁextract_email_parts__mutmut_mutants"), args, kwargs, self)
        return result 
    
    extract_email_parts.__signature__ = _mutmut_signature(xǁEmailInProducerǁextract_email_parts__mutmut_orig)
    xǁEmailInProducerǁextract_email_parts__mutmut_orig.__name__ = 'xǁEmailInProducerǁextract_email_parts'

__all__ = ["EmailInProducer"]

