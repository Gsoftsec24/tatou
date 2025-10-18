"""watermarking_utils.py

Utility functions and registry for PDF watermarking methods.

This module exposes:

- :data:`METHODS`: a mapping from method name to an instantiated
  :class:`~watermarking_method.WatermarkingMethod`.
- :func:`explore_pdf`: build a lightweight JSON-serializable tree of PDF
  nodes with deterministic identifiers ("name nodes").
- :func:`apply_watermark`: run a concrete watermarking method on a PDF.
- :func:`apply_watermark`: run a concrete watermarking method on a PDF.
- :func:`read_watermark`: recover a secret using a concrete method.
- :func:`register_method` / :func:`get_method`: registry helpers.
- :func:`send_email_with_pdf` : send mail to the appropriate user with watermarked pdf

Dependencies
------------
Only the standard library is required. If available, the exploration
routine will use *PyMuPDF* (``fitz``) for a richer object inventory. If
``fitz`` is not installed, it gracefully falls back to a permissive
regex-based scan for ``obj ... endobj`` blocks (this may miss compressed
object streams).

To enable the richer exploration, install PyMuPDF:

    pip install pymupdf

"""
from __future__ import annotations

from typing import Any, Dict, Final, Iterable, List, Mapping
import base64
import hashlib
import io
import json
import os
import re
import email
import smtplib
from email.message import EmailMessage

from watermarking_method import (
    PdfSource,
    WatermarkingMethod,
    load_pdf_bytes,
)
from add_after_eof import AddAfterEOF
from email_after_eof import EmailAfterEOF
from hash_after_eof import HashAfterEOF
from email_in_producer import EmailInProducer
# --------------------
# Method registry
# --------------------

METHODS: Dict[str, WatermarkingMethod] = {
    AddAfterEOF.name: AddAfterEOF(),   
    EmailAfterEOF.name: EmailAfterEOF(),
    HashAfterEOF.name: HashAfterEOF(),
    EmailInProducer.name: EmailInProducer()
}
"""Registry of available watermarking methods.

Keys are human-readable method names (stable, lowercase, hyphenated)
exposed by each implementation's ``.name`` attribute. Values are
*instances* of the corresponding class.
"""
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


def x_register_method__mutmut_orig(method: WatermarkingMethod) -> None:
    """Register (or replace) a watermarking method instance by name."""
    METHODS[method.name] = method


def x_register_method__mutmut_1(method: WatermarkingMethod) -> None:
    """Register (or replace) a watermarking method instance by name."""
    METHODS[method.name] = None

x_register_method__mutmut_mutants : ClassVar[MutantDict] = {
'x_register_method__mutmut_1': x_register_method__mutmut_1
}

def register_method(*args, **kwargs):
    result = _mutmut_trampoline(x_register_method__mutmut_orig, x_register_method__mutmut_mutants, args, kwargs)
    return result 

register_method.__signature__ = _mutmut_signature(x_register_method__mutmut_orig)
x_register_method__mutmut_orig.__name__ = 'x_register_method'


def x_get_method__mutmut_orig(method: str | WatermarkingMethod) -> WatermarkingMethod:
    """Resolve a method from a string name or pass-through an instance.

    Raises
    ------
    KeyError
        If ``method`` is a string not present in :data:`METHODS`.
    """
    if isinstance(method, WatermarkingMethod):
        return method
    try:
        return METHODS[method]
    except KeyError as exc:
        raise KeyError(
            f"Unknown watermarking method: {method!r}. Known: {sorted(METHODS)}"
        ) from exc


def x_get_method__mutmut_1(method: str | WatermarkingMethod) -> WatermarkingMethod:
    """Resolve a method from a string name or pass-through an instance.

    Raises
    ------
    KeyError
        If ``method`` is a string not present in :data:`METHODS`.
    """
    if isinstance(method, WatermarkingMethod):
        return method
    try:
        return METHODS[method]
    except KeyError as exc:
        raise KeyError(
            None
        ) from exc


def x_get_method__mutmut_2(method: str | WatermarkingMethod) -> WatermarkingMethod:
    """Resolve a method from a string name or pass-through an instance.

    Raises
    ------
    KeyError
        If ``method`` is a string not present in :data:`METHODS`.
    """
    if isinstance(method, WatermarkingMethod):
        return method
    try:
        return METHODS[method]
    except KeyError as exc:
        raise KeyError(
            f"Unknown watermarking method: {method!r}. Known: {sorted(None)}"
        ) from exc

x_get_method__mutmut_mutants : ClassVar[MutantDict] = {
'x_get_method__mutmut_1': x_get_method__mutmut_1, 
    'x_get_method__mutmut_2': x_get_method__mutmut_2
}

def get_method(*args, **kwargs):
    result = _mutmut_trampoline(x_get_method__mutmut_orig, x_get_method__mutmut_mutants, args, kwargs)
    return result 

get_method.__signature__ = _mutmut_signature(x_get_method__mutmut_orig)
x_get_method__mutmut_orig.__name__ = 'x_get_method'


# --------------------
# Public API helpers
# --------------------

def x_apply_watermark__mutmut_orig(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    secret: str,
    key: str,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.add_watermark(pdf=pdf, secret=secret, key=key, position=position)


# --------------------
# Public API helpers
# --------------------

def x_apply_watermark__mutmut_1(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    secret: str,
    key: str,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = None
    return m.add_watermark(pdf=pdf, secret=secret, key=key, position=position)


# --------------------
# Public API helpers
# --------------------

def x_apply_watermark__mutmut_2(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    secret: str,
    key: str,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(None)
    return m.add_watermark(pdf=pdf, secret=secret, key=key, position=position)


# --------------------
# Public API helpers
# --------------------

def x_apply_watermark__mutmut_3(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    secret: str,
    key: str,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.add_watermark(pdf=None, secret=secret, key=key, position=position)


# --------------------
# Public API helpers
# --------------------

def x_apply_watermark__mutmut_4(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    secret: str,
    key: str,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.add_watermark(pdf=pdf, secret=None, key=key, position=position)


# --------------------
# Public API helpers
# --------------------

def x_apply_watermark__mutmut_5(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    secret: str,
    key: str,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.add_watermark(pdf=pdf, secret=secret, key=None, position=position)


# --------------------
# Public API helpers
# --------------------

def x_apply_watermark__mutmut_6(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    secret: str,
    key: str,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.add_watermark(pdf=pdf, secret=secret, key=key, position=None)


# --------------------
# Public API helpers
# --------------------

def x_apply_watermark__mutmut_7(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    secret: str,
    key: str,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.add_watermark(secret=secret, key=key, position=position)


# --------------------
# Public API helpers
# --------------------

def x_apply_watermark__mutmut_8(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    secret: str,
    key: str,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.add_watermark(pdf=pdf, key=key, position=position)


# --------------------
# Public API helpers
# --------------------

def x_apply_watermark__mutmut_9(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    secret: str,
    key: str,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.add_watermark(pdf=pdf, secret=secret, position=position)


# --------------------
# Public API helpers
# --------------------

def x_apply_watermark__mutmut_10(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    secret: str,
    key: str,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.add_watermark(pdf=pdf, secret=secret, key=key, )

x_apply_watermark__mutmut_mutants : ClassVar[MutantDict] = {
'x_apply_watermark__mutmut_1': x_apply_watermark__mutmut_1, 
    'x_apply_watermark__mutmut_2': x_apply_watermark__mutmut_2, 
    'x_apply_watermark__mutmut_3': x_apply_watermark__mutmut_3, 
    'x_apply_watermark__mutmut_4': x_apply_watermark__mutmut_4, 
    'x_apply_watermark__mutmut_5': x_apply_watermark__mutmut_5, 
    'x_apply_watermark__mutmut_6': x_apply_watermark__mutmut_6, 
    'x_apply_watermark__mutmut_7': x_apply_watermark__mutmut_7, 
    'x_apply_watermark__mutmut_8': x_apply_watermark__mutmut_8, 
    'x_apply_watermark__mutmut_9': x_apply_watermark__mutmut_9, 
    'x_apply_watermark__mutmut_10': x_apply_watermark__mutmut_10
}

def apply_watermark(*args, **kwargs):
    result = _mutmut_trampoline(x_apply_watermark__mutmut_orig, x_apply_watermark__mutmut_mutants, args, kwargs)
    return result 

apply_watermark.__signature__ = _mutmut_signature(x_apply_watermark__mutmut_orig)
x_apply_watermark__mutmut_orig.__name__ = 'x_apply_watermark'

def x_is_watermarking_applicable__mutmut_orig(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.is_watermark_applicable(pdf=pdf, position=position)

def x_is_watermarking_applicable__mutmut_1(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = None
    return m.is_watermark_applicable(pdf=pdf, position=position)

def x_is_watermarking_applicable__mutmut_2(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(None)
    return m.is_watermark_applicable(pdf=pdf, position=position)

def x_is_watermarking_applicable__mutmut_3(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.is_watermark_applicable(pdf=None, position=position)

def x_is_watermarking_applicable__mutmut_4(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.is_watermark_applicable(pdf=pdf, position=None)

def x_is_watermarking_applicable__mutmut_5(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.is_watermark_applicable(position=position)

def x_is_watermarking_applicable__mutmut_6(
    method: str | WatermarkingMethod,
    pdf: PdfSource,
    position: str | None = None,
) -> bytes:
    """Apply a watermark using the specified method and return new PDF bytes."""
    m = get_method(method)
    return m.is_watermark_applicable(pdf=pdf, )

x_is_watermarking_applicable__mutmut_mutants : ClassVar[MutantDict] = {
'x_is_watermarking_applicable__mutmut_1': x_is_watermarking_applicable__mutmut_1, 
    'x_is_watermarking_applicable__mutmut_2': x_is_watermarking_applicable__mutmut_2, 
    'x_is_watermarking_applicable__mutmut_3': x_is_watermarking_applicable__mutmut_3, 
    'x_is_watermarking_applicable__mutmut_4': x_is_watermarking_applicable__mutmut_4, 
    'x_is_watermarking_applicable__mutmut_5': x_is_watermarking_applicable__mutmut_5, 
    'x_is_watermarking_applicable__mutmut_6': x_is_watermarking_applicable__mutmut_6
}

def is_watermarking_applicable(*args, **kwargs):
    result = _mutmut_trampoline(x_is_watermarking_applicable__mutmut_orig, x_is_watermarking_applicable__mutmut_mutants, args, kwargs)
    return result 

is_watermarking_applicable.__signature__ = _mutmut_signature(x_is_watermarking_applicable__mutmut_orig)
x_is_watermarking_applicable__mutmut_orig.__name__ = 'x_is_watermarking_applicable'


def x_read_watermark__mutmut_orig(method: str | WatermarkingMethod, pdf: PdfSource, key: str) -> str:
    """Recover a secret from ``pdf`` using the specified method."""
    m = get_method(method)
    return m.read_secret(pdf=pdf, key=key)


def x_read_watermark__mutmut_1(method: str | WatermarkingMethod, pdf: PdfSource, key: str) -> str:
    """Recover a secret from ``pdf`` using the specified method."""
    m = None
    return m.read_secret(pdf=pdf, key=key)


def x_read_watermark__mutmut_2(method: str | WatermarkingMethod, pdf: PdfSource, key: str) -> str:
    """Recover a secret from ``pdf`` using the specified method."""
    m = get_method(None)
    return m.read_secret(pdf=pdf, key=key)


def x_read_watermark__mutmut_3(method: str | WatermarkingMethod, pdf: PdfSource, key: str) -> str:
    """Recover a secret from ``pdf`` using the specified method."""
    m = get_method(method)
    return m.read_secret(pdf=None, key=key)


def x_read_watermark__mutmut_4(method: str | WatermarkingMethod, pdf: PdfSource, key: str) -> str:
    """Recover a secret from ``pdf`` using the specified method."""
    m = get_method(method)
    return m.read_secret(pdf=pdf, key=None)


def x_read_watermark__mutmut_5(method: str | WatermarkingMethod, pdf: PdfSource, key: str) -> str:
    """Recover a secret from ``pdf`` using the specified method."""
    m = get_method(method)
    return m.read_secret(key=key)


def x_read_watermark__mutmut_6(method: str | WatermarkingMethod, pdf: PdfSource, key: str) -> str:
    """Recover a secret from ``pdf`` using the specified method."""
    m = get_method(method)
    return m.read_secret(pdf=pdf, )

x_read_watermark__mutmut_mutants : ClassVar[MutantDict] = {
'x_read_watermark__mutmut_1': x_read_watermark__mutmut_1, 
    'x_read_watermark__mutmut_2': x_read_watermark__mutmut_2, 
    'x_read_watermark__mutmut_3': x_read_watermark__mutmut_3, 
    'x_read_watermark__mutmut_4': x_read_watermark__mutmut_4, 
    'x_read_watermark__mutmut_5': x_read_watermark__mutmut_5, 
    'x_read_watermark__mutmut_6': x_read_watermark__mutmut_6
}

def read_watermark(*args, **kwargs):
    result = _mutmut_trampoline(x_read_watermark__mutmut_orig, x_read_watermark__mutmut_mutants, args, kwargs)
    return result 

read_watermark.__signature__ = _mutmut_signature(x_read_watermark__mutmut_orig)
x_read_watermark__mutmut_orig.__name__ = 'x_read_watermark'


# --------------------
# PDF exploration
# --------------------

# Pre-compiled regex for the fallback parser (very permissive):
_OBJ_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"(?m)^(\d+)\s+(\d+)\s+obj\b"
)
_ENDOBJ_RE: Final[re.Pattern[bytes]] = re.compile(rb"\bendobj\b")
_TYPE_RE: Final[re.Pattern[bytes]] = re.compile(rb"/Type\s*/([A-Za-z]+)")


def x__sha1__mutmut_orig(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


def x__sha1__mutmut_1(b: bytes) -> str:
    return hashlib.sha1(None).hexdigest()

x__sha1__mutmut_mutants : ClassVar[MutantDict] = {
'x__sha1__mutmut_1': x__sha1__mutmut_1
}

def _sha1(*args, **kwargs):
    result = _mutmut_trampoline(x__sha1__mutmut_orig, x__sha1__mutmut_mutants, args, kwargs)
    return result 

_sha1.__signature__ = _mutmut_signature(x__sha1__mutmut_orig)
x__sha1__mutmut_orig.__name__ = 'x__sha1'


def x_explore_pdf__mutmut_orig(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_1(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = None

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_2(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(None)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_3(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = None

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_4(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "XXidXX": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_5(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "ID": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_6(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(None)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_7(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "XXtypeXX": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_8(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "TYPE": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_9(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "XXDocumentXX",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_10(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_11(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "DOCUMENT",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_12(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "XXsizeXX": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_13(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "SIZE": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_14(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "XXchildrenXX": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_15(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "CHILDREN": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_16(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = None
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_17(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=None, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_18(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype=None)
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_19(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_20(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, )
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_21(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="XXpdfXX")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_22(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="PDF")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_23(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(None):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_24(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = None
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_25(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "XXidXX": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_26(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "ID": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_27(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "XXtypeXX": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_28(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "TYPE": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_29(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "XXPageXX",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_30(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_31(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "PAGE",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_32(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "XXindexXX": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_33(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "INDEX": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_34(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "XXbboxXX": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_35(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "BBOX": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_36(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(None),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_37(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(None).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_38(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(None)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_39(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["XXchildrenXX"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_40(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["CHILDREN"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_41(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = None
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_42(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(None, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_43(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, None):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_44(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_45(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, ):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_46(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(2, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_47(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = None
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_48(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) and ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_49(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(None, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_50(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=None) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_51(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_52(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, ) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_53(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=True) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_54(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or "XXXX"
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_55(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = None
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_56(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = "XXXX"
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_57(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = None
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_58(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode(None, "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_59(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", None) if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_60(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_61(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", ) if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_62(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("XXlatin-1XX", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_63(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("LATIN-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_64(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "XXreplaceXX") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_65(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "REPLACE") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_66(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b"XXXX"
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_67(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_68(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_69(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = None
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_70(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(None)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_71(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = None
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_72(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode(None, "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_73(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", None) if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_74(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_75(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", ) if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_76(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(None).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_77(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(2).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_78(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("XXasciiXX", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_79(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ASCII", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_80(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "XXreplaceXX") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_81(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "REPLACE") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_82(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "XXObjectXX"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_83(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_84(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "OBJECT"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_85(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = None
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_86(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "XXidXX": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_87(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "ID": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_88(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "XXtypeXX": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_89(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "TYPE": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_90(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "XXxrefXX": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_91(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "XREF": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_92(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "XXis_streamXX": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_93(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "IS_STREAM": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_94(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(None),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_95(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(None)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_96(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "XXcontent_sha1XX": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_97(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "CONTENT_SHA1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_98(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(None) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_99(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(None)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_100(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["XXchildrenXX"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_101(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["CHILDREN"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_102(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = None
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_103(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(None):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_104(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = None
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_105(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(None)
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_106(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(None))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_107(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(2))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_108(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = None
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_109(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(None)
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_110(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(None))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_111(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(3))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_112(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = None
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_113(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = None
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_114(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(None, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_115(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, None)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_116(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_117(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, )
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_118(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = None
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_119(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = None
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_120(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = None
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_121(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(None)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_122(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = None
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_123(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode(None, "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_124(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", None) if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_125(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_126(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", ) if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_127(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(None).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_128(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(2).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_129(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("XXasciiXX", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_130(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ASCII", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_131(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "XXreplaceXX") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_132(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "REPLACE") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_133(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "XXObjectXX"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_134(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_135(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "OBJECT"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_136(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = None
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_137(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "XXidXX": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_138(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "ID": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_139(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "XXtypeXX": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_140(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "TYPE": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_141(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "XXobjectXX": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_142(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "OBJECT": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_143(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "XXgenerationXX": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_144(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "GENERATION": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_145(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "XXcontent_sha1XX": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_146(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "CONTENT_SHA1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_147(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(None),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_148(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(None)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_149(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = None
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_150(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get(None) == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_151(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("XXtypeXX") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_152(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("TYPE") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_153(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") != "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_154(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "XXPageXX"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_155(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_156(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "PAGE"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_157(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(None):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_158(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = None
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_159(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "XXidXX": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_160(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "ID": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_161(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "XXtypeXX": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_162(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "TYPE": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_163(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "XXPageXX",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_164(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_165(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "PAGE",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_166(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "XXxref_hintXX": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_167(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "XREF_HINT": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_168(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["XXidXX"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_169(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["ID"],
        }
        children.insert(i, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_170(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(None, c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_171(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, None)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_172(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(c_page)

    root["children"] = children
    return root


def x_explore_pdf__mutmut_173(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, )

    root["children"] = children
    return root


def x_explore_pdf__mutmut_174(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["children"] = None
    return root


def x_explore_pdf__mutmut_175(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["XXchildrenXX"] = children
    return root


def x_explore_pdf__mutmut_176(pdf: PdfSource) -> Dict[str, Any]:
    """Return a JSON-serializable *tree* describing the PDF's nodes.

    The structure is deterministic for a given set of input bytes. When
    PyMuPDF (``fitz``) is available, the function uses the cross
    reference (xref) table to enumerate objects and page nodes. When not
    available, it falls back to scanning for ``obj`` / ``endobj`` blocks.

    The returned dictionary has the following shape (fields may be
    omitted when data is unavailable):

    .. code-block:: json

        {
          "id": "pdf:<sha1>",
          "type": "Document",
          "size": 12345,
          "children": [
            {"id": "page:0000", "type": "Page", ...},
            {"id": "obj:000001", "type": "XObject", ...}
          ]
        }

    Each node includes a deterministic ``id`` suitable as a "name node".
    """
    data = load_pdf_bytes(pdf)

    root: Dict[str, Any] = {
        "id": f"pdf:{_sha1(data)}",
        "type": "Document",
        "size": len(data),
        "children": [],
    }

    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=data, filetype="pdf")
        # Pages as first-class nodes
        for page_index in range(doc.page_count):
            node = {
                "id": f"page:{page_index:04d}",
                "type": "Page",
                "index": page_index,
                "bbox": list(doc.load_page(page_index).bound()),  # [x0,y0,x1,y1]
            }
            root["children"].append(node)

        # XRef objects
        xref_len = doc.xref_length()
        for xref in range(1, xref_len):
            try:
                s = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                s = ""
            s_bytes = s.encode("latin-1", "replace") if isinstance(s, str) else b""
            # Type detection
            m = _TYPE_RE.search(s_bytes)
            pdf_type = m.group(1).decode("ascii", "replace") if m else "Object"
            node = {
                "id": f"obj:{xref:06d}",
                "type": pdf_type,
                "xref": xref,
                "is_stream": bool(doc.xref_is_stream(xref)),
                "content_sha1": _sha1(s_bytes) if s_bytes else None,
            }
            root["children"].append(node)

        doc.close()
        return root
    except Exception:
        # Fallback: regex-based object scanning (no third-party deps)
        pass

    # Regex fallback: enumerate uncompressed objects
    children: List[Dict[str, Any]] = []
    for m in _OBJ_RE.finditer(data):
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        start = m.end()
        end_match = _ENDOBJ_RE.search(data, start)
        end = end_match.start() if end_match else start
        slice_bytes = data[start:end]
        # Guess type
        t = _TYPE_RE.search(slice_bytes)
        pdf_type = t.group(1).decode("ascii", "replace") if t else "Object"
        node = {
            "id": f"obj:{obj_num:06d}:{gen_num:05d}",
            "type": pdf_type,
            "object": obj_num,
            "generation": gen_num,
            "content_sha1": _sha1(slice_bytes),
        }
        children.append(node)

    # Also derive simple page nodes by searching for '/Type /Page'
    page_nodes = [c for c in children if c.get("type") == "Page"]
    for i, c in enumerate(page_nodes):
        # Provide deterministic page IDs independent from object numbers
        c_page = {
            "id": f"page:{i:04d}",
            "type": "Page",
            "xref_hint": c["id"],
        }
        children.insert(i, c_page)

    root["CHILDREN"] = children
    return root

x_explore_pdf__mutmut_mutants : ClassVar[MutantDict] = {
'x_explore_pdf__mutmut_1': x_explore_pdf__mutmut_1, 
    'x_explore_pdf__mutmut_2': x_explore_pdf__mutmut_2, 
    'x_explore_pdf__mutmut_3': x_explore_pdf__mutmut_3, 
    'x_explore_pdf__mutmut_4': x_explore_pdf__mutmut_4, 
    'x_explore_pdf__mutmut_5': x_explore_pdf__mutmut_5, 
    'x_explore_pdf__mutmut_6': x_explore_pdf__mutmut_6, 
    'x_explore_pdf__mutmut_7': x_explore_pdf__mutmut_7, 
    'x_explore_pdf__mutmut_8': x_explore_pdf__mutmut_8, 
    'x_explore_pdf__mutmut_9': x_explore_pdf__mutmut_9, 
    'x_explore_pdf__mutmut_10': x_explore_pdf__mutmut_10, 
    'x_explore_pdf__mutmut_11': x_explore_pdf__mutmut_11, 
    'x_explore_pdf__mutmut_12': x_explore_pdf__mutmut_12, 
    'x_explore_pdf__mutmut_13': x_explore_pdf__mutmut_13, 
    'x_explore_pdf__mutmut_14': x_explore_pdf__mutmut_14, 
    'x_explore_pdf__mutmut_15': x_explore_pdf__mutmut_15, 
    'x_explore_pdf__mutmut_16': x_explore_pdf__mutmut_16, 
    'x_explore_pdf__mutmut_17': x_explore_pdf__mutmut_17, 
    'x_explore_pdf__mutmut_18': x_explore_pdf__mutmut_18, 
    'x_explore_pdf__mutmut_19': x_explore_pdf__mutmut_19, 
    'x_explore_pdf__mutmut_20': x_explore_pdf__mutmut_20, 
    'x_explore_pdf__mutmut_21': x_explore_pdf__mutmut_21, 
    'x_explore_pdf__mutmut_22': x_explore_pdf__mutmut_22, 
    'x_explore_pdf__mutmut_23': x_explore_pdf__mutmut_23, 
    'x_explore_pdf__mutmut_24': x_explore_pdf__mutmut_24, 
    'x_explore_pdf__mutmut_25': x_explore_pdf__mutmut_25, 
    'x_explore_pdf__mutmut_26': x_explore_pdf__mutmut_26, 
    'x_explore_pdf__mutmut_27': x_explore_pdf__mutmut_27, 
    'x_explore_pdf__mutmut_28': x_explore_pdf__mutmut_28, 
    'x_explore_pdf__mutmut_29': x_explore_pdf__mutmut_29, 
    'x_explore_pdf__mutmut_30': x_explore_pdf__mutmut_30, 
    'x_explore_pdf__mutmut_31': x_explore_pdf__mutmut_31, 
    'x_explore_pdf__mutmut_32': x_explore_pdf__mutmut_32, 
    'x_explore_pdf__mutmut_33': x_explore_pdf__mutmut_33, 
    'x_explore_pdf__mutmut_34': x_explore_pdf__mutmut_34, 
    'x_explore_pdf__mutmut_35': x_explore_pdf__mutmut_35, 
    'x_explore_pdf__mutmut_36': x_explore_pdf__mutmut_36, 
    'x_explore_pdf__mutmut_37': x_explore_pdf__mutmut_37, 
    'x_explore_pdf__mutmut_38': x_explore_pdf__mutmut_38, 
    'x_explore_pdf__mutmut_39': x_explore_pdf__mutmut_39, 
    'x_explore_pdf__mutmut_40': x_explore_pdf__mutmut_40, 
    'x_explore_pdf__mutmut_41': x_explore_pdf__mutmut_41, 
    'x_explore_pdf__mutmut_42': x_explore_pdf__mutmut_42, 
    'x_explore_pdf__mutmut_43': x_explore_pdf__mutmut_43, 
    'x_explore_pdf__mutmut_44': x_explore_pdf__mutmut_44, 
    'x_explore_pdf__mutmut_45': x_explore_pdf__mutmut_45, 
    'x_explore_pdf__mutmut_46': x_explore_pdf__mutmut_46, 
    'x_explore_pdf__mutmut_47': x_explore_pdf__mutmut_47, 
    'x_explore_pdf__mutmut_48': x_explore_pdf__mutmut_48, 
    'x_explore_pdf__mutmut_49': x_explore_pdf__mutmut_49, 
    'x_explore_pdf__mutmut_50': x_explore_pdf__mutmut_50, 
    'x_explore_pdf__mutmut_51': x_explore_pdf__mutmut_51, 
    'x_explore_pdf__mutmut_52': x_explore_pdf__mutmut_52, 
    'x_explore_pdf__mutmut_53': x_explore_pdf__mutmut_53, 
    'x_explore_pdf__mutmut_54': x_explore_pdf__mutmut_54, 
    'x_explore_pdf__mutmut_55': x_explore_pdf__mutmut_55, 
    'x_explore_pdf__mutmut_56': x_explore_pdf__mutmut_56, 
    'x_explore_pdf__mutmut_57': x_explore_pdf__mutmut_57, 
    'x_explore_pdf__mutmut_58': x_explore_pdf__mutmut_58, 
    'x_explore_pdf__mutmut_59': x_explore_pdf__mutmut_59, 
    'x_explore_pdf__mutmut_60': x_explore_pdf__mutmut_60, 
    'x_explore_pdf__mutmut_61': x_explore_pdf__mutmut_61, 
    'x_explore_pdf__mutmut_62': x_explore_pdf__mutmut_62, 
    'x_explore_pdf__mutmut_63': x_explore_pdf__mutmut_63, 
    'x_explore_pdf__mutmut_64': x_explore_pdf__mutmut_64, 
    'x_explore_pdf__mutmut_65': x_explore_pdf__mutmut_65, 
    'x_explore_pdf__mutmut_66': x_explore_pdf__mutmut_66, 
    'x_explore_pdf__mutmut_67': x_explore_pdf__mutmut_67, 
    'x_explore_pdf__mutmut_68': x_explore_pdf__mutmut_68, 
    'x_explore_pdf__mutmut_69': x_explore_pdf__mutmut_69, 
    'x_explore_pdf__mutmut_70': x_explore_pdf__mutmut_70, 
    'x_explore_pdf__mutmut_71': x_explore_pdf__mutmut_71, 
    'x_explore_pdf__mutmut_72': x_explore_pdf__mutmut_72, 
    'x_explore_pdf__mutmut_73': x_explore_pdf__mutmut_73, 
    'x_explore_pdf__mutmut_74': x_explore_pdf__mutmut_74, 
    'x_explore_pdf__mutmut_75': x_explore_pdf__mutmut_75, 
    'x_explore_pdf__mutmut_76': x_explore_pdf__mutmut_76, 
    'x_explore_pdf__mutmut_77': x_explore_pdf__mutmut_77, 
    'x_explore_pdf__mutmut_78': x_explore_pdf__mutmut_78, 
    'x_explore_pdf__mutmut_79': x_explore_pdf__mutmut_79, 
    'x_explore_pdf__mutmut_80': x_explore_pdf__mutmut_80, 
    'x_explore_pdf__mutmut_81': x_explore_pdf__mutmut_81, 
    'x_explore_pdf__mutmut_82': x_explore_pdf__mutmut_82, 
    'x_explore_pdf__mutmut_83': x_explore_pdf__mutmut_83, 
    'x_explore_pdf__mutmut_84': x_explore_pdf__mutmut_84, 
    'x_explore_pdf__mutmut_85': x_explore_pdf__mutmut_85, 
    'x_explore_pdf__mutmut_86': x_explore_pdf__mutmut_86, 
    'x_explore_pdf__mutmut_87': x_explore_pdf__mutmut_87, 
    'x_explore_pdf__mutmut_88': x_explore_pdf__mutmut_88, 
    'x_explore_pdf__mutmut_89': x_explore_pdf__mutmut_89, 
    'x_explore_pdf__mutmut_90': x_explore_pdf__mutmut_90, 
    'x_explore_pdf__mutmut_91': x_explore_pdf__mutmut_91, 
    'x_explore_pdf__mutmut_92': x_explore_pdf__mutmut_92, 
    'x_explore_pdf__mutmut_93': x_explore_pdf__mutmut_93, 
    'x_explore_pdf__mutmut_94': x_explore_pdf__mutmut_94, 
    'x_explore_pdf__mutmut_95': x_explore_pdf__mutmut_95, 
    'x_explore_pdf__mutmut_96': x_explore_pdf__mutmut_96, 
    'x_explore_pdf__mutmut_97': x_explore_pdf__mutmut_97, 
    'x_explore_pdf__mutmut_98': x_explore_pdf__mutmut_98, 
    'x_explore_pdf__mutmut_99': x_explore_pdf__mutmut_99, 
    'x_explore_pdf__mutmut_100': x_explore_pdf__mutmut_100, 
    'x_explore_pdf__mutmut_101': x_explore_pdf__mutmut_101, 
    'x_explore_pdf__mutmut_102': x_explore_pdf__mutmut_102, 
    'x_explore_pdf__mutmut_103': x_explore_pdf__mutmut_103, 
    'x_explore_pdf__mutmut_104': x_explore_pdf__mutmut_104, 
    'x_explore_pdf__mutmut_105': x_explore_pdf__mutmut_105, 
    'x_explore_pdf__mutmut_106': x_explore_pdf__mutmut_106, 
    'x_explore_pdf__mutmut_107': x_explore_pdf__mutmut_107, 
    'x_explore_pdf__mutmut_108': x_explore_pdf__mutmut_108, 
    'x_explore_pdf__mutmut_109': x_explore_pdf__mutmut_109, 
    'x_explore_pdf__mutmut_110': x_explore_pdf__mutmut_110, 
    'x_explore_pdf__mutmut_111': x_explore_pdf__mutmut_111, 
    'x_explore_pdf__mutmut_112': x_explore_pdf__mutmut_112, 
    'x_explore_pdf__mutmut_113': x_explore_pdf__mutmut_113, 
    'x_explore_pdf__mutmut_114': x_explore_pdf__mutmut_114, 
    'x_explore_pdf__mutmut_115': x_explore_pdf__mutmut_115, 
    'x_explore_pdf__mutmut_116': x_explore_pdf__mutmut_116, 
    'x_explore_pdf__mutmut_117': x_explore_pdf__mutmut_117, 
    'x_explore_pdf__mutmut_118': x_explore_pdf__mutmut_118, 
    'x_explore_pdf__mutmut_119': x_explore_pdf__mutmut_119, 
    'x_explore_pdf__mutmut_120': x_explore_pdf__mutmut_120, 
    'x_explore_pdf__mutmut_121': x_explore_pdf__mutmut_121, 
    'x_explore_pdf__mutmut_122': x_explore_pdf__mutmut_122, 
    'x_explore_pdf__mutmut_123': x_explore_pdf__mutmut_123, 
    'x_explore_pdf__mutmut_124': x_explore_pdf__mutmut_124, 
    'x_explore_pdf__mutmut_125': x_explore_pdf__mutmut_125, 
    'x_explore_pdf__mutmut_126': x_explore_pdf__mutmut_126, 
    'x_explore_pdf__mutmut_127': x_explore_pdf__mutmut_127, 
    'x_explore_pdf__mutmut_128': x_explore_pdf__mutmut_128, 
    'x_explore_pdf__mutmut_129': x_explore_pdf__mutmut_129, 
    'x_explore_pdf__mutmut_130': x_explore_pdf__mutmut_130, 
    'x_explore_pdf__mutmut_131': x_explore_pdf__mutmut_131, 
    'x_explore_pdf__mutmut_132': x_explore_pdf__mutmut_132, 
    'x_explore_pdf__mutmut_133': x_explore_pdf__mutmut_133, 
    'x_explore_pdf__mutmut_134': x_explore_pdf__mutmut_134, 
    'x_explore_pdf__mutmut_135': x_explore_pdf__mutmut_135, 
    'x_explore_pdf__mutmut_136': x_explore_pdf__mutmut_136, 
    'x_explore_pdf__mutmut_137': x_explore_pdf__mutmut_137, 
    'x_explore_pdf__mutmut_138': x_explore_pdf__mutmut_138, 
    'x_explore_pdf__mutmut_139': x_explore_pdf__mutmut_139, 
    'x_explore_pdf__mutmut_140': x_explore_pdf__mutmut_140, 
    'x_explore_pdf__mutmut_141': x_explore_pdf__mutmut_141, 
    'x_explore_pdf__mutmut_142': x_explore_pdf__mutmut_142, 
    'x_explore_pdf__mutmut_143': x_explore_pdf__mutmut_143, 
    'x_explore_pdf__mutmut_144': x_explore_pdf__mutmut_144, 
    'x_explore_pdf__mutmut_145': x_explore_pdf__mutmut_145, 
    'x_explore_pdf__mutmut_146': x_explore_pdf__mutmut_146, 
    'x_explore_pdf__mutmut_147': x_explore_pdf__mutmut_147, 
    'x_explore_pdf__mutmut_148': x_explore_pdf__mutmut_148, 
    'x_explore_pdf__mutmut_149': x_explore_pdf__mutmut_149, 
    'x_explore_pdf__mutmut_150': x_explore_pdf__mutmut_150, 
    'x_explore_pdf__mutmut_151': x_explore_pdf__mutmut_151, 
    'x_explore_pdf__mutmut_152': x_explore_pdf__mutmut_152, 
    'x_explore_pdf__mutmut_153': x_explore_pdf__mutmut_153, 
    'x_explore_pdf__mutmut_154': x_explore_pdf__mutmut_154, 
    'x_explore_pdf__mutmut_155': x_explore_pdf__mutmut_155, 
    'x_explore_pdf__mutmut_156': x_explore_pdf__mutmut_156, 
    'x_explore_pdf__mutmut_157': x_explore_pdf__mutmut_157, 
    'x_explore_pdf__mutmut_158': x_explore_pdf__mutmut_158, 
    'x_explore_pdf__mutmut_159': x_explore_pdf__mutmut_159, 
    'x_explore_pdf__mutmut_160': x_explore_pdf__mutmut_160, 
    'x_explore_pdf__mutmut_161': x_explore_pdf__mutmut_161, 
    'x_explore_pdf__mutmut_162': x_explore_pdf__mutmut_162, 
    'x_explore_pdf__mutmut_163': x_explore_pdf__mutmut_163, 
    'x_explore_pdf__mutmut_164': x_explore_pdf__mutmut_164, 
    'x_explore_pdf__mutmut_165': x_explore_pdf__mutmut_165, 
    'x_explore_pdf__mutmut_166': x_explore_pdf__mutmut_166, 
    'x_explore_pdf__mutmut_167': x_explore_pdf__mutmut_167, 
    'x_explore_pdf__mutmut_168': x_explore_pdf__mutmut_168, 
    'x_explore_pdf__mutmut_169': x_explore_pdf__mutmut_169, 
    'x_explore_pdf__mutmut_170': x_explore_pdf__mutmut_170, 
    'x_explore_pdf__mutmut_171': x_explore_pdf__mutmut_171, 
    'x_explore_pdf__mutmut_172': x_explore_pdf__mutmut_172, 
    'x_explore_pdf__mutmut_173': x_explore_pdf__mutmut_173, 
    'x_explore_pdf__mutmut_174': x_explore_pdf__mutmut_174, 
    'x_explore_pdf__mutmut_175': x_explore_pdf__mutmut_175, 
    'x_explore_pdf__mutmut_176': x_explore_pdf__mutmut_176
}

def explore_pdf(*args, **kwargs):
    result = _mutmut_trampoline(x_explore_pdf__mutmut_orig, x_explore_pdf__mutmut_mutants, args, kwargs)
    return result 

explore_pdf.__signature__ = _mutmut_signature(x_explore_pdf__mutmut_orig)
x_explore_pdf__mutmut_orig.__name__ = 'x_explore_pdf'

#def store_recipient_credentials(email: str,recipient_secret: str,key: str | None = None):

 #   with open("recipient.txt", "a") as file:
  #      file.write(f"Email: {email},Secret: {recipient_secret},Key: {key}\n")

__all__ = [
    "METHODS",
    "register_method",
    "get_method",
    "apply_watermark",
    "read_watermark",
    "explore_pdf",
    "is_watermarking_applicable"
    #"send_email_with_pdf"
]

