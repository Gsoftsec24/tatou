"""watermarking_method.py

Abstract base classes and common utilities for PDF watermarking methods.

This module defines the interface that all watermarking methods must
implement, along with a few lightweight helpers that concrete
implementations can import. The goal is to keep the contract stable and
clear, while leaving algorithmic details up to each method.

Design highlights
-----------------
- Modern Python (3.10+), with type hints and docstrings.
- Standard library only in this file. Concrete methods may optionally
  depend on third‑party libraries such as *PyMuPDF* (a.k.a. ``fitz``).
- Stateless API: methods receive a PDF input and return a new PDF as
  ``bytes``; no in‑place mutation or file I/O is required by the
  interface (callers may choose to write the returned bytes to disk).

Required interface
------------------
Concrete implementations must subclass :class:`WatermarkingMethod` and
implement the two abstract methods:

``add_watermark(pdf, secret, key, position) -> bytes``
    Produce a new watermarked PDF (as ``bytes``) by embedding the
    provided secret using the given key. The optional ``position``
    string can include method‑specific placement or strategy hints.

``read_secret(pdf, key) -> str``
    Recover and return the embedded secret from the given PDF using the
    provided key. Implementations should raise
    :class:`SecretNotFoundError` when no recognizable watermark is
    present and :class:`InvalidKeyError` when the key is incorrect.

Utilities
---------
This module also exposes :func:`load_pdf_bytes` and :func:`is_pdf_bytes`
which are convenience helpers many implementations will find useful.

"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import IO, ClassVar, TypeAlias, Union
import io
import os

# ----------------------------
# Public type aliases & errors
# ----------------------------

PdfSource: TypeAlias = Union[bytes, str, os.PathLike[str], IO[bytes]]
"""Accepted input type for a PDF document.

Implementations should *not* assume the input is a file path; always call
:func:`load_pdf_bytes` to normalize a :class:`PdfSource` into
``bytes`` before processing.
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


class WatermarkingError(Exception):
    """Base class for all watermarking-related errors."""


class SecretNotFoundError(WatermarkingError):
    """Raised when a watermark/secret cannot be found in the PDF."""


class InvalidKeyError(WatermarkingError):
    """Raised when the provided key does not validate/decrypt correctly."""


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_orig(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_1(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = None
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_2(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(None)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_3(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(None, "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_4(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), None) as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_5(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open("rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_6(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), ) as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_7(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(None), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_8(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "XXrbXX") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_9(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "RB") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_10(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = None
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_11(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(None, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_12(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, None):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_13(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr("read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_14(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, ):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_15(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "XXreadXX"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_16(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "READ"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_17(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = None  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_18(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            None
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_19(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "XXUnsupported PdfSource; expected bytes, path, or binary IOXX"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_20(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "unsupported pdfsource; expected bytes, path, or binary io"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_21(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "UNSUPPORTED PDFSOURCE; EXPECTED BYTES, PATH, OR BINARY IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_22(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") and b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_23(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_24(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(None) or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_25(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"XX%PDFXX") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_26(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%pdf") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_27(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_28(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"XX%%EOFXX" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_29(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%eof" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_30(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_31(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" in data:
        raise ValueError("Input does not look like a valid PDF (missing %PDF header or %%EOF marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_32(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError(None)
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_33(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("XXInput does not look like a valid PDF (missing %PDF header or %%EOF marker)XX")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_34(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("input does not look like a valid pdf (missing %pdf header or %%eof marker)")
    return data


# ----------------------------
# Helper functions
# ----------------------------

def x_load_pdf_bytes__mutmut_35(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not data.strip().startswith(b"%PDF") or b"%%EOF" not in data:
        raise ValueError("INPUT DOES NOT LOOK LIKE A VALID PDF (MISSING %PDF HEADER OR %%EOF MARKER)")
    return data

x_load_pdf_bytes__mutmut_mutants : ClassVar[MutantDict] = {
'x_load_pdf_bytes__mutmut_1': x_load_pdf_bytes__mutmut_1, 
    'x_load_pdf_bytes__mutmut_2': x_load_pdf_bytes__mutmut_2, 
    'x_load_pdf_bytes__mutmut_3': x_load_pdf_bytes__mutmut_3, 
    'x_load_pdf_bytes__mutmut_4': x_load_pdf_bytes__mutmut_4, 
    'x_load_pdf_bytes__mutmut_5': x_load_pdf_bytes__mutmut_5, 
    'x_load_pdf_bytes__mutmut_6': x_load_pdf_bytes__mutmut_6, 
    'x_load_pdf_bytes__mutmut_7': x_load_pdf_bytes__mutmut_7, 
    'x_load_pdf_bytes__mutmut_8': x_load_pdf_bytes__mutmut_8, 
    'x_load_pdf_bytes__mutmut_9': x_load_pdf_bytes__mutmut_9, 
    'x_load_pdf_bytes__mutmut_10': x_load_pdf_bytes__mutmut_10, 
    'x_load_pdf_bytes__mutmut_11': x_load_pdf_bytes__mutmut_11, 
    'x_load_pdf_bytes__mutmut_12': x_load_pdf_bytes__mutmut_12, 
    'x_load_pdf_bytes__mutmut_13': x_load_pdf_bytes__mutmut_13, 
    'x_load_pdf_bytes__mutmut_14': x_load_pdf_bytes__mutmut_14, 
    'x_load_pdf_bytes__mutmut_15': x_load_pdf_bytes__mutmut_15, 
    'x_load_pdf_bytes__mutmut_16': x_load_pdf_bytes__mutmut_16, 
    'x_load_pdf_bytes__mutmut_17': x_load_pdf_bytes__mutmut_17, 
    'x_load_pdf_bytes__mutmut_18': x_load_pdf_bytes__mutmut_18, 
    'x_load_pdf_bytes__mutmut_19': x_load_pdf_bytes__mutmut_19, 
    'x_load_pdf_bytes__mutmut_20': x_load_pdf_bytes__mutmut_20, 
    'x_load_pdf_bytes__mutmut_21': x_load_pdf_bytes__mutmut_21, 
    'x_load_pdf_bytes__mutmut_22': x_load_pdf_bytes__mutmut_22, 
    'x_load_pdf_bytes__mutmut_23': x_load_pdf_bytes__mutmut_23, 
    'x_load_pdf_bytes__mutmut_24': x_load_pdf_bytes__mutmut_24, 
    'x_load_pdf_bytes__mutmut_25': x_load_pdf_bytes__mutmut_25, 
    'x_load_pdf_bytes__mutmut_26': x_load_pdf_bytes__mutmut_26, 
    'x_load_pdf_bytes__mutmut_27': x_load_pdf_bytes__mutmut_27, 
    'x_load_pdf_bytes__mutmut_28': x_load_pdf_bytes__mutmut_28, 
    'x_load_pdf_bytes__mutmut_29': x_load_pdf_bytes__mutmut_29, 
    'x_load_pdf_bytes__mutmut_30': x_load_pdf_bytes__mutmut_30, 
    'x_load_pdf_bytes__mutmut_31': x_load_pdf_bytes__mutmut_31, 
    'x_load_pdf_bytes__mutmut_32': x_load_pdf_bytes__mutmut_32, 
    'x_load_pdf_bytes__mutmut_33': x_load_pdf_bytes__mutmut_33, 
    'x_load_pdf_bytes__mutmut_34': x_load_pdf_bytes__mutmut_34, 
    'x_load_pdf_bytes__mutmut_35': x_load_pdf_bytes__mutmut_35
}

def load_pdf_bytes(*args, **kwargs):
    result = _mutmut_trampoline(x_load_pdf_bytes__mutmut_orig, x_load_pdf_bytes__mutmut_mutants, args, kwargs)
    return result 

load_pdf_bytes.__signature__ = _mutmut_signature(x_load_pdf_bytes__mutmut_orig)
x_load_pdf_bytes__mutmut_orig.__name__ = 'x_load_pdf_bytes'


def x_is_pdf_bytes__mutmut_orig(data: bytes) -> bool:
    """Lightweight check that the data looks like a PDF file.

    This is intentionally permissive: it verifies the standard header
    magic (``%PDF-``). Trailers (``%%EOF``) can be absent in incremental
    updates, so we don't strictly require them here.
    """
    return data.startswith(b"%PDF-")


def x_is_pdf_bytes__mutmut_1(data: bytes) -> bool:
    """Lightweight check that the data looks like a PDF file.

    This is intentionally permissive: it verifies the standard header
    magic (``%PDF-``). Trailers (``%%EOF``) can be absent in incremental
    updates, so we don't strictly require them here.
    """
    return data.startswith(None)


def x_is_pdf_bytes__mutmut_2(data: bytes) -> bool:
    """Lightweight check that the data looks like a PDF file.

    This is intentionally permissive: it verifies the standard header
    magic (``%PDF-``). Trailers (``%%EOF``) can be absent in incremental
    updates, so we don't strictly require them here.
    """
    return data.startswith(b"XX%PDF-XX")


def x_is_pdf_bytes__mutmut_3(data: bytes) -> bool:
    """Lightweight check that the data looks like a PDF file.

    This is intentionally permissive: it verifies the standard header
    magic (``%PDF-``). Trailers (``%%EOF``) can be absent in incremental
    updates, so we don't strictly require them here.
    """
    return data.startswith(b"%pdf-")


def x_is_pdf_bytes__mutmut_4(data: bytes) -> bool:
    """Lightweight check that the data looks like a PDF file.

    This is intentionally permissive: it verifies the standard header
    magic (``%PDF-``). Trailers (``%%EOF``) can be absent in incremental
    updates, so we don't strictly require them here.
    """
    return data.startswith(b"%PDF-")

x_is_pdf_bytes__mutmut_mutants : ClassVar[MutantDict] = {
'x_is_pdf_bytes__mutmut_1': x_is_pdf_bytes__mutmut_1, 
    'x_is_pdf_bytes__mutmut_2': x_is_pdf_bytes__mutmut_2, 
    'x_is_pdf_bytes__mutmut_3': x_is_pdf_bytes__mutmut_3, 
    'x_is_pdf_bytes__mutmut_4': x_is_pdf_bytes__mutmut_4
}

def is_pdf_bytes(*args, **kwargs):
    result = _mutmut_trampoline(x_is_pdf_bytes__mutmut_orig, x_is_pdf_bytes__mutmut_mutants, args, kwargs)
    return result 

is_pdf_bytes.__signature__ = _mutmut_signature(x_is_pdf_bytes__mutmut_orig)
x_is_pdf_bytes__mutmut_orig.__name__ = 'x_is_pdf_bytes'


# ---------------------------------
# Abstract base class (the contract)
# ---------------------------------

class WatermarkingMethod(ABC):
    """Abstract base class for PDF watermarking algorithms.

    Subclasses define how secrets are embedded into and extracted from a
    PDF document. All I/O is performed in-memory; callers manage reading
    from and writing to files as needed.
    """

    #: Optional, human-friendly unique identifier for the method.
    #: Concrete implementations should override this with a short name
    #: (e.g., "toy-eof", "xmp-metadata", "object-stream").
    name: ClassVar[str] = "abstract"
    
    
    @staticmethod
    @abstractmethod
    def get_usage() -> str:
        """Return a a string containing a description of the expected usage.

        It's highly recommended to provide a description if custom position 
        is expected.

        Returns
        -------
        str
            Usage description.
        """
        raise NotImplementedError

    @abstractmethod
    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with an embedded watermark.

        Implementations *must* be deterministic given identical inputs
        to support reproducible pipelines and testing.

        Parameters
        ----------
        pdf:
            The source PDF (bytes, path, or binary file object).
        secret:
            The cleartext secret to embed. Implementations may apply
            authenticated encryption or integrity checks using ``key``.
        key:
            A string used to derive encryption/obfuscation material or
            as a password. The semantics are method-specific.
        position:
            Optional placement or strategy hint (method-specific). For
            example: a page index, object number, or named region.

        Returns
        -------
        bytes
            The complete, watermarked PDF as a byte string.

        Raises
        ------
        WatermarkingError
            On any failure to embed the watermark.
        ValueError
            If inputs are invalid (e.g., not a PDF or empty secret).
        """
        raise NotImplementedError
        
    @abstractmethod
    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        """Return whether the method is applicable on this specific method 

        Parameters
        ----------
        pdf:
            The source PDF (bytes, path, or binary file object).
        secret:
            The cleartext secret to embed. Implementations may apply
            authenticated encryption or integrity checks using ``key``.
        key:
            A string used to derive encryption/obfuscation material or
            as a password. The semantics are method-specific.
        position:
            Optional placement or strategy hint (method-specific). For
            example: a page index, object number, or named region.

        Returns
        -------
        bool
            If true, calling add_watermark should not return errors.

        Raises
        ------
        ValueError
            If inputs are invalid (e.g., not a PDF or empty secret).
        """
        raise NotImplementedError

    @abstractmethod
    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """Extract and return the embedded secret from ``pdf``.

        Parameters
        ----------
        pdf:
            The candidate PDF containing an embedded secret.
        key:
            The key required to validate/decrypt the watermark.

        Returns
        -------
        str
            The recovered secret.

        Raises
        ------
        SecretNotFoundError
            If no recognizable watermark is present in the PDF.
        InvalidKeyError
            If the provided key does not validate or decrypt correctly.
        WatermarkingError
            For other extraction errors.
        """
        raise NotImplementedError


__all__ = [
    "PdfSource",
    "WatermarkingError",
    "SecretNotFoundError",
    "InvalidKeyError",
    "load_pdf_bytes",
    "is_pdf_bytes",
    "WatermarkingMethod",
]

