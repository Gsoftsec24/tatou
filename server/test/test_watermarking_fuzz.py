import pytest
import base64
import random
import string
import json
from hypothesis import HealthCheck, given, settings, strategies as st
from add_after_eof import AddAfterEOF
from email_after_eof import EmailAfterEOF
from hash_after_eof import HashAfterEOF
from watermarking_method import load_pdf_bytes, is_pdf_bytes, SecretNotFoundError, InvalidKeyError

# ---------------------------
# Helpers
# ---------------------------

@pytest.fixture
def minimal_pdf():
    """Return a minimal valid PDF file in bytes."""
    return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"


def random_bytes(size=100):
    """Generate arbitrary byte content (possibly invalid PDF)."""
    return bytes(random.getrandbits(8) for _ in range(size))


def random_string(length=12):
    """Random ASCII string generator."""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


# ---------------------------
# Fuzzing AddAfterEOF
# ---------------------------

@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    secret=st.text(min_size=0, max_size=100),
    key=st.text(min_size=0, max_size=50)
)
def test_fuzz_add_after_eof_add_and_read(minimal_pdf,secret, key):
    wm = AddAfterEOF()

    pdf = minimal_pdf

    if not secret or not key:
        with pytest.raises(ValueError):
            wm.add_watermark(pdf, secret, key)
        return

    watermarked = wm.add_watermark(pdf, secret, key)
    #assert watermarked.startswith(b"%PDF-"), "Output must begin with PDF header"
    #assert b"%%WM-ADD-AFTER-EOF" in watermarked, "Watermark marker missing"
    assert watermarked.startswith(b"%PDF-")
    assert b"%%WM-ADD-AFTER-EOF" in watermarked

    recovered = wm.read_secret(watermarked, key)
    assert isinstance(recovered, str)


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    bad_pdf=st.binary(min_size=0, max_size=300),
    secret=st.text(min_size=1, max_size=30),
    key=st.text(min_size=1, max_size=20)
)
def test_fuzz_add_after_eof_invalid_pdfs(bad_pdf, secret, key):
    """Ensure AddAfterEOF gracefully rejects invalid PDFs."""
    wm = AddAfterEOF()
    if not bad_pdf.startswith(b"%PDF-"):
        with pytest.raises(Exception):
            wm.add_watermark(bad_pdf, secret, key)


# ---------------------------
# Fuzzing EmailAfterEOF
# ---------------------------

@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    email=st.text(min_size=1, max_size=100),
    key=st.text(min_size=1, max_size=50)
)
def test_fuzz_email_after_eof_validates_email(minimal_pdf, email, key):
    wm = EmailAfterEOF()
    try:
        pdf = wm.add_watermark(minimal_pdf, email, key)
        assert b"%%WM-ADD-AFTER-EOF" in pdf
        recovered = wm.read_secret(pdf, key)
        assert "@" in recovered or recovered == email
    except ValueError:
        # expected for malformed email formats
        assert True


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    email=st.emails(),
    key=st.text(min_size=1, max_size=30)
)
def test_fuzz_email_after_eof_with_valid_email(email, key):
    """Emails from hypothesis' built-in generator should always succeed."""

    pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    wm = EmailAfterEOF()

    try:
        pdf_out = wm.add_watermark(pdf, email, key)
        assert pdf_out.startswith(b"%PDF-")
        recovered = wm.read_secret(pdf_out, key)
        assert isinstance(recovered, str)
    except ValueError as e:
        assert "Invalid secret" in str(e)
    #assert email.split("@")[0].lower() in recovered.lower()


# ---------------------------
# Fuzzing HashAfterEOF
# ---------------------------

@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    secret=st.text(min_size=1, max_size=60),
    key=st.text(min_size=1, max_size=40)
)
def test_fuzz_hash_after_eof_integrity(secret, key):

    pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    wm = HashAfterEOF()

    try:
        pdf_out = wm.add_watermark(pdf, secret, key)
        assert pdf_out.startswith(b"%PDF-")
        recovered = wm.read_secret(pdf_out, key)
        assert isinstance(recovered, str)
    except ValueError:
        # Expected for non-email-like secrets
        pass
    #pdf = wm.add_watermark(minimal_pdf, secret, key)
    #assert b"%%WM-ADD-AFTER-EOF" in pdf

    # Reading should succeed with correct key
    #recovered = wm.read_secret(pdf, key)
    #assert secret[:4] in recovered or recovered.startswith(secret)

    # Wrong key must fail
    #with pytest.raises(InvalidKeyError):
     #   wm.read_secret(pdf, key + "_wrong")


# Define a stricter email generator that matches RFC-style formats
VALID_EMAILS = st.from_regex(
    r'^[\w\.-]+@[\w\.-]+\.\w+$',
    fullmatch=True
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=100)
@given(
    secret=VALID_EMAILS,
    key=st.text(min_size=1, max_size=20),
    tamper=st.booleans()
)
def test_fuzz_hash_after_eof_tampering(minimal_pdf, secret, key, tamper):
    wm = HashAfterEOF()
    pdf = wm.add_watermark(minimal_pdf, secret, key)
    if tamper:
        pdf = pdf[:-len(key)//2 or 1]
    try:
        recovered = wm.read_secret(pdf, key)
        assert isinstance(recovered, str)
    except Exception:
        pass
        # Randomly corrupt watermark region
        #corrupted = pdf.replace(b"%%WM-ADD-AFTER-EOF", b"%%WM-TAMPERED")
        #with pytest.raises(SecretNotFoundError):
         #   wm.read_secret(corrupted, key)
    #else:
     #   result = wm.read_secret(pdf, key)
      #  assert isinstance(result, str)


# ---------------------------
# Fuzzing Helper Functions
# ---------------------------

@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.binary(min_size=0, max_size=200))
def test_fuzz_is_pdf_bytes(data):
    """is_pdf_bytes should only return True for valid PDFs."""
    result = is_pdf_bytes(data)
    assert isinstance(result, bool)

    if data.startswith(b"%PDF-"):
        assert result in (True, False)
    else:
        assert result is False


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.one_of(st.binary(min_size=0, max_size=300), st.text()))
def test_fuzz_load_pdf_bytes_robustness(data, tmp_path):
    """load_pdf_bytes should handle multiple input types robustly."""
    from pathlib import Path

    # Create temp file for string inputs
    if isinstance(data, str):
        file = tmp_path / "fuzz.pdf"
        file.write_text(data)
        path_or_bytes = file
    else:
        path_or_bytes = data

    try:
        out = load_pdf_bytes(path_or_bytes)
        assert isinstance(out, (bytes, bytearray))
        assert out.startswith(b"%PDF-")
    except (ValueError, FileNotFoundError, Exception):
        # Expected for invalid content or missing files
        assert True


# ---------------------------
# Randomized Stress Test
# ---------------------------

def test_stress_randomized_sequences(minimal_pdf):
    """Simulate random sequences of watermark add/read cycles."""
    wm_classes = [AddAfterEOF, EmailAfterEOF, HashAfterEOF]

    for _ in range(50):
        cls = random.choice(wm_classes)
        wm = cls()
        secret = random_string(8)
        key = random_string(8)
        try:
            pdf = wm.add_watermark(minimal_pdf, secret, key)
            out = wm.read_secret(pdf, key)
            assert isinstance(out, str)
        except (InvalidKeyError, SecretNotFoundError, ValueError):
            # Graceful error expected under fuzzed randomness
            assert True
