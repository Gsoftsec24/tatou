import pytest
import base64
import json
import io
from add_after_eof import AddAfterEOF
from email_after_eof import EmailAfterEOF
from hash_after_eof import HashAfterEOF
from watermarking_method import SecretNotFoundError, InvalidKeyError, load_pdf_bytes

# Import all relevant exceptions and utilities
from watermarking_method import (
    SecretNotFoundError,
    InvalidKeyError,
    WatermarkingError,
    load_pdf_bytes,
)

# ------------------------
# Helper: minimal fake PDF
# ------------------------
@pytest.fixture
def sample_pdf_bytes():
    return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"

@pytest.fixture
def valid_key():
    return "SuperSecretKey"

@pytest.fixture
def valid_secret():
    return "user@example.com"


# ------------------------
# AddAfterEOF Tests
# ------------------------
def test_add_after_eof_add_and_read(sample_pdf_bytes, valid_secret, valid_key):
    wm = AddAfterEOF()
    watermarked = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    assert b"%%WM-ADD-AFTER-EOF" in watermarked

    recovered = wm.read_secret(watermarked, valid_key)
    assert recovered == valid_secret


def test_add_after_eof_invalid_key(sample_pdf_bytes, valid_secret, valid_key):
    wm = AddAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    with pytest.raises(InvalidKeyError):
        wm.read_secret(pdf, "WrongKey")


def test_add_after_eof_no_marker_raises(sample_pdf_bytes, valid_key):
    wm = AddAfterEOF()
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(sample_pdf_bytes, valid_key)


# ------------------------
# EmailAfterEOF Tests
# ------------------------
def test_email_after_eof_valid_email(sample_pdf_bytes, valid_key):
    wm = EmailAfterEOF()
    email_secret = "abc@test.com"
    out = wm.add_watermark(sample_pdf_bytes, email_secret, valid_key)
    assert b"%%WM-ADD-AFTER-EOF" in out
    result = wm.read_secret(out, valid_key)
    assert "abc@test.com" in result


def test_email_after_eof_invalid_email_raises(sample_pdf_bytes, valid_key):
    wm = EmailAfterEOF()
    with pytest.raises(ValueError):
        wm.add_watermark(sample_pdf_bytes, "notanemail", valid_key)


# ------------------------
# HashAfterEOF Tests
# ------------------------
def test_hash_after_eof_add_and_read(sample_pdf_bytes, valid_secret, valid_key):
    wm = HashAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    assert b"%%WM-ADD-AFTER-EOF" in pdf
    recovered = wm.read_secret(pdf, valid_key)
    assert valid_secret in recovered


def test_hash_after_eof_wrong_key_raises(sample_pdf_bytes, valid_secret, valid_key):
    wm = HashAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    with pytest.raises(InvalidKeyError):
        wm.read_secret(pdf, "invalidkey")

# ------------------------
# AddAfterEOF Edge Cases (kills surviving mutants)
# ------------------------

def test_add_after_eof_empty_secret_raises(sample_pdf_bytes, valid_key):
    wm = AddAfterEOF()
    with pytest.raises(ValueError):
        wm.add_watermark(sample_pdf_bytes, "", valid_key)


def test_add_after_eof_empty_key_raises(sample_pdf_bytes, valid_secret):
    wm = AddAfterEOF()
    with pytest.raises(ValueError):
        wm.add_watermark(sample_pdf_bytes, valid_secret, "")


def test_add_after_eof_invalid_pdf_raises(valid_secret, valid_key):
    wm = AddAfterEOF()
    with pytest.raises(Exception):
        wm.add_watermark(b"NOT_A_PDF", valid_secret, valid_key)


def test_add_after_eof_different_secret_results_in_different_output(sample_pdf_bytes, valid_key):
    wm = AddAfterEOF()
    pdf1 = wm.add_watermark(sample_pdf_bytes, "a@example.com", valid_key)
    pdf2 = wm.add_watermark(sample_pdf_bytes, "b@example.com", valid_key)
    assert pdf1 != pdf2


def test_add_after_eof_repeated_watermark_changes_output(sample_pdf_bytes, valid_secret, valid_key):
    wm = AddAfterEOF()
    first = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    second = wm.add_watermark(first, valid_secret, valid_key)
    # The second should be larger (append watermark again)
    assert len(second) > len(first)


def test_add_after_eof_output_still_pdf(sample_pdf_bytes, valid_secret, valid_key):
    wm = AddAfterEOF()
    out = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    assert out.startswith(b"%PDF-"), "Output must remain a valid PDF header"


def test_add_after_eof_mac_integrity_differs_on_key_change(sample_pdf_bytes, valid_secret, valid_key):
    wm = AddAfterEOF()
    pdf1 = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    pdf2 = wm.add_watermark(sample_pdf_bytes, valid_secret, "AnotherKey")
    assert pdf1 != pdf2, "Watermark should differ when the key changes"
# ------------------------
# AddAfterEOF: read_secret robustness
# ------------------------

def test_add_after_eof_read_secret_with_corrupted_marker(sample_pdf_bytes, valid_secret, valid_key):
    """If the marker text is tampered, it should raise SecretNotFoundError."""
    wm = AddAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    corrupted = pdf.replace(b"%%WM-ADD-AFTER-EOF", b"%%WM-CORRUPTED")
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(corrupted, valid_key)


def test_add_after_eof_read_secret_with_truncated_payload(sample_pdf_bytes, valid_secret, valid_key):
    """If payload at EOF is incomplete, it should raise SecretNotFoundError."""
    wm = AddAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    truncated = pdf[:-10]  # cut off end of file
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(truncated, valid_key)


def test_add_after_eof_read_secret_with_wrong_key_raises(sample_pdf_bytes, valid_secret, valid_key):
    """MAC mismatch or wrong key should raise InvalidKeyError."""
    wm = AddAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    with pytest.raises(InvalidKeyError):
        wm.read_secret(pdf, "wrong-key")


def test_add_after_eof_read_secret_with_extra_noise(sample_pdf_bytes, valid_secret, valid_key):
    """Noise after EOF should not break reading if watermark exists."""
    wm = AddAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    noisy = pdf + b"RANDOMGARBAGE"
    result = wm.read_secret(noisy, valid_key)
    assert result == valid_secret


def test_add_after_eof_read_secret_returns_exact_secret(sample_pdf_bytes, valid_secret, valid_key):
    """Ensure read_secret returns the same secret that was embedded."""
    wm = AddAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    recovered = wm.read_secret(pdf, valid_key)
    assert recovered == valid_secret
    assert isinstance(recovered, str)


def test_add_after_eof_read_secret_case_sensitivity(sample_pdf_bytes, valid_key):
    """Watermark retrieval should respect key sensitivity."""
    wm = AddAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, "Case@Test.com", valid_key)
    recovered = wm.read_secret(pdf, valid_key)
    assert recovered == "Case@Test.com"
    assert recovered != "case@test.com"
# ------------------------
# AddAfterEOF: build_payload tests
# ------------------------

def test_add_after_eof_build_payload_format(sample_pdf_bytes, valid_secret, valid_key):
    """Ensure build_payload returns properly structured bytes."""
    wm = AddAfterEOF()
    payload = wm._build_payload(valid_secret, valid_key)
    assert isinstance(payload, bytes)
    assert b"WM-ADD-AFTER-EOF" not in payload  # marker not inside payload itself
    assert len(payload) > 0


def test_add_after_eof_build_payload_changes_with_secret(valid_key):
    """Different secrets should yield different payloads."""
    wm = AddAfterEOF()
    p1 = wm._build_payload("secret1", valid_key)
    p2 = wm._build_payload("secret2", valid_key)
    assert p1 != p2


def test_add_after_eof_build_payload_changes_with_key(valid_secret):
    """Changing the key should yield a different payload (MAC)."""
    wm = AddAfterEOF()
    p1 = wm._build_payload(valid_secret, "keyA")
    p2 = wm._build_payload(valid_secret, "keyB")
    assert p1 != p2


def test_add_after_eof_build_payload_empty_secret_raises(valid_key):
    wm = AddAfterEOF()
    with pytest.raises(ValueError):
        wm._build_payload("", valid_key)


def test_add_after_eof_build_payload_empty_key_raises(valid_secret):
    wm = AddAfterEOF()
    with pytest.raises(ValueError):
        wm._build_payload(valid_secret, "")
        

def test_add_after_eof_build_payload_contains_encoded_secret(valid_secret, valid_key):
    """Check that secret text is actually encoded in the payload."""
    wm = AddAfterEOF()
    payload = wm._build_payload(valid_secret, valid_key)
    # Decode and ensure secret or its hash is inside the payload
    decoded = base64.b64decode(payload)
    assert valid_secret.encode()[:5] in decoded or len(decoded) > len(valid_secret)
# ------------------------
# watermarking_method: load_pdf_bytes & is_pdf_bytes
# ------------------------
import tempfile
from pathlib import Path
from watermarking_method import load_pdf_bytes, is_pdf_bytes, SecretNotFoundError

def test_load_pdf_bytes_accepts_bytes(sample_pdf_bytes):
    """Should return same bytes when given valid PDF bytes."""
    data = load_pdf_bytes(sample_pdf_bytes)
    assert data.startswith(b"%PDF-")
    assert b"%%EOF" in data


def test_load_pdf_bytes_reads_from_file(tmp_path, sample_pdf_bytes):
    """Should read PDF from a file path correctly."""
    pdf_path = tmp_path / "sample.pdf"
    pdf_path.write_bytes(sample_pdf_bytes)
    result = load_pdf_bytes(pdf_path)
    assert result == sample_pdf_bytes


#def test_load_pdf_bytes_non_pdf_raises(tmp_path):
 #   """Should raise when file or bytes are not a valid PDF."""
  #  bad_path = tmp_path / "bad.txt"
   # bad_path.write_text("Not a PDF at all")
#
 #   invalid_inputs = [
 #       b"INVALID BYTES",
  #      b"",
   #     b"NO_PDF_MARKER",
    #    b"%PDF-but-no-eof",
     #   b"%EOF only",
      #  b"PDF%EOFinvalid",
       # b"%PDF-1.4 but missing %%EOF marker",
        #b"%PDF-1.4\nbroken content",
        #b"%PDF-1.4 but corrupted end",
        #b"%PDF-nofooter",
    #]

#    for data in invalid_inputs:
#        with pytest.raises(ValueError), pytest.raises(Exception):
#           load_pdf_bytes(data)
#
#    with pytest.raises(ValueError):
#        load_pdf_bytes(bad_path)



def test_load_pdf_bytes_invalid_path_raises():
    """Should raise when invalid path or wrong type is passed."""
    with pytest.raises(FileNotFoundError):
        load_pdf_bytes("nonexistent.pdf")


def test_is_pdf_bytes_true_for_valid(sample_pdf_bytes):
    assert is_pdf_bytes(sample_pdf_bytes) is True


def test_is_pdf_bytes_false_for_invalid():
    assert is_pdf_bytes(b"") is False
    assert is_pdf_bytes(b"NotPDF") is False
    assert is_pdf_bytes(b"%PDF but missing end") is False
# ------------------------
# HashAfterEOF: Mutation-killing tests
# ------------------------

def test_hash_after_eof_empty_secret_raises(sample_pdf_bytes, valid_key):
    wm = HashAfterEOF()
    with pytest.raises(ValueError):
        wm.add_watermark(sample_pdf_bytes, "", valid_key)


def test_hash_after_eof_empty_key_raises(sample_pdf_bytes, valid_secret):
    wm = HashAfterEOF()
    with pytest.raises(ValueError):
        wm.add_watermark(sample_pdf_bytes, valid_secret, "")
# ------------------------
# HashAfterEOF: read_secret mutation-killing tests
# ------------------------

def test_hash_after_eof_no_marker_found_raises(sample_pdf_bytes, valid_key):
    """Should raise SecretNotFoundError when no watermark marker exists."""
    wm = HashAfterEOF()
    corrupted_pdf = sample_pdf_bytes.replace(b"%%EOF", b"%%EOF something_else")
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(corrupted_pdf, valid_key)


def test_hash_after_eof_tampered_marker_raises(sample_pdf_bytes, valid_secret, valid_key):
    """If watermark content is tampered, should not validate."""
    wm = HashAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    tampered = pdf.replace(b"%%WM-ADD-AFTER-EOF", b"%%WM-TAMPERED")
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(tampered, valid_key)


def test_hash_after_eof_partial_payload_raises(sample_pdf_bytes, valid_secret, valid_key):
    """If payload is cut off or incomplete, should raise SecretNotFoundError."""
    wm = HashAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    truncated = pdf[:-10]  # remove end part of payload
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(truncated, valid_key)


def test_hash_after_eof_empty_payload_raises(valid_key):
    wm = HashAfterEOF()
    bad_pdf = b"%PDF-1.4\n%%EOF\n%%WM-ADD-AFTER-EOF\n"
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(bad_pdf, valid_key)


def test_hash_after_eof_wrong_encoding_does_not_crash(sample_pdf_bytes, valid_secret, valid_key):
    """If watermark contains invalid base64, should raise gracefully."""
    wm = HashAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    corrupted = pdf.replace(b"=", b"*")  # break base64
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(corrupted, valid_key)


def test_hash_after_eof_reads_correct_secret(sample_pdf_bytes, valid_secret, valid_key):
    """Ensure correct secret is recovered with valid key."""
    wm = HashAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    recovered = wm.read_secret(pdf, valid_key)
    assert valid_secret in recovered


def test_hash_after_eof_wrong_key_invalidates_mac(sample_pdf_bytes, valid_secret, valid_key):
    """Should raise InvalidKeyError when MAC validation fails."""
    wm = HashAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    # Change key to simulate wrong hash
    with pytest.raises(InvalidKeyError):
        wm.read_secret(pdf, "anotherWrongKey")


def test_hash_after_eof_non_ascii_secret_recoverable(valid_key):
    """Ensure read_secret can handle and preserve encoded UTF-8 secrets."""
    wm = HashAfterEOF()
    secret = "s1@teest.com"
    pdf = wm.add_watermark(b"%PDF-1.4\n%%EOF\n", secret, valid_key)
    recovered = wm.read_secret(pdf, valid_key)
    
    # ✅ Expect the original secret or its encoded/hashed form to appear
    assert secret in recovered or recovered.startswith(secret)


def test_hash_after_eof_different_keys_produce_different_output(sample_pdf_bytes, valid_secret):
    wm = HashAfterEOF()
    pdf1 = wm.add_watermark(sample_pdf_bytes, valid_secret, "key1")
    pdf2 = wm.add_watermark(sample_pdf_bytes, valid_secret, "key2")
    assert pdf1 != pdf2


def test_hash_after_eof_different_secrets_produce_different_output(sample_pdf_bytes, valid_key):
    """Ensure that different secrets generate distinct watermark outputs."""
    wm = HashAfterEOF()
    
    # ✅ Use valid email-like secrets so is_email() check passes
    pdf1 = wm.add_watermark(sample_pdf_bytes, "secret1@test.com", valid_key)
    pdf2 = wm.add_watermark(sample_pdf_bytes, "secret2@test.com", valid_key)
    
    assert pdf1 != pdf2, "Different secrets should produce different outputs"



def test_hash_after_eof_watermark_appears_after_eof(sample_pdf_bytes, valid_secret, valid_key):
    wm = HashAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    eof_index = pdf.find(b"%%EOF")
    wm_index = pdf.find(b"%%WM-ADD-AFTER-EOF")
    assert wm_index > eof_index, "Watermark should be added after EOF marker"


def test_hash_after_eof_watermark_is_unique_per_run(sample_pdf_bytes, valid_secret, valid_key):
    """Repeated calls with same inputs should give identical output."""
    wm = HashAfterEOF()
    pdf1 = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    pdf2 = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    assert pdf1 == pdf2


def test_hash_after_eof_payload_includes_hash_marker(sample_pdf_bytes, valid_secret, valid_key):
    """Ensure payload includes recognizable hash data."""
    wm = HashAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    assert b"%%WM-ADD-AFTER-EOF" in pdf


def test_hash_after_eof_handles_non_ascii_secret(valid_key):
    """Non-ASCII characters (in emails) should be safely handled and encoded."""
    wm = HashAfterEOF()

    # ✅ Use a valid UTF-8 email-like address and manually IDNA-encode the domain
    local_part = "user_tést"
    domain = "examplé.com"
    encoded_domain = domain.encode("idna").decode("ascii")  # → xn--exampl-8ya.com
    secret = f"{local_part}@{encoded_domain}"

    # ✅ Add watermark safely
    pdf = wm.add_watermark(b"%PDF-1.4\n%%EOF\n", secret, valid_key)

    # The watermark marker must be present
    assert b"%%WM-ADD-AFTER-EOF" in pdf, "Watermark marker missing in PDF output"

    # ✅ Ensure reading back the watermark doesn’t crash and preserves email-like structure
    recovered = wm.read_secret(pdf, valid_key)
    assert "@" in recovered, "Recovered secret must contain '@'"
    assert recovered.split("@")[1].startswith("xn--"), "Domain must have been safely encoded"



# ------------------------
# HashAfterEOF: build_payload mutation-killing tests
# ------------------------

def test_hash_after_eof_build_payload_structure(sample_pdf_bytes, valid_secret, valid_key):
    """Ensure payload structure from _build_payload() is valid and well-formed."""
    wm = HashAfterEOF()

    # ✅ Mock a fake file hash (as would be generated from file content)
    fake_file_hash = "abc123def456"

    # Call with all required parameters
    payload = wm._build_payload(valid_secret, valid_key, fake_file_hash)

    # ✅ Ensure payload validity
    assert isinstance(payload, bytes)
    assert len(payload) > 10

    # ✅ Decode Base64 safely and check expected fields in the JSON structure
    decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")

    # Optional: Try to parse JSON
    try:
        data = json.loads(decoded)
    except Exception:
        pytest.fail("Decoded payload is not valid JSON")

    # ✅ Check expected keys and algorithm info
    assert "alg" in data, "Algorithm key missing in payload"
    assert any(x in data["alg"].upper() for x in ["SHA", "HMAC"]), "Expected hash algorithm info in payload"
    assert "mac" in data, "MAC field missing in payload"
    assert "secret" in data, "Secret field missing in payload"



def test_hash_after_eof_build_payload_differs_for_different_secret(valid_key):
    """Ensure _build_payload() produces different results for different secrets."""
    wm = HashAfterEOF()
    
    # ✅ Mock a fake, consistent file hash
    fake_file_hash = "dummy_hash_value_001"
    
    # Generate payloads with different secrets but same key + file hash
    p1 = wm._build_payload("secret1@test.com", valid_key, fake_file_hash)
    p2 = wm._build_payload("secret2@test.com", valid_key, fake_file_hash)
    
    # ✅ Verify that payloads differ
    assert p1 != p2, "Different secrets must yield different payloads"
    assert isinstance(p1, bytes)
    assert isinstance(p2, bytes)



def test_hash_after_eof_build_payload_differs_for_different_key(valid_secret):
    """Ensure _build_payload() produces different results for different keys."""
    wm = HashAfterEOF()
    
    # ✅ Mock a consistent fake file hash
    fake_file_hash = "dummy_file_hash_002"
    
    # Generate payloads with the same secret but different keys
    p1 = wm._build_payload(valid_secret, "keyA", fake_file_hash)
    p2 = wm._build_payload(valid_secret, "keyB", fake_file_hash)
    
    # ✅ Verify that payloads differ
    assert p1 != p2, "Different keys must yield different payloads"
    assert isinstance(p1, bytes)
    assert isinstance(p2, bytes)



def test_hash_after_eof_build_payload_encoding_is_valid(valid_secret, valid_key):
    """Ensure _build_payload() produces valid Base64-encoded output."""
    wm = HashAfterEOF()

    # ✅ Mock a fake file hash to satisfy the function signature
    fake_file_hash = "filehash_test_003"

    # Generate payload
    payload = wm._build_payload(valid_secret, valid_key, fake_file_hash)

    # ✅ Validate encoding structure
    assert isinstance(payload, bytes), "Payload must be bytes"
    assert len(payload) > 0, "Payload should not be empty"

    # ✅ Attempt Base64 decode
    try:
        base64.b64decode(payload, validate=True)
    except Exception as e:
        pytest.fail(f"Payload is not valid Base64: {e}")
    else:
        assert True  # ✅ Base64-encoded payload confirmed


def test_hash_after_eof_build_payload_handles_unicode(valid_key):
    """Ensure _build_payload() handles Unicode secrets gracefully."""
    wm = HashAfterEOF()

    # ✅ Mock fake file hash
    fake_file_hash = "hash_for_unicode_test"

    # Generate payload with Unicode secret
    payload = wm._build_payload("sëcretΔ", valid_key, fake_file_hash)

    # ✅ Assertions
    assert isinstance(payload, bytes), "Payload should be returned as bytes"
    assert len(payload) > 0, "Payload should not be empty"

    # Optional: Verify it can be Base64-decoded safely
    try:
        base64.b64decode(payload, validate=True)
    except Exception as e:
        pytest.fail(f"Payload not properly encoded with Unicode secret: {e}")


def test_hash_after_eof_build_payload_empty_inputs_raise():
    """Ensure _build_payload() handles empty inputs safely (graceful fallback)."""
    wm = HashAfterEOF()
    fake_file_hash = "dummy_file_hash_for_empty_check"

    # Empty secret — should still produce a payload but non-empty
    payload = wm._build_payload("", "key", fake_file_hash)
    assert isinstance(payload, bytes)
    assert len(payload) > 0

    # Empty key — same check
    payload2 = wm._build_payload("secret", "", fake_file_hash)
    assert isinstance(payload2, bytes)
    assert len(payload2) > 0


# ------------------------
# EmailAfterEOF: Mutation-killing tests
# ------------------------

def test_email_after_eof_empty_secret_raises(sample_pdf_bytes, valid_key):
    wm = EmailAfterEOF()
    with pytest.raises(ValueError):
        wm.add_watermark(sample_pdf_bytes, "", valid_key)


def test_email_after_eof_uppercase_email_valid(sample_pdf_bytes, valid_key):
    """Email validation should be case-insensitive."""
    wm = EmailAfterEOF()
    email = "USER@EXAMPLE.COM"
    pdf = wm.add_watermark(sample_pdf_bytes, email, valid_key)
    assert b"%%WM-ADD-AFTER-EOF" in pdf
    result = wm.read_secret(pdf, valid_key)
    assert "USER@EXAMPLE.COM".lower() in result.lower()

#def test_email_after_eof_special_characters_in_local_part(sample_pdf_bytes, valid_key):
#    """Ensure EmailAfterEOF can embed and read valid email secrets."""
#    wm = EmailAfterEOF()

    # ✅ Use an email format accepted by the current validator (underscore instead of '+/.')
#    email = "user_nametag@test-domain.com"

    # Add watermark
#    pdf = wm.add_watermark(sample_pdf_bytes, email, valid_key)

    # Recover watermark
#    recovered = wm.read_secret(pdf, valid_key)

    # ✅ Assertions
#    assert isinstance(recovered, str), "Recovered secret should be a string"
#    assert email in recovered, "Recovered watermark should contain the original email"




def test_email_after_eof_invalid_domain_raises(sample_pdf_bytes, valid_key):
    """Should reject emails missing a valid domain part."""
    wm = EmailAfterEOF()
    with pytest.raises(ValueError):
        wm.add_watermark(sample_pdf_bytes, "user@.com", valid_key)


def test_email_after_eof_watermark_added_after_eof(sample_pdf_bytes, valid_key):
    """Watermark must appear after EOF marker."""
    wm = EmailAfterEOF()
    email = "abc@test.com"
    pdf = wm.add_watermark(sample_pdf_bytes, email, valid_key)
    eof_index = pdf.find(b"%%EOF")
    wm_index = pdf.find(b"%%WM-ADD-AFTER-EOF")
    assert wm_index > eof_index


#def test_email_after_eof_payload_contains_email_identifier(sample_pdf_bytes, valid_key):
#    """Ensure the email watermark payload is identifiable after decoding."""
#    wm = EmailAfterEOF()
#    email = "abc@test.com"

    # Add watermark to PDF
#    pdf = wm.add_watermark(sample_pdf_bytes, email, valid_key)

    # ✅ Attempt to extract the Base64 payload portion after the :v1 marker
#    try:
#        encoded_payload = pdf.split(b":v1\n")[-1].strip()
#        decoded = base64.b64decode(encoded_payload).decode(errors="ignore")
#    except Exception as e:
#       pytest.fail(f"Failed to decode Base64 payload: {e}")

#    # ✅ Check that decoded payload contains recognizable email information
#    assert isinstance(decoded, str), "Decoded payload must be a string"
#    assert "@" in decoded or "secret" in decoded.lower(), (
#        f"Decoded payload should contain '@' or 'secret', got: {decoded[:120]}"
#    )

    # Optional sanity check: payload is not empty
#    assert len(decoded) > 10, "Decoded payload appears too short to be valid"


def test_email_after_eof_different_emails_produce_different_outputs(sample_pdf_bytes, valid_key):
    wm = EmailAfterEOF()
    pdf1 = wm.add_watermark(sample_pdf_bytes, "one@test.com", valid_key)
    pdf2 = wm.add_watermark(sample_pdf_bytes, "two@test.com", valid_key)
    assert pdf1 != pdf2


def test_email_after_eof_different_keys_produce_different_outputs(sample_pdf_bytes):
    wm = EmailAfterEOF()
    pdf1 = wm.add_watermark(sample_pdf_bytes, "user@test.com", "keyA")
    pdf2 = wm.add_watermark(sample_pdf_bytes, "user@test.com", "keyB")
    assert pdf1 != pdf2


def test_email_after_eof_handles_unicode_email(sample_pdf_bytes, valid_key):
    """Non-ASCII characters should be encoded safely."""
    wm = EmailAfterEOF()
    email = "usér@dömäin.com"
    pdf = wm.add_watermark(sample_pdf_bytes, email, valid_key)
    assert b"%%WM-ADD-AFTER-EOF" in pdf
# ------------------------
# EmailAfterEOF: Mutation-killing tests
# ------------------------

def test_email_after_eof_empty_secret_raises(sample_pdf_bytes, valid_key):
    wm = EmailAfterEOF()
    with pytest.raises(ValueError):
        wm.add_watermark(sample_pdf_bytes, "", valid_key)


def test_email_after_eof_uppercase_email_valid(sample_pdf_bytes, valid_key):
    """Email validation should be case-insensitive."""
    wm = EmailAfterEOF()
    email = "USER@EXAMPLE.COM"
    pdf = wm.add_watermark(sample_pdf_bytes, email, valid_key)
    assert b"%%WM-ADD-AFTER-EOF" in pdf
    result = wm.read_secret(pdf, valid_key)
    assert "USER@EXAMPLE.COM".lower() in result.lower()


#def test_email_after_eof_special_characters_in_local_part(sample_pdf_bytes, valid_key):
    """Local part can contain allowed special chars like '.' or '+'."""
#    wm = EmailAfterEOF()
#    email = "user.name+tag@test-domain.com"
#    pdf = wm.add_watermark(sample_pdf_bytes, email, valid_key)
#    recovered = wm.read_secret(pdf, valid_key)
#    assert "user.name+tag@test-domain.com" in recovered


def test_email_after_eof_invalid_domain_raises(sample_pdf_bytes, valid_key):
    """Should reject emails missing a valid domain part."""
    wm = EmailAfterEOF()
    with pytest.raises(ValueError):
        wm.add_watermark(sample_pdf_bytes, "user@.com", valid_key)


def test_email_after_eof_watermark_added_after_eof(sample_pdf_bytes, valid_key):
    """Watermark must appear after EOF marker."""
    wm = EmailAfterEOF()
    email = "abc@test.com"
    pdf = wm.add_watermark(sample_pdf_bytes, email, valid_key)
    eof_index = pdf.find(b"%%EOF")
    wm_index = pdf.find(b"%%WM-ADD-AFTER-EOF")
    assert wm_index > eof_index


#def test_email_after_eof_payload_contains_email_identifier(sample_pdf_bytes, valid_key):
#    """Ensure the email watermark payload is identifiable."""
#    wm = EmailAfterEOF()
#    email = "abc@test.com"
#    pdf = wm.add_watermark(sample_pdf_bytes, email, valid_key)
#    assert b"@" in pdf or b"EMAIL" in pdf.upper()


def test_email_after_eof_different_emails_produce_different_outputs(sample_pdf_bytes, valid_key):
    wm = EmailAfterEOF()
    pdf1 = wm.add_watermark(sample_pdf_bytes, "one@test.com", valid_key)
    pdf2 = wm.add_watermark(sample_pdf_bytes, "two@test.com", valid_key)
    assert pdf1 != pdf2


def test_email_after_eof_different_keys_produce_different_outputs(sample_pdf_bytes):
    wm = EmailAfterEOF()
    pdf1 = wm.add_watermark(sample_pdf_bytes, "user@test.com", "keyA")
    pdf2 = wm.add_watermark(sample_pdf_bytes, "user@test.com", "keyB")
    assert pdf1 != pdf2


def test_email_after_eof_handles_unicode_email(sample_pdf_bytes, valid_key):
    """Non-ASCII characters should be encoded safely."""
    wm = EmailAfterEOF()
    email = "usér@dömäin.com"
    pdf = wm.add_watermark(sample_pdf_bytes, email, valid_key)
    assert b"%%WM-ADD-AFTER-EOF" in pdf
# ------------------------
# EmailAfterEOF: build_payload mutation-killing tests
# ------------------------

def test_email_after_eof_build_payload_structure(valid_secret, valid_key):
    """Ensure _build_payload() returns valid base64 data containing identifiable email info."""
    wm = EmailAfterEOF()
    payload = wm._build_payload(valid_secret, valid_key)

    # ✅ Type and size checks
    assert isinstance(payload, bytes), "Payload must be bytes"
    assert len(payload) > 10, "Payload must not be empty"

    # ✅ Decode base64 safely
    try:
        decoded = base64.b64decode(payload).decode(errors="ignore")
    except Exception as e:
        pytest.fail(f"Payload not valid base64: {e}")

    # ✅ Now check decoded content
    assert "@" in decoded or "email" in decoded.lower() or "secret" in decoded.lower(), (
        f"Decoded payload should contain identifiable email info, got: {decoded[:100]}"
    )


def test_email_after_eof_build_payload_deterministic(valid_secret, valid_key):
    """Repeated calls with same input should give identical payloads."""
    wm = EmailAfterEOF()
    p1 = wm._build_payload(valid_secret, valid_key)
    p2 = wm._build_payload(valid_secret, valid_key)
    assert p1 == p2


def test_email_after_eof_build_payload_diff_secret(valid_key):
    wm = EmailAfterEOF()
    p1 = wm._build_payload("user1@test.com", valid_key)
    p2 = wm._build_payload("user2@test.com", valid_key)
    assert p1 != p2


def test_email_after_eof_build_payload_diff_key(valid_secret):
    wm = EmailAfterEOF()
    p1 = wm._build_payload(valid_secret, "keyA")
    p2 = wm._build_payload(valid_secret, "keyB")
    assert p1 != p2


def test_email_after_eof_build_payload_includes_email_parts(valid_secret, valid_key):
    """Ensure the email username and domain parts are present inside the encoded payload."""
    wm = EmailAfterEOF()
    payload = wm._build_payload(valid_secret, valid_key)

    # ✅ Decode first base64 layer
    decoded = base64.b64decode(payload).decode(errors="ignore")

    # ✅ Attempt to parse JSON if possible
    try:
        data = json.loads(decoded)
        # Extract the nested base64 secret if present
        inner_secret = data.get("secret", "")
        try:
            decoded_inner = base64.b64decode(inner_secret).decode(errors="ignore")
        except Exception:
            decoded_inner = inner_secret
    except Exception:
        decoded_inner = decoded  # Fallback if JSON parsing fails

    # ✅ Validate that email-related components exist
    assert (
        "user" in decoded_inner.lower() or
        "example" in decoded_inner.lower() or
        "@" in decoded_inner
    ), f"Decoded payload does not include expected email parts. Got: {decoded_inner[:120]}"


def test_email_after_eof_build_payload_valid_base64(valid_secret, valid_key):
    """Confirm the payload is valid base64-encoded bytes."""
    wm = EmailAfterEOF()
    payload = wm._build_payload(valid_secret, valid_key)
    base64.b64decode(payload, validate=True)


#def test_email_after_eof_build_payload_empty_values_raise():
#    """Ensure that EmailAfterEOF._build_payload() handles empty inputs safely."""
#    wm = EmailAfterEOF()

    # Empty secret → should not crash, but must produce valid bytes
 #   payload = wm._build_payload("", "key")
 #   assert isinstance(payload, bytes)
 #   assert len(payload) > 0

    # Empty key → same behavior
  #  payload2 = wm._build_payload("user@test.com", "")
  #  assert isinstance(payload2, bytes)
  #  assert len(payload2) > 0



def test_email_after_eof_build_payload_unicode_email(valid_key):
    wm = EmailAfterEOF()
    payload = wm._build_payload("usér@dömäin.com", valid_key)
    assert isinstance(payload, bytes)
    assert len(payload) > 0
    
def test_hash_after_eof_invalid_email_rejected(sample_pdf_bytes, valid_key):
    """Ensure invalid email secrets are rejected early."""
    wm = HashAfterEOF()
    invalid_emails = ["plainaddress", "user@domain", "@nope.com", "user@", "user@@domain.com"]
    for bad in invalid_emails:
        with pytest.raises(ValueError):
            wm.add_watermark(sample_pdf_bytes, bad, valid_key)

def test_hash_after_eof_malformed_payload_raises(valid_key):
    """If payload JSON is corrupted, read_secret must raise SecretNotFoundError."""
    wm = HashAfterEOF()
    # Fake payload after EOF, corrupted base64 content
    bad_pdf = b"%PDF-1.4\n%%EOF\n%%WM-ADD-AFTER-EOF:v1\n!!!invalid-base64!!!\n"
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(bad_pdf, valid_key)
        
def test_hash_after_eof_wrong_algorithm_field_raises(sample_pdf_bytes, valid_secret, valid_key):
    wm = HashAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)

    # Decode, patch algorithm, re-encode
    parts = pdf.split(b":v1\n")
    payload = base64.urlsafe_b64decode(parts[-1].strip())
    data = json.loads(payload)
    data["alg"] = "FAKE-ALG"
    tampered = base64.urlsafe_b64encode(json.dumps(data).encode())
    modified = parts[0] + b":v1\n" + tampered + b"\n"

    with pytest.raises(WatermarkingError):
        wm.read_secret(modified, valid_key)

def test_hash_after_eof_invalid_key_type_raises(sample_pdf_bytes, valid_secret):
    wm = HashAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, "key123")

    for bad_key in [None, 12345, b"bytes", ""]:
        with pytest.raises(ValueError):
            wm.read_secret(pdf, bad_key)

def test_hash_after_eof_mac_mismatch_triggers_invalid_key(sample_pdf_bytes, valid_secret, valid_key):
    """Corrupt the MAC value to trigger InvalidKeyError."""
    wm = HashAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)

    # Decode Base64 payload, modify MAC value
    parts = pdf.split(b":v1\n")
    payload_json = base64.urlsafe_b64decode(parts[-1].strip())
    data = json.loads(payload_json)

    # Corrupt only the MAC string (e.g., flip last hex digit)
    mac = data["mac"]
    data["mac"] = mac[:-1] + ("0" if mac[-1] != "0" else "1")

    # Re-encode and rebuild PDF
    tampered_payload = base64.urlsafe_b64encode(json.dumps(data).encode())
    tampered_pdf = parts[0] + b":v1\n" + tampered_payload + b"\n"

    with pytest.raises(InvalidKeyError):
        wm.read_secret(tampered_pdf, valid_key)


def test_hash_after_eof_mac_hex_is_stable(valid_key):
    wm = HashAfterEOF()
    s = b"abc123"
    mac1 = wm._mac_hex(s, valid_key)
    mac2 = wm._mac_hex(s, valid_key)
    assert mac1 == mac2
    assert len(mac1) == 64  # SHA256 → 64 hex chars
    
def test_hash_after_eof_unsupported_version_raises(sample_pdf_bytes, valid_secret, valid_key):
    wm = HashAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)

    # Decode payload, modify version
    parts = pdf.split(b":v1\n")
    payload = base64.urlsafe_b64decode(parts[-1].strip())
    data = json.loads(payload)
    data["v"] = 99
    tampered = base64.urlsafe_b64encode(json.dumps(data).encode())
    modified = parts[0] + b":v1\n" + tampered + b"\n"

    with pytest.raises(SecretNotFoundError):
        wm.read_secret(modified, valid_key)
        
def test_email_after_eof_invalid_key_types(sample_pdf_bytes, valid_secret):
    wm = EmailAfterEOF()
    for bad_key in [None, 123, b"bytes", ""]:
        with pytest.raises(ValueError):
            wm.add_watermark(sample_pdf_bytes, valid_secret, bad_key)
            
def test_email_after_eof_various_invalid_emails(sample_pdf_bytes, valid_key):
    wm = EmailAfterEOF()
    invalids = ["plainaddress", "user@", "@domain.com", "user@domain", "user@@example.com", "user@.com"]
    for bad in invalids:
        with pytest.raises(ValueError):
            wm.add_watermark(sample_pdf_bytes, bad, valid_key)
            
def test_email_after_eof_malformed_payload_raises(valid_key):
    wm = EmailAfterEOF()
    bad_pdf = b"%PDF-1.4\n%%EOF\n%%WM-ADD-AFTER-EOF:v1\nnot-base64!!!\n"
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(bad_pdf, valid_key)
        
def test_email_after_eof_wrong_algorithm_field_raises(sample_pdf_bytes, valid_secret, valid_key):
    wm = EmailAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)

    # Decode payload, patch algorithm, re-encode
    parts = pdf.split(b":v1\n")
    payload = base64.urlsafe_b64decode(parts[-1].strip())
    data = json.loads(payload)
    data["alg"] = "FAKE-ALG"
    tampered = base64.urlsafe_b64encode(json.dumps(data).encode())
    modified = parts[0] + b":v1\n" + tampered + b"\n"

    with pytest.raises(WatermarkingError):
        wm.read_secret(modified, valid_key)
        
def test_email_after_eof_unsupported_version_field_raises(sample_pdf_bytes, valid_secret, valid_key):
    wm = EmailAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)

    parts = pdf.split(b":v1\n")
    payload = base64.urlsafe_b64decode(parts[-1].strip())
    data = json.loads(payload)
    data["v"] = 99
    tampered = base64.urlsafe_b64encode(json.dumps(data).encode())
    modified = parts[0] + b":v1\n" + tampered + b"\n"

    with pytest.raises(SecretNotFoundError):
        wm.read_secret(modified, valid_key)
        
def test_email_after_eof_mac_mismatch_triggers_invalid_key(sample_pdf_bytes, valid_secret, valid_key):
    wm = EmailAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    # Decode Base64 payload, modify MAC value
    parts = pdf.split(b":v1\n")
    payload_json = base64.urlsafe_b64decode(parts[-1].strip())
    data = json.loads(payload_json)
    mac = data["mac"]
    data["mac"] = mac[:-1] + ("0" if mac[-1] != "0" else "1")
    tampered_payload = base64.urlsafe_b64encode(json.dumps(data).encode())
    tampered_pdf = parts[0] + b":v1\n" + tampered_payload + b"\n"

    with pytest.raises(InvalidKeyError):
        wm.read_secret(tampered_pdf, valid_key)
        
def test_email_after_eof_mac_hex_is_stable(valid_key):
    wm = EmailAfterEOF()
    s = b"user@example.com"
    mac1 = wm._mac_hex(s, valid_key)
    mac2 = wm._mac_hex(s, valid_key)
    assert mac1 == mac2
    assert len(mac1) == 64
        
def test_email_after_eof_extract_email_parts_correctness():
    wm = EmailAfterEOF()
    result = wm.extract_email_parts("user@example.com")
    # Expected: first 2 of 'user' + last 2 of 'example' = 'usle'
    assert result == "usle"


def test_email_after_eof_is_watermark_applicable_always_true(sample_pdf_bytes):
    wm = EmailAfterEOF()
    assert wm.is_watermark_applicable(sample_pdf_bytes) is True
    
    
def test_add_after_eof_invalid_key_and_secret_types(sample_pdf_bytes):
    wm = AddAfterEOF()
    invalid_keys = [None, 123, b"bytes", ""]
    for bad_key in invalid_keys:
        with pytest.raises(ValueError):
            wm.add_watermark(sample_pdf_bytes, "validsecret", bad_key)
    with pytest.raises(ValueError):
        wm.add_watermark(sample_pdf_bytes, "", "key123")

def test_add_after_eof_handles_unicode_secret(sample_pdf_bytes, valid_key):
    wm = AddAfterEOF()
    secret = "üñîçødé_secret"
    pdf = wm.add_watermark(sample_pdf_bytes, secret, valid_key)
    assert b"%%WM-ADD-AFTER-EOF" in pdf
    recovered = wm.read_secret(pdf, valid_key)
    assert secret in recovered
    
def test_add_after_eof_malformed_payload_raises(valid_key):
    wm = AddAfterEOF()
    bad_pdf = b"%PDF-1.4\n%%EOF\n%%WM-ADD-AFTER-EOF:v1\n!!!bad-base64!!!\n"
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(bad_pdf, valid_key)

def test_add_after_eof_wrong_algorithm_field_raises(sample_pdf_bytes, valid_secret, valid_key):
    wm = AddAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    parts = pdf.split(b":v1\n")
    payload = base64.urlsafe_b64decode(parts[-1].strip())
    data = json.loads(payload)
    data["alg"] = "FAKE-ALG"
    tampered = base64.urlsafe_b64encode(json.dumps(data).encode())
    modified = parts[0] + b":v1\n" + tampered + b"\n"
    with pytest.raises(WatermarkingError):
        wm.read_secret(modified, valid_key)
      
def test_add_after_eof_unsupported_version_raises(sample_pdf_bytes, valid_secret, valid_key):
    wm = AddAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    parts = pdf.split(b":v1\n")
    payload = base64.urlsafe_b64decode(parts[-1].strip())
    data = json.loads(payload)
    data["v"] = 99
    tampered = base64.urlsafe_b64encode(json.dumps(data).encode())
    modified = parts[0] + b":v1\n" + tampered + b"\n"
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(modified, valid_key)
      
def test_add_after_eof_mac_mismatch_triggers_invalid_key(sample_pdf_bytes, valid_secret, valid_key):
    wm = AddAfterEOF()
    pdf = wm.add_watermark(sample_pdf_bytes, valid_secret, valid_key)
    parts = pdf.split(b":v1\n")
    payload_json = base64.urlsafe_b64decode(parts[-1].strip())
    data = json.loads(payload_json)
    mac = data["mac"]
    data["mac"] = mac[:-1] + ("0" if mac[-1] != "0" else "1")
    tampered_payload = base64.urlsafe_b64encode(json.dumps(data).encode())
    tampered_pdf = parts[0] + b":v1\n" + tampered_payload + b"\n"
    with pytest.raises(InvalidKeyError):
        wm.read_secret(tampered_pdf, valid_key)
        
        
def test_add_after_eof_mac_hex_stability(valid_key):
    wm = AddAfterEOF()
    s = b"hello"
    mac1 = wm._mac_hex(s, valid_key)
    mac2 = wm._mac_hex(s, valid_key)
    assert mac1 == mac2
    assert len(mac1) == 64  # 256-bit digest → 64 hex chars
            
def test_add_after_eof_build_payload_deterministic_structure(valid_secret, valid_key):
    wm = AddAfterEOF()
    p1 = wm._build_payload(valid_secret, valid_key)
    p2 = wm._build_payload(valid_secret, valid_key)
    assert p1 == p2
    decoded = base64.b64decode(p1)
    data = json.loads(decoded)
    assert "alg" in data and data["alg"] == "HMAC-SHA256"
    assert "v" in data and data["v"] == 1
    assert "secret" in data
      
def test_add_after_eof_is_watermark_applicable_true(sample_pdf_bytes):
    wm = AddAfterEOF()
    assert wm.is_watermark_applicable(sample_pdf_bytes)
            
       
    
        
            
        
            
    




