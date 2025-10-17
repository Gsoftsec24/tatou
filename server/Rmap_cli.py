#!/usr/bin/env python3
"""
rmap_cli.py — run the two-step RMAP flow against a running server.

Usage:
    python rmap_cli.py \
      --server http://localhost:5000 \
      --identity Group_24 \
      --client-priv keys/clients/Group_24_priv.asc \
      --server-pub keys/server_pub.asc \
      [--nonce 123456789] \
      [--out /tmp/session.pdf]

Environment:
    If your client private key is passphrase-protected, set:
      export CLIENT_KEY_PASSPHRASE='your-pass'

Notes:
  - Requires python packages: requests, pgpy
  - Run inside your project's virtualenv: source .venv/bin/activate
"""

import argparse
import json
import base64
import os
import sys
import logging
from pathlib import Path

import requests
from pgpy import PGPKey, PGPMessage

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("rmap_cli")


def load_key(path: Path, key_type: str):
    if not path.exists():
        log.error("%s key file not found: %s", key_type, path)
        sys.exit(2)
    try:
        key, _ = PGPKey.from_file(str(path))
        return key
    except Exception as e:
        log.error("Failed to load %s key %s: %s", key_type, path, e)
        raise


def create_b64_payload(server_pub: PGPKey, obj: dict) -> str:
    """Encrypt JSON obj to server_pub and return base64(ascii-armored-pgp)."""
    txt = json.dumps(obj, separators=(",", ":"))
    msg = PGPMessage.new(txt)
    enc = server_pub.encrypt(msg)
    armored = str(enc)
    b64 = base64.b64encode(armored.encode("utf-8")).decode("utf-8")
    return b64


def decrypt_payload_with_client(priv_key: PGPKey, payload_b64: str, passphrase: str | None):
    """Decode base64->armored PGP and decrypt with priv_key. Returns Python object (parsed JSON) or raw text."""
    try:
        armored = base64.b64decode(payload_b64).decode("utf-8")
    except Exception as e:
        log.error("Failed to base64-decode payload: %s", e)
        raise

    try:
        pgp_msg = PGPMessage.from_blob(armored)
    except Exception as e:
        log.error("Failed to parse armored PGP message: %s", e)
        raise

    # Decrypt with passphrase handling (support both 'with priv.unlock(pw)' and legacy unlock())
    try:
        if getattr(priv_key, "is_protected", False):
            if not passphrase:
                raise RuntimeError("Client private key is protected; CLIENT_KEY_PASSPHRASE required")
            # attempt context manager style
            try:
                with priv_key.unlock(passphrase):
                    decrypted = priv_key.decrypt(pgp_msg)
            except TypeError:
                # some versions may return a non-context-manager; call unlock then decrypt
                priv_key.unlock(passphrase)
                decrypted = priv_key.decrypt(pgp_msg)
        else:
            decrypted = priv_key.decrypt(pgp_msg)
    except Exception as e:
        log.error("Failed to decrypt payload with client private key: %s", e)
        raise

    txt = str(decrypted.message)
    # If JSON, parse it; otherwise return raw text
    try:
        return json.loads(txt)
    except Exception:
        return txt


def post_json(url: str, data: dict, timeout: int = 10):
    headers = {"Content-Type": "application/json"}
    try:
        r = requests.post(url, json=data, headers=headers, timeout=timeout)
    except Exception as e:
        log.error("HTTP request failed: %s", e)
        raise
    return r


def main():
    p = argparse.ArgumentParser(description="RMAP two-step client helper")
    p.add_argument("--server", required=True, help="Server base URL, e.g. http://localhost:5000")
    p.add_argument("--identity", required=True, help="Client identity (public key file name without .asc)")
    p.add_argument("--client-priv", required=True, help="Path to client private key (ASCII-armored .asc)")
    p.add_argument("--server-pub", required=True, help="Path to server public key (ASCII-armored .asc)")
    p.add_argument("--nonce", type=int, default=123456789, help="nonceClient (u64) to send")
    p.add_argument("--out", help="optional path to save returned PDF (if link provided)")
    args = p.parse_args()

    server_url = args.server.rstrip("/")
    identity_name = args.identity
    client_priv_path = Path(args.client_priv)
    server_pub_path = Path(args.server_pub)
    nonce_client = args.nonce
    out_path = Path(args.out) if args.out else None

    log.info("Loading server public key from %s", server_pub_path)
    server_pub = load_key(server_pub_path, "server public")

    log.info("Loading client private key from %s", client_priv_path)
    client_priv = load_key(client_priv_path, "client private")

    client_pw = os.environ.get("CLIENT_KEY_PASSPHRASE")

    # --- Message 1 ---
    msg1_plain = {"nonceClient": nonce_client, "identity": identity_name}
    log.info("Creating payload1 (nonceClient=%s identity=%s)", nonce_client, identity_name)
    payload1 = create_b64_payload(server_pub, msg1_plain)

    url1 = f"{server_url}/rmap-initiate"
    log.info("POST %s", url1)
    resp1 = post_json(url1, {"payload": payload1})
    log.info("HTTP %s", resp1.status_code)
    try:
        j1 = resp1.json()
    except Exception:
        log.error("Server did not return JSON for message1, raw:\n%s", resp1.text)
        sys.exit(3)

    if "error" in j1:
        log.error("Server returned error for message1: %s", j1.get("error"))
        sys.exit(4)

    payload1_resp = j1.get("payload")
    if not payload1_resp:
        log.error("No 'payload' present in server response to message1: %s", j1)
        sys.exit(5)

    # Decrypt server reply to extract nonceServer
    log.info("Decrypting server response to extract nonceServer")
    try:
        decrypted1 = decrypt_payload_with_client(client_priv, payload1_resp, client_pw)
    except Exception:
        log.exception("Failed to decrypt server response")
        sys.exit(6)

    if isinstance(decrypted1, dict):
        nonce_server = decrypted1.get("nonceServer")
        log.info("Decrypted JSON: %s", json.dumps(decrypted1))
    else:
        log.info("Decrypted text (non-JSON): %s", str(decrypted1))
        # try to parse if possible
        try:
            parsed = json.loads(str(decrypted1))
            nonce_server = parsed.get("nonceServer")
        except Exception:
            log.error("Cannot extract nonceServer from decrypted response")
            sys.exit(7)

    if not nonce_server:
        log.error("nonceServer not found in decrypted response")
        sys.exit(8)

    # --- Message 2 ---
    msg2_plain = {"nonceServer": int(nonce_server)}
    log.info("Creating payload2 with nonceServer=%s", nonce_server)
    payload2 = create_b64_payload(server_pub, msg2_plain)

    url2 = f"{server_url}/rmap-get-link"
    log.info("POST %s", url2)
    resp2 = post_json(url2, {"payload": payload2})
    log.info("HTTP %s", resp2.status_code)
    try:
        j2 = resp2.json()
    except Exception:
        log.error("Server did not return JSON for message2, raw:\n%s", resp2.text)
        sys.exit(9)

    if "error" in j2:
        log.error("Server returned error for message2: %s", j2.get("error"))
        sys.exit(10)

    log.info("Final response: %s", json.dumps(j2))
    # If a link was returned, optionally download the PDF
    link = j2.get("link")
    if link and out_path:
        # ensure link starts with '/'
        if not link.startswith("/"):
            link = "/" + link
        download_url = server_url + link
        log.info("Downloading PDF from %s to %s", download_url, out_path)
        try:
            r = requests.get(download_url, timeout=20)
            r.raise_for_status()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "wb") as fh:
                fh.write(r.content)
            log.info("Saved to %s (size=%d bytes)", out_path, len(r.content))
        except Exception as e:
            log.error("Failed to download PDF: %s", e)

    # print result to stdout for convenience
    print(json.dumps(j2, indent=2))


if __name__ == "__main__":
    main()
