import os
import sys
import requests
import json
import base64
from pathlib import Path
from pgpy import PGPKey, PGPMessage
from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP

# ---- CONFIG ----
HARDCODED_CLIENT_PASSPHRASE = "Group@24rkj"
SERVER_URL = "http://localhost:5000"   # adjust if needed
# ----------------

def print_key_fingerprints(pub_path: Path, priv_path: Path):
    print("\n--- Fingerprint Verification ---")
    # Load public key
    try:
        client_pub, _ = PGPKey.from_file(str(pub_path))
        print(f"Public key ({pub_path.name}): {client_pub.fingerprint}")
    except Exception as e:
        print(f"ERROR: Failed to load public key {pub_path}: {e}", file=sys.stderr)

    # Load private key
    try:
        client_priv, _ = PGPKey.from_file(str(priv_path))
        print(f"Private key ({priv_path.name}): {client_priv.fingerprint}")
    except Exception as e:
        print(f"ERROR: Failed to load private key {priv_path}: {e}", file=sys.stderr)
    print("--- End Fingerprints ---\n")


def main():
    # Adjust these paths to match your setup
    assets = Path("keys")
    clients_dir = assets / "clients"
    server_pub = str(assets / "server_pub.asc")
    server_priv = str(assets / "server_priv.asc")
    client_pub_path = clients_dir / "Group_24.asc"
    client_priv_path = clients_dir / "Group_24_priv.asc"   # 🔑 must match public key

    # quick existence checks
    for p in [clients_dir, server_pub, server_priv, client_pub_path, client_priv_path]:
        if not Path(p).exists():
            print(f"ERROR: missing file {p}", file=sys.stderr)
            sys.exit(1)

    # Print fingerprints for sanity check
   # print_key_fingerprints(client_pub_path, client_priv_path)

    im = IdentityManager(
        client_keys_dir=str(clients_dir),
        server_public_key_path=server_pub,
        server_private_key_path=server_priv,
    )
    rmap = RMAP(im)

    # Load your group's private key
    client_priv, _ = PGPKey.from_file(str(client_priv_path))

    # Unlock if needed
    if client_priv.is_protected:
        passphrase = os.environ.get("CLIENT_KEY_PASSPHRASE") or HARDCODED_CLIENT_PASSPHRASE
        try:
            client_priv.unlock(passphrase)
        except Exception as e:
            print("Failed to unlock client private key:", e, file=sys.stderr)

   # print("Client private key is_protected:", client_priv.is_protected)
    #print("Client private key is_unlocked:", getattr(client_priv, "is_unlocked", False))
    if not getattr(client_priv, "is_unlocked", False) and client_priv.is_protected:
        print("ERROR: client private key is not unlocked. Aborting.", file=sys.stderr)
        sys.exit(1)

    # --- Message 1 ---
    nonce_client = 123456789
    msg1_plain = {"nonceClient": nonce_client, "identity": "Group_24"}  # identity = public key filename (no .asc)
    msg1 = {"payload": im.encrypt_for_server(msg1_plain)}

    resp1 = requests.post(f"{SERVER_URL}/rmap-initiate", json=msg1)
    print("Raw Response status:", resp1.status_code)
    print("Raw Response text:", resp1.text)

    try:
        resp1_json = resp1.json()
    except Exception as e:
        print("Could not parse JSON:", e, file=sys.stderr)
        return

    print("Response 1 (JSON):", resp1_json)

    armored = base64.b64decode(resp1_json["payload"]).decode("utf-8")
    pgp_msg = PGPMessage.from_blob(armored)
    resp1_plain = json.loads(client_priv.decrypt(pgp_msg).message)
    print("Decrypted Response 1:", resp1_plain)

    # --- Message 2 ---
    nonce_server = int(resp1_plain["nonceServer"])
    msg2_plain = {"nonceServer": nonce_server}
    msg2 = {"payload": im.encrypt_for_server(msg2_plain)}

    resp2 = requests.post(f"{SERVER_URL}/rmap-get-link", json=msg2)
    print("Raw Response 2 status:", resp2.status_code)
    print("Raw Response 2 text:", resp2.text)

    try:
        resp2_json = resp2.json()
    except Exception as e:
        print("Could not parse JSON for Response 2:", e, file=sys.stderr)
        return

    print("Response 2 (JSON):", resp2_json)


if __name__ == "__main__":
    main()
