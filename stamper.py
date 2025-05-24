import hashlib
import json
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import os
import tempfile # For temporary file when adding to IPFS
import ipfshttpclient # For IPFS interaction

# Import functions from our identity_manager
try:
    from .identity_manager import load_private_key, get_tsnue_id, PRIVATE_KEY_FILE as DEFAULT_PRIV_KEY_PATH
except ImportError:
    from identity_manager import load_private_key, get_tsnue_id, PRIVATE_KEY_FILE as DEFAULT_PRIV_KEY_PATH

PROTOCOL_VERSION = "Tsnu'eMahtem-1.0"
IPFS_API_ADDR = '/ip4/127.0.0.1/tcp/5001' # Default local IPFS API

def calculate_file_hash(filepath, hash_algorithm='sha256'):
    BUF_SIZE = 65536
    if hash_algorithm == 'sha256':
        hasher = hashlib.sha256()
    elif hash_algorithm == 'sha512':
        hasher = hashlib.sha512()
    else:
        raise ValueError("Unsupported hash algorithm. Choose 'sha256' or 'sha512'.")
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            hasher.update(data)
    return hasher.hexdigest()

def create_stamp_payload_to_sign(tsnue_id, timestamp_utc, original_filename, file_hash_algorithm, file_hash):
    payload = f"{PROTOCOL_VERSION}|{tsnue_id}|{timestamp_utc}|{original_filename}|{file_hash_algorithm}|{file_hash}"
    return payload.encode('utf-8')

def sign_data(private_key: rsa.RSAPrivateKey, data_to_sign: bytes):
    import base64
    signature = private_key.sign(
        data_to_sign,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def create_tsnue_stamp(filepath, private_key_path=DEFAULT_PRIV_KEY_PATH, private_key_password=None):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File to stamp not found: {filepath}")
    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"Private key file not found: {private_key_path}. Please generate ID first.")

    private_key = load_private_key(private_key_path, password=private_key_password)
    public_key = private_key.public_key()
    tsnue_id = get_tsnue_id(public_key)
    timestamp_utc = time.time()
    original_filename = os.path.basename(filepath)
    file_hash_algorithm = 'sha256'
    file_hash_hex = calculate_file_hash(filepath, file_hash_algorithm)
    payload_to_sign = create_stamp_payload_to_sign(
        tsnue_id, timestamp_utc, original_filename, file_hash_algorithm, file_hash_hex
    )
    signature_b64 = sign_data(private_key, payload_to_sign)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    stamp = {
        "protocol_version": PROTOCOL_VERSION,
        "tsnue_id": tsnue_id,
        "timestamp_utc": timestamp_utc,
        "original_filename": original_filename,
        "file_hash_algorithm": file_hash_algorithm,
        "file_hash": file_hash_hex,
        "signature_algorithm": "RSASSA-PKCS1-v1_5-SHA256",
        "signature": signature_b64,
        "public_key_pem": public_key_pem
    }
    return stamp

def publish_stamp_to_ipfs(stamp_data_dict):
    """
    Publishes the given Tsnu'e Stamp data (dictionary) to IPFS.
    Returns the IPFS CID if successful, None otherwise.
    """
    ipfs_client = None
    temp_file_path = None
    try:
        # Connect to IPFS daemon
        try:
            ipfs_client = ipfshttpclient.connect(IPFS_API_ADDR, session=True)
        except ipfshttpclient.exceptions.ConnectionError:
            print(f"[ERROR] IPFS: Could not connect to daemon at {IPFS_API_ADDR}. Is 'ipfs daemon' running?")
            return None
        
        # Create a temporary file to hold the JSON stamp data
        # Suffix is important for IPFS to potentially infer mime type, though not critical for `ipfs add`
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".tsnue-stamp.json", encoding='utf-8') as tmp_file:
            json.dump(stamp_data_dict, tmp_file, indent=2)
            temp_file_path = tmp_file.name
        
        # Add the temporary file to IPFS
        # The add method returns a dictionary (or list of dicts if multiple files)
        # For a single file, it's like: {'Name': 'filename.json', 'Hash': 'CID_Qm...', 'Size': '123'}
        print(f"[INFO] IPFS: Adding stamp data to IPFS from temporary file: {temp_file_path}")
        result = ipfs_client.add(temp_file_path, pin=True) # Pin by default to keep it locally
        
        cid = result['Hash']
        print(f"[SUCCESS] IPFS: Stamp published with CID: {cid}")
        return cid

    except ipfshttpclient.exceptions.VersionMismatch as e_version:
        # This is now a warning in 0.8.0a2 for our daemon version, but good to catch if it becomes an error again
        print(f"[WARNING] IPFS: Version mismatch with daemon, but attempting to proceed. Details: {e_version}")
        # If it was a warning, the code above might have still worked.
        # This specific catch might not be hit if it's only a warning and not an exception.
        # The CID might have been returned correctly if the 'add' operation still succeeded.
        # Re-evaluating how to handle this if it's just a warning and 'add' succeeds.
        # For now, if 'add' failed due to this (if it becomes a hard error), this is the path.
        # If it's just a warning, `cid` would be set.
        if 'cid' in locals() and cid:
             return cid # It worked despite the warning
        print(f"[ERROR] IPFS: Could not publish due to version issue that became an error. Details: {e_version}")
        return None # Explicitly return None if we can't get a CID.
    except ipfshttpclient.exceptions.ipfshttpclient.exceptions.ErrorResponse as e_api:
        print(f"[ERROR] IPFS: API ErrorResponse while publishing: {e_api}")
        return None
    except Exception as e:
        print(f"[ERROR] IPFS: An unexpected error occurred during publishing: {e}")
        return None
    finally:
        if ipfs_client:
            ipfs_client.close()
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path) # Clean up temporary file
                # print(f"[DEBUG] IPFS: Removed temporary file {temp_file_path}")
            except OSError as e_del:
                 print(f"[WARNING] IPFS: Could not remove temporary file {temp_file_path}: {e_del}")


if __name__ == "__main__":
    print("Tsnu'e-Mahtem Stamper (Test Block with IPFS publishing awareness)")
    print("----------------------------------------------------------------")
    print("NOTE: Direct execution of stamper.py's test block may FAIL if 'tsnue_private_key.pem' is password-protected,")
    print("as it does not currently prompt for a password. Test password functionality via main_cli.py.")
    print("This test block also does NOT attempt to publish to IPFS directly.")

    TEST_FILE = "sample_document_stamper_direct.txt"
    if not os.path.exists(DEFAULT_PRIV_KEY_PATH):
        print(f"[ERROR] Private key '{DEFAULT_PRIV_KEY_PATH}' not found. Cannot run direct stamper test.")
    else:
        with open(TEST_FILE, "w") as f:
            f.write(f"Direct stamper test file content. {time.ctime()}")
        print(f"Created {TEST_FILE} for direct stamping test.")
        try:
            # Attempting to create stamp without password. Will fail if key is encrypted.
            stamp = create_tsnue_stamp(TEST_FILE, private_key_password=None) 
            print("[SUCCESS] Stamp created by direct stamper test (assuming key was not password protected):")
            print(json.dumps(stamp, indent=2))

            # Example of how publishing MIGHT be tested here (but requires daemon & assumes unencrypted key)
            # print("\nAttempting to publish the above stamp to IPFS (requires daemon)...")
            # cid = publish_stamp_to_ipfs(stamp)
            # if cid:
            #     print(f"Successfully published to IPFS with CID: {cid}")
            # else:
            #     print("Failed to publish to IPFS.")

        except (ValueError, TypeError) as e:
            if "decryption failed" in str(e).lower() or "password" in str(e).lower():
                print(f"[ERROR] Failed to create stamp directly: Private key likely password-protected. {e}")
            else:
                print(f"[ERROR] Failed to create stamp directly (ValueError/TypeError): {e}")
        except Exception as e:
            print(f"[ERROR] Failed to create stamp directly: {e}")
        finally:
            if os.path.exists(TEST_FILE):
                os.remove(TEST_FILE)