import hashlib
import json
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa # For type hinting if needed
from cryptography.hazmat.primitives import serialization # For type hinting if needed
from cryptography.exceptions import InvalidSignature # For verifier later

# Import functions from our identity_manager
# We need to handle Python's import system. If running stamper.py directly for tests,
# this might need adjustment or we ensure tests are run from the root of the project.
# For now, let's assume it can be imported if the execution context is the project root.
try:
    from .identity_manager import load_private_key, get_tsnue_id
except ImportError:
    # Fallback for direct execution (e.g. python stamper.py)
    from identity_manager import load_private_key, get_tsnue_id


# Define the structure of a Tsnu'e Stamp
# This is a Python dictionary that will be serialized to JSON for storage/transfer
# {
#   "protocol_version": "1.0",
#   "tsnue_id": "string (hash of public key)",
#   "timestamp_utc": float (Unix timestamp),
#   "original_filename": "string",
#   "file_hash_algorithm": "string (e.g., 'sha256')",
#   "file_hash": "string (hex digest of the file content)",
#   "signature_algorithm": "string (e.g., 'RSASSA-PKCS1-v1_5-SHA256')",
#   "signature": "string (base64 encoded signature of 'file_hash' + other metadata)"
#   "public_key_pem": "string (PEM format of public key, for easier verification)"
# }

PROTOCOL_VERSION = "Tsnu'eMahtem-1.0"

def calculate_file_hash(filepath, hash_algorithm='sha256'):
    """
    Calculates the hash of a file's content.
    Supports 'sha256', 'sha512'.
    Returns the hex digest of the hash.
    """
    BUF_SIZE = 65536  # Read in 64kb chunks

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
    """
    Creates a canonical representation of the stamp data that will be signed.
    This ensures that the verifier signs the exact same structured data.
    For simplicity, we'll make it a concatenated string of key fields.
    A more robust method would be a canonical JSON or XML representation.
    """
    # Order is important here for consistent signature generation
    payload = f"{PROTOCOL_VERSION}|{tsnue_id}|{timestamp_utc}|{original_filename}|{file_hash_algorithm}|{file_hash}"
    return payload.encode('utf-8') # Sign bytes, not strings

def sign_data(private_key: rsa.RSAPrivateKey, data_to_sign: bytes):
    """
    Signs the given data using the private key with RSASSA-PKCS1-v1_5 padding and SHA256.
    Returns the signature as base64 encoded string.
    """
    import base64
    signature = private_key.sign(
        data_to_sign,
        padding.PKCS1v15(),
        hashes.SHA256() # The hash algorithm used for the signature itself
    )
    return base64.b64encode(signature).decode('utf-8')

def create_tsnue_stamp(filepath, private_key_path="tsnue_private_key.pem", private_key_password=None):
    """
    Creates a Tsnu'e Stamp for the given file.
    """
    import os

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    # 1. Load the private key
    private_key = load_private_key(private_key_path, private_key_password)
    public_key = private_key.public_key() # Get public key for ID and embedding

    # 2. Get Tsnu'e ID
    tsnue_id = get_tsnue_id(public_key)

    # 3. Get current timestamp
    timestamp_utc = time.time() # Unix timestamp (seconds since epoch)

    # 4. Get original filename
    original_filename = os.path.basename(filepath)

    # 5. Calculate file hash
    file_hash_algorithm = 'sha256' # Default algorithm
    file_hash_hex = calculate_file_hash(filepath, file_hash_algorithm)

    # 6. Create the payload to be signed
    payload_to_sign = create_stamp_payload_to_sign(
        tsnue_id, timestamp_utc, original_filename, file_hash_algorithm, file_hash_hex
    )

    # 7. Sign the payload
    signature_b64 = sign_data(private_key, payload_to_sign)

    # 8. Get public key PEM for embedding in stamp (useful for verifiers)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # 9. Construct the Tsnu'e Stamp dictionary
    stamp = {
        "protocol_version": PROTOCOL_VERSION,
        "tsnue_id": tsnue_id,
        "timestamp_utc": timestamp_utc,
        "original_filename": original_filename,
        "file_hash_algorithm": file_hash_algorithm,
        "file_hash": file_hash_hex,
        "signature_algorithm": "RSASSA-PKCS1-v1_5-SHA256", # Algorithm used for signing
        "signature": signature_b64,
        "public_key_pem": public_key_pem
    }

    return stamp

# --- Main execution for testing ---
if __name__ == "__main__":
    print("Tsnu'e-Mahtem Stamper")
    print("---------------------")

    # Create a dummy file to stamp for testing
    TEST_FILE = "sample_document.txt"
    with open(TEST_FILE, "w") as f:
        f.write("This is a test document for Tsnu'e-Mahtem.\n")
        f.write(f"It was created at {time.ctime()}.\n")

    print(f"Attempting to stamp file: {TEST_FILE}")

    try:
        # Ensure keys exist from identity_manager.py first run
        import os
        if not os.path.exists("tsnue_private_key.pem"):
            print("Error: Private key 'tsnue_private_key.pem' not found.")
            print("Please run identity_manager.py first to generate keys.")
            exit()

        tsnue_stamp = create_tsnue_stamp(TEST_FILE)
        print("\nSuccessfully created Tsnu'e Stamp:")
        # Pretty print the JSON
        print(json.dumps(tsnue_stamp, indent=2))

        # For now, let's save the stamp to a file for easy inspection
        # We'll build a proper stamp_store.py later
        stamp_filename = f"{TEST_FILE}.tsnue-stamp.json"
        with open(stamp_filename, "w") as sf:
            json.dump(tsnue_stamp, sf, indent=2)
        print(f"\nStamp saved to: {stamp_filename}")

    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc() # Print full traceback for debugging

    finally:
        # Clean up the dummy file
        if os.path.exists(TEST_FILE):
            # os.remove(TEST_FILE) # Comment out if you want to keep the file for verifier testing
            pass