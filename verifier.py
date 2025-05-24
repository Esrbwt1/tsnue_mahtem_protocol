import json
import os # Added for os.path.exists in main block
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import ipfshttpclient # For IPFS interaction

# Import functions/constants from our other modules
try:
    from .stamper import calculate_file_hash, create_stamp_payload_to_sign, PROTOCOL_VERSION, IPFS_API_ADDR
    # identity_manager.load_public_key is not directly used here anymore as pubkey comes from stamp
except ImportError:
    from stamper import calculate_file_hash, create_stamp_payload_to_sign, PROTOCOL_VERSION, IPFS_API_ADDR

def fetch_stamp_from_ipfs(cid_string):
    """
    Fetches Tsnu'e Stamp data (JSON) from IPFS using its CID.
    Returns the stamp data as a dictionary if successful, None otherwise.
    """
    ipfs_client = None
    print(f"[INFO] IPFS: Attempting to fetch stamp data for CID: {cid_string}")
    try:
        # Connect to IPFS daemon
        try:
            ipfs_client = ipfshttpclient.connect(IPFS_API_ADDR, session=True)
        except ipfshttpclient.exceptions.ConnectionError:
            print(f"[ERROR] IPFS: Could not connect to daemon at {IPFS_API_ADDR}. Is 'ipfs daemon' running?")
            return None

        # Get the content of the file by its CID (should be JSON bytes)
        # Add a timeout to prevent indefinite hanging
        timeout_seconds = 20 # Increased timeout for potentially slow IPFS fetches
        print(f"[INFO] IPFS: Fetching content for CID {cid_string} (timeout: {timeout_seconds}s)...")
        content_bytes = ipfs_client.cat(cid_string, timeout=timeout_seconds)
        content_str = content_bytes.decode('utf-8')
        
        # Parse the JSON string into a dictionary
        stamp_data_dict = json.loads(content_str)
        print(f"[SUCCESS] IPFS: Successfully fetched and parsed stamp data for CID: {cid_string}")
        return stamp_data_dict

    except ipfshttpclient.exceptions.VersionMismatch as e_version:
        # This is a warning in 0.8.0a2 for our daemon, but good to note.
        # If it were a hard error, the ipfshttpclient.connect would have failed.
        # If cat() fails due to this (unlikely if connect succeeded), it would be an ErrorResponse.
        print(f"[WARNING] IPFS: Version mismatch with daemon. Details: {e_version}")
        # Attempt to proceed if it was just a warning (which it is for Kubo 0.35.0 + client 0.8.0a2)
        # If the above cat/json.loads failed, the more specific exceptions below would catch it.
        # This specific catch path for VersionMismatch might not be strictly necessary here if connect works.
        return None # Assuming if it's a problem, cat would fail.
    except ipfshttpclient.exceptions.Timeout:
        print(f"[ERROR] IPFS: Timeout while fetching CID {cid_string}. Content may not be available or network is slow.")
        return None
    except ipfshttpclient.exceptions.ErrorResponse as e_api:
        if "not found" in str(e_api).lower() or "no link named" in str(e_api).lower(): # Improve error detection
             print(f"[ERROR] IPFS: Content for CID {cid_string} not found on the network or via your node.")
        else:
            print(f"[ERROR] IPFS: API ErrorResponse while fetching CID {cid_string}: {e_api}")
        return None
    except json.JSONDecodeError:
        print(f"[ERROR] IPFS: Fetched content for CID {cid_string}, but it was not valid JSON.")
        return None
    except Exception as e:
        print(f"[ERROR] IPFS: An unexpected error occurred while fetching CID {cid_string}: {e}")
        return None
    finally:
        if ipfs_client:
            ipfs_client.close()


def verify_signature(public_key_pem_str: str, signature_b64: str, data_that_was_signed: bytes):
    import base64
    public_key = serialization.load_pem_public_key(
        public_key_pem_str.encode('utf-8')
    )
    signature_bytes = base64.b64decode(signature_b64)
    try:
        public_key.verify(
            signature_bytes,
            data_that_was_signed,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        raise

def verify_tsnue_stamp(filepath_to_verify, stamp_filepath):
    results = {
        "verified": False,
        "checks": {
            "protocol_version_match": False,
            "file_integrity_match": False,
            "signature_valid": False
        },
        "message": "",
        "stamp_content": None # Will hold the content of the stamp_filepath
    }

    if not os.path.exists(filepath_to_verify):
        results["message"] = f"File to verify not found: {filepath_to_verify}"
        return results
    if not os.path.exists(stamp_filepath): # stamp_filepath is a path to a local JSON file
        results["message"] = f"Stamp file (local path) not found: {stamp_filepath}"
        return results

    try:
        with open(stamp_filepath, 'r') as sf:
            stamp_data = json.load(sf)
        results["stamp_content"] = stamp_data
    except json.JSONDecodeError:
        results["message"] = f"Error: Could not decode JSON from stamp file: {stamp_filepath}"
        return results
    except Exception as e:
        results["message"] = f"Error reading stamp file '{stamp_filepath}': {e}"
        return results

    # Proceed with verification using stamp_data
    if stamp_data.get("protocol_version") == PROTOCOL_VERSION:
        results["checks"]["protocol_version_match"] = True
    else:
        results["message"] = f"Protocol version mismatch. Expected '{PROTOCOL_VERSION}', got '{stamp_data.get('protocol_version')}'."
    
    current_file_hash_algorithm = stamp_data.get("file_hash_algorithm", 'sha256')
    try:
        current_file_hash_hex = calculate_file_hash(filepath_to_verify, current_file_hash_algorithm)
    except Exception as e:
        results["message"] = (results["message"] + " " if results["message"] else "") + f"Error calculating hash for '{filepath_to_verify}': {e}"
        return results # Cannot proceed without current file hash

    stored_file_hash = stamp_data.get("file_hash")
    if current_file_hash_hex == stored_file_hash:
        results["checks"]["file_integrity_match"] = True
    else:
        results["message"] = (results["message"] + " " if results["message"] else "") + "File integrity check FAILED: File content has changed since stamping."

    try:
        payload_to_verify = create_stamp_payload_to_sign(
            stamp_data.get("tsnue_id"),
            stamp_data.get("timestamp_utc"),
            stamp_data.get("original_filename"),
            stamp_data.get("file_hash_algorithm"),
            stamp_data.get("file_hash") 
        )
    except Exception as e_payload:
        results["message"] = (results["message"] + " " if results["message"] else "") + f"Could not reconstruct stamp payload for signature: {e_payload}"
        # Signature check cannot proceed if payload can't be made
        results["checks"]["signature_valid"] = False # Mark as explicitly failed
        # Update overall status if not already failed
        if results["checks"]["protocol_version_match"] and results["checks"]["file_integrity_match"]:
            results["verified"] = False # It would have been true, now it's false
        return results


    public_key_pem_str = stamp_data.get("public_key_pem")
    signature_b64 = stamp_data.get("signature")

    if not public_key_pem_str or not signature_b64:
        results["message"] = (results["message"] + " " if results["message"] else "") + "Missing public key or signature in stamp data. Cannot verify signature."
    else:
        try:
            verify_signature(public_key_pem_str, signature_b64, payload_to_verify)
            results["checks"]["signature_valid"] = True
        except InvalidSignature:
            results["message"] = (results["message"] + " " if results["message"] else "") + "Signature verification FAILED: Signature is not valid for the data in the stamp."
        except Exception as e_sig:
            results["message"] = (results["message"] + " " if results["message"] else "") + f"Error during signature verification: {e_sig}."

    if results["checks"]["protocol_version_match"] and \
       results["checks"]["file_integrity_match"] and \
       results["checks"]["signature_valid"]:
        results["verified"] = True
        results["message"] = "File successfully verified: Authentic and integrity intact."
    elif not results["message"]:
         results["message"] = "Verification failed. Check individual checks."
    
    return results

if __name__ == "__main__":
    print("Tsnu'e-Mahtem Verifier (Test Block with IPFS fetching awareness)")
    print("-------------------------------------------------------------")
    print("This test block can try to fetch a stamp from IPFS if a CID is provided.")
    print("Ensure IPFS daemon is running for IPFS tests.")

    # Example: To test IPFS fetching directly (replace with a real CID of a stamp you published)
    # TEST_CID = "QmXnQztaZbBQS8yVSSvELYVRnZwVqAJPWKvP12qHVPscv2" # Example from previous step
    TEST_CID = None # Set this to a real CID to test fetching

    if TEST_CID:
        print(f"\n--- Test Case: Fetching stamp from IPFS with CID: {TEST_CID} ---")
        fetched_stamp_data = fetch_stamp_from_ipfs(TEST_CID)
        if fetched_stamp_data:
            print("[SUCCESS] Fetched stamp data from IPFS:")
            print(json.dumps(fetched_stamp_data, indent=2))
            
            # To fully test verification with this fetched stamp, you'd need:
            # 1. The original file that this stamp corresponds to.
            # 2. Save fetched_stamp_data to a temporary local .json file.
            # 3. Call verify_tsnue_stamp(original_file_path, temp_stamp_json_path)
            # Example (conceptual):
            # if os.path.exists("ipfs_publish_test.txt"): # Assuming this was the file for TEST_CID
            #     with open("_temp_ipfs_stamp.json", "w") as tmp_f:
            #         json.dump(fetched_stamp_data, tmp_f)
            #     result = verify_tsnue_stamp("ipfs_publish_test.txt", "_temp_ipfs_stamp.json")
            #     print("\nVerification result using fetched IPFS stamp:")
            #     print(json.dumps(result, indent=2))
            #     if os.path.exists("_temp_ipfs_stamp.json"): os.remove("_temp_ipfs_stamp.json")
            # else:
            #     print("Original file 'ipfs_publish_test.txt' not found to complete verification test.")

        else:
            print(f"[FAILURE] Could not fetch stamp data from IPFS for CID: {TEST_CID}")
    else:
        print("\nSkipping direct IPFS fetch test in verifier.py (TEST_CID not set).")
        print("Use main_cli.py to test IPFS verification flow.")

    # Keep existing local file verification tests if desired, or rely on main_cli.py for those.
    # For brevity, the previous local file test cases are omitted here, assuming
    # they are covered by main_cli.py or previous direct tests of verifier.py.