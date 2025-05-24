import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import ipfshttpclient # For IPFS interaction

# Import functions/constants from our other modules
try:
    from .stamper import calculate_file_hash, create_stamp_payload_to_sign, PROTOCOL_VERSION, IPFS_API_ADDR
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
        except ipfshttpclient.exceptions.ConnectionError: # This should be caught first if daemon is down
            print(f"[ERROR] IPFS: Could not connect to daemon at {IPFS_API_ADDR}. Is 'ipfs daemon' running?")
            return None
        except Exception as e_conn: # Broader catch for other connection setup issues
            print(f"[ERROR] IPFS: Failed to establish connection to daemon. Details: {e_conn}")
            return None


        timeout_seconds = 20
        print(f"[INFO] IPFS: Fetching content for CID {cid_string} (timeout: {timeout_seconds}s)...")
        content_bytes = ipfs_client.cat(cid_string, timeout=timeout_seconds)
        content_str = content_bytes.decode('utf-8')
        
        stamp_data_dict = json.loads(content_str)
        print(f"[SUCCESS] IPFS: Successfully fetched and parsed stamp data for CID: {cid_string}")
        return stamp_data_dict

    except ipfshttpclient.exceptions.TimeoutError: # More specific timeout often from underlying requests
        print(f"[ERROR] IPFS: Timeout while fetching CID {cid_string}. Content may not be available or network is slow.")
        return None
    except ipfshttpclient.exceptions.ConnectionError: # Already caught above, but good for defense
        print(f"[ERROR] IPFS: ( вторично ) Could not connect to daemon at {IPFS_API_ADDR}.") # Re-catch with differentiation
        return None
    except ipfshttpclient.exceptions.ErrorResponse as e_api:
        error_str = str(e_api).lower()
        if "context deadline exceeded" in error_str or \
           "not found" in error_str or \
           "no link named" in error_str or \
           "path does not have enough components" in error_str or \
           "invalid cid" in error_str:
             print(f"[ERROR] IPFS: Content for CID '{cid_string}' not found on the network, the CID is invalid, or access timed out during search.")
        elif "timeout" in error_str: # Some timeouts manifest as ErrorResponse
             print(f"[ERROR] IPFS: Timeout occurred while fetching CID '{cid_string}' (reported as API error).")
        else:
            print(f"[ERROR] IPFS: API ErrorResponse while fetching CID '{cid_string}': {e_api}")
        return None
    except json.JSONDecodeError:
        print(f"[ERROR] IPFS: Fetched content for CID '{cid_string}', but it was not valid JSON.")
        return None
    except Exception as e: # General catch-all
        print(f"[ERROR] IPFS: An unexpected error occurred while fetching CID '{cid_string}': {type(e).__name__} - {e}")
        return None
    finally:
        if ipfs_client:
            try:
                ipfs_client.close()
            except Exception as e_close:
                print(f"[WARNING] IPFS: Error trying to close IPFS client connection: {e_close}")


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
        "stamp_content": None
    }

    if not os.path.exists(filepath_to_verify):
        results["message"] = f"File to verify not found: {filepath_to_verify}"
        return results
    if not os.path.exists(stamp_filepath):
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

    if stamp_data.get("protocol_version") == PROTOCOL_VERSION:
        results["checks"]["protocol_version_match"] = True
    else:
        results["message"] = f"Protocol version mismatch. Expected '{PROTOCOL_VERSION}', got '{stamp_data.get('protocol_version')}'."
    
    current_file_hash_algorithm = stamp_data.get("file_hash_algorithm", 'sha256')
    try:
        current_file_hash_hex = calculate_file_hash(filepath_to_verify, current_file_hash_algorithm)
    except Exception as e:
        results["message"] = (results["message"] + " " if results["message"] else "") + f"Error calculating hash for '{filepath_to_verify}': {e}"
        return results

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
        results["checks"]["signature_valid"] = False
        if results["checks"]["protocol_version_match"] and results["checks"]["file_integrity_match"]:
            results["verified"] = False
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
    elif not results["message"]: # if no specific error message was set, provide a generic one
         results["message"] = "Verification failed due to one or more checks not passing. See 'checks' for details."
    
    return results

if __name__ == "__main__":
    print("Tsnu'e-Mahtem Verifier (Test Block with IPFS fetching awareness)")
    print("-------------------------------------------------------------")
    print("This test block can try to fetch a stamp from IPFS if a CID is provided.")
    print("Ensure IPFS daemon is running for IPFS tests.")

    # To test IPFS fetching directly, uncomment below and replace with a real CID of a stamp you published
    # TEST_CID = "QmXnQztaZbBQS8yVSSvELYVRnZwVqAJPWKvP12qHVPscv2" # Example from previous step
    TEST_CID = None 

    if TEST_CID:
        print(f"\n--- Test Case: Fetching stamp from IPFS with CID: {TEST_CID} ---")
        fetched_stamp_data = fetch_stamp_from_ipfs(TEST_CID)
        if fetched_stamp_data:
            print("[SUCCESS] Fetched stamp data from IPFS:")
            print(json.dumps(fetched_stamp_data, indent=2))
            
            # Conceptual full verification test (requires original file):
            # ORIGINAL_FILE_FOR_CID = "ipfs_publish_test.txt" # The file that TEST_CID was for
            # if os.path.exists(ORIGINAL_FILE_FOR_CID):
            #     temp_stamp_path = "_temp_direct_ipfs_stamp.json"
            #     with open(temp_stamp_path, "w") as tmp_f:
            #         json.dump(fetched_stamp_data, tmp_f)
            #     print(f"\nVerifying '{ORIGINAL_FILE_FOR_CID}' with fetched IPFS stamp...")
            #     result = verify_tsnue_stamp(ORIGINAL_FILE_FOR_CID, temp_stamp_path)
            #     print("\nVerification result using fetched IPFS stamp:")
            #     print(json.dumps(result, indent=2))
            #     if os.path.exists(temp_stamp_path): os.remove(temp_stamp_path)
            # else:
            #     print(f"Original file '{ORIGINAL_FILE_FOR_CID}' not found to complete verification test with fetched IPFS stamp.")
        else:
            print(f"[FAILURE] Could not fetch stamp data from IPFS for CID: {TEST_CID}")
    else:
        print("\nSkipping direct IPFS fetch test in verifier.py (TEST_CID not set).")
        print("Use main_cli.py to test IPFS verification flow.")