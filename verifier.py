import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Import functions/constants from our other modules
try:
    # Assuming execution from project root or that modules are in PYTHONPATH
    from .stamper import calculate_file_hash, create_stamp_payload_to_sign, PROTOCOL_VERSION
    from .identity_manager import load_public_key # We'll use the embedded one first
except ImportError:
    # Fallback for direct execution (e.g. python verifier.py)
    from stamper import calculate_file_hash, create_stamp_payload_to_sign, PROTOCOL_VERSION
    from identity_manager import load_public_key


def verify_signature(public_key_pem_str: str, signature_b64: str, data_that_was_signed: bytes):
    """
    Verifies the signature against the data using the public key.
    - public_key_pem_str: The public key in PEM format (string).
    - signature_b64: The base64 encoded signature string.
    - data_that_was_signed: The exact bytes that were originally signed.

    Returns True if verification is successful, raises InvalidSignature otherwise.
    """
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
            hashes.SHA256() # Hash algorithm used for the signature scheme
        )
        return True
    except InvalidSignature:
        # Let the caller handle or re-raise if they prefer
        # print("DEBUG: Signature verification failed.")
        raise # Re-raise the InvalidSignature exception


def verify_tsnue_stamp(filepath_to_verify, stamp_filepath):
    """
    Verifies a file against its Tsnu'e Stamp.

    Returns a dictionary with:
    {
        "verified": bool,
        "checks": {
            "protocol_version_match": bool,
            "file_integrity_match": bool, // Compares current file hash with stored hash
            "signature_valid": bool
        },
        "message": "string describing outcome",
        "stamp_content": dict (the loaded stamp)
    }
    """
    import os

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
        results["message"] = f"Stamp file not found: {stamp_filepath}"
        return results

    # 1. Load the Tsnu'e Stamp from its file
    try:
        with open(stamp_filepath, 'r') as sf:
            stamp_data = json.load(sf)
        results["stamp_content"] = stamp_data
    except json.JSONDecodeError:
        results["message"] = f"Error: Could not decode JSON from stamp file: {stamp_filepath}"
        return results
    except Exception as e:
        results["message"] = f"Error reading stamp file: {e}"
        return results

    # 2. Check Protocol Version (basic check)
    if stamp_data.get("protocol_version") == PROTOCOL_VERSION:
        results["checks"]["protocol_version_match"] = True
    else:
        results["message"] = f"Protocol version mismatch. Expected '{PROTOCOL_VERSION}', got '{stamp_data.get('protocol_version')}'."
        # Potentially stop further checks if this is critical
        # For now, we'll continue other checks

    # 3. Recalculate hash of the current file
    current_file_hash_algorithm = stamp_data.get("file_hash_algorithm", 'sha256') # Use algorithm from stamp
    try:
        current_file_hash_hex = calculate_file_hash(filepath_to_verify, current_file_hash_algorithm)
    except Exception as e:
        results["message"] = f"Error calculating hash for '{filepath_to_verify}': {e}"
        return results

    # 4. Compare current file hash with hash stored in the stamp (Integrity Check)
    stored_file_hash = stamp_data.get("file_hash")
    if current_file_hash_hex == stored_file_hash:
        results["checks"]["file_integrity_match"] = True
    else:
        results["message"] += "File integrity check FAILED: File content has changed since stamping. "
        # Even if integrity fails, we might still want to check if the signature on the *original* hash was valid.
        # However, for a simple "verified" status, this is a failure.

    # 5. Reconstruct the payload that was originally signed
    # This MUST match the structure and content from stamper.create_stamp_payload_to_sign()
    payload_to_verify = create_stamp_payload_to_sign(
        stamp_data.get("tsnue_id"),
        stamp_data.get("timestamp_utc"),
        stamp_data.get("original_filename"),
        stamp_data.get("file_hash_algorithm"),
        stamp_data.get("file_hash") # IMPORTANT: Use the HASH FROM THE STAMP for signature verification
                                  # This verifies the signature on the *original* declared hash.
    )

    # 6. Verify the signature
    public_key_pem_str = stamp_data.get("public_key_pem")
    signature_b64 = stamp_data.get("signature")

    if not public_key_pem_str or not signature_b64:
        results["message"] += "Missing public key or signature in stamp data. Cannot verify signature. "
    else:
        try:
            verify_signature(public_key_pem_str, signature_b64, payload_to_verify)
            results["checks"]["signature_valid"] = True
        except InvalidSignature:
            results["message"] += "Signature verification FAILED: Signature is not valid for the data in the stamp. "
        except Exception as e:
            results["message"] += f"Error during signature verification: {e}. "

    # 7. Determine overall verification status
    if results["checks"]["protocol_version_match"] and \
       results["checks"]["file_integrity_match"] and \
       results["checks"]["signature_valid"]:
        results["verified"] = True
        results["message"] = "File successfully verified: Authentic and integrity intact."
    elif not results["message"]: # If no specific error message set yet
         results["message"] = "Verification failed. Check individual checks."


    return results

# --- Main execution for testing ---
if __name__ == "__main__":
    print("Tsnu'e-Mahtem Verifier")
    print("----------------------")

    # Test files generated by stamper.py
    TEST_FILE_ORIGINAL = "sample_document.txt"
    STAMP_FILE_ORIGINAL = "sample_document.txt.tsnue-stamp.json"

    # --- Test Case 1: Verify the original, unaltered file ---
    print(f"\n--- Test Case 1: Verifying original file '{TEST_FILE_ORIGINAL}' ---")
    if not (os.path.exists(TEST_FILE_ORIGINAL) and os.path.exists(STAMP_FILE_ORIGINAL)):
        print(f"Error: Test files '{TEST_FILE_ORIGINAL}' or '{STAMP_FILE_ORIGINAL}' not found.")
        print("Please run stamper.py first to generate them.")
    else:
        verification_result = verify_tsnue_stamp(TEST_FILE_ORIGINAL, STAMP_FILE_ORIGINAL)
        print(json.dumps(verification_result, indent=2))
        if verification_result["verified"]:
            print("SUCCESS: Original file verified successfully.")
        else:
            print("FAILURE: Original file verification failed.")

    # --- Test Case 2: Verify a tampered file ---
    print(f"\n--- Test Case 2: Verifying a tampered file ---")
    TEST_FILE_TAMPERED = "sample_document_tampered.txt"
    # Create a tampered version
    if os.path.exists(TEST_FILE_ORIGINAL):
        with open(TEST_FILE_ORIGINAL, 'r') as f_orig:
            content = f_orig.read()
        with open(TEST_FILE_TAMPERED, 'w') as f_tamp:
            f_tamp.write(content + "\nThis line was added to tamper the file.")
        print(f"Created '{TEST_FILE_TAMPERED}' for testing.")

        verification_result_tampered = verify_tsnue_stamp(TEST_FILE_TAMPERED, STAMP_FILE_ORIGINAL)
        print(json.dumps(verification_result_tampered, indent=2))
        if not verification_result_tampered["verified"] and \
           not verification_result_tampered["checks"]["file_integrity_match"] and \
           verification_result_tampered["checks"]["signature_valid"]: # Signature on original hash should still be valid
            print("SUCCESS: Tampered file correctly identified as NOT VERIFIED (integrity failed, signature on original data was valid).")
        else:
            print("FAILURE: Tampered file test did not behave as expected.")
        # Clean up tampered file
        # os.remove(TEST_FILE_TAMPERED) # Comment out if you want to inspect it
    else:
        print(f"Skipping tampered file test as original '{TEST_FILE_ORIGINAL}' not found.")


    # --- Test Case 3: Verify with a tampered stamp (e.g., modified signature) ---
    print(f"\n--- Test Case 3: Verifying with a tampered stamp ---")
    STAMP_FILE_TAMPERED = "sample_document.txt.tsnue-stamp-tampered.json"
    if os.path.exists(STAMP_FILE_ORIGINAL):
        with open(STAMP_FILE_ORIGINAL, 'r') as sf_orig:
            stamp_content_tampered = json.load(sf_orig)
        # Tamper the signature slightly
        original_sig = stamp_content_tampered["signature"]
        if original_sig:
             # Change one character; ensure it doesn't become valid by chance
            tampered_sig = list(original_sig)
            tampered_sig[5] = 'X' if tampered_sig[5] != 'X' else 'Y'
            stamp_content_tampered["signature"] = "".join(tampered_sig)

        with open(STAMP_FILE_TAMPERED, 'w') as sf_tamp:
            json.dump(stamp_content_tampered, sf_tamp, indent=2)
        print(f"Created '{STAMP_FILE_TAMPERED}' for testing.")

        verification_result_tampered_stamp = verify_tsnue_stamp(TEST_FILE_ORIGINAL, STAMP_FILE_TAMPERED)
        print(json.dumps(verification_result_tampered_stamp, indent=2))
        if not verification_result_tampered_stamp["verified"] and \
           not verification_result_tampered_stamp["checks"]["signature_valid"]:
            print("SUCCESS: Tampered stamp correctly identified as NOT VERIFIED (signature invalid).")
        else:
            print("FAILURE: Tampered stamp test did not behave as expected.")
        # Clean up tampered stamp file
        # os.remove(STAMP_FILE_TAMPERED) # Comment out if you want to inspect it
    else:
        print(f"Skipping tampered stamp test as original stamp '{STAMP_FILE_ORIGINAL}' not found.")

    # Note: To keep sample_document_tampered.txt and sample_document.txt.tsnue-stamp-tampered.json
    # after running, comment out the os.remove lines in the test cases.
    # You can then add them to .gitignore if you don't want them committed.
    # For now, we'll let them be created and you can decide if you want to commit them
    # as further examples or add to .gitignore.
    # Let's add the generated files to .gitignore to keep repo clean.
    # Update .gitignore with:
    # sample_document_tampered.txt
    # *.tsnue-stamp-tampered.json