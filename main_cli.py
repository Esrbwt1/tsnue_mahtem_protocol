import argparse
import os
import json
import sys
import getpass
import tempfile # For temporary file when verifying IPFS stamps

from cryptography.hazmat.primitives import serialization

try:
    from identity_manager import (
        generate_key_pair, save_private_key, save_public_key,
        load_private_key, load_public_key, get_tsnue_id,
        PRIVATE_KEY_FILE, PUBLIC_KEY_FILE
    )
    from stamper import create_tsnue_stamp, calculate_file_hash, publish_stamp_to_ipfs
    from verifier import verify_tsnue_stamp, fetch_stamp_from_ipfs # ADDED fetch_stamp_from_ipfs
    from stamp_store import add_stamp, get_stamp_by_file_hash, get_stamps_by_filename, list_all_stamps, STAMP_STORE_FILE
except ImportError as e:
    print(f"[ERROR] Critical module import failed: {e}")
    print("Please ensure all Tsnu'e-Mahtem Python files are in the same directory as main_cli.py.")
    sys.exit(1)

def print_success(message):
    print(f"[SUCCESS] {message}")

def print_error(message):
    print(f"[ERROR] {message}")

def print_warning(message):
    print(f"[WARNING] {message}")

def print_info(message):
    print(f"[INFO] {message}")

# ... (handle_generate_id, handle_stamp_file, handle_show_id, handle_list_stamps remain unchanged from previous step) ...
# For brevity, I'm only showing the changed handle_verify_file and the main parser setup again.
# Make sure the other handler functions are still present as they were in the previous version you had.

def handle_generate_id(args):
    print_info("Attempting to generate Tsnu'e ID (key pair)...")
    if not args.force and (os.path.exists(PRIVATE_KEY_FILE) or os.path.exists(PUBLIC_KEY_FILE)):
        print_warning(f"Key files ('{PRIVATE_KEY_FILE}', '{PUBLIC_KEY_FILE}') already exist.")
        print_info("Use --force to overwrite existing keys.")
        try:
            if os.path.exists(PUBLIC_KEY_FILE):
                public_key = load_public_key()
                tsnue_id = get_tsnue_id(public_key)
                print_info(f"Existing Tsnu'e ID: {tsnue_id}")
            else:
                print_warning(f"Public key file '{PUBLIC_KEY_FILE}' not found, cannot display existing ID.")
        except Exception as e:
            print_error(f"Could not load existing public key: {e}")
        return

    print_info("Proceeding with new key pair generation.")
    key_password = None
    if not args.no_password:
        while True:
            key_password_temp = getpass.getpass("Enter password to encrypt new private key (leave blank or use --no-password for none): ")
            if not key_password_temp:
                print_info("No password entered. Private key will NOT be encrypted.")
                key_password = None
                break
            key_password_confirm = getpass.getpass("Confirm password: ")
            if key_password_temp == key_password_confirm:
                key_password = key_password_temp
                break
            else:
                print_error("Passwords do not match. Please try again.")
    else:
        print_info("Option --no-password selected. Private key will NOT be encrypted.")
        key_password = None

    private_key_obj, public_key_obj = generate_key_pair()
    try:
        save_private_key(private_key_obj, PRIVATE_KEY_FILE, password=key_password)
        print_info(f"Private key saved to: {PRIVATE_KEY_FILE}")
        save_public_key(public_key_obj, PUBLIC_KEY_FILE)
        print_info(f"Public key saved to: {PUBLIC_KEY_FILE}")
        tsnue_id = get_tsnue_id(public_key_obj)
        print_success(f"New Tsnu'e ID generated: {tsnue_id}")
        if key_password:
            print_info("Private key is ENCRYPTED.")
        else:
            print_info("Private key is NOT encrypted.")
    except Exception as e:
        print_error(f"Failed to save keys: {e}")

def handle_stamp_file(args):
    filepath = args.filepath
    publish_to_ipfs_flag = args.publish_ipfs

    print_info(f"Attempting to stamp file: {filepath}")
    if publish_to_ipfs_flag:
        print_info("IPFS publishing is ENABLED for this stamp.")

    if not os.path.exists(filepath):
        print_error(f"File not found at '{filepath}'. Cannot stamp.")
        return
    if not os.path.isfile(filepath):
        print_error(f"Path '{filepath}' is not a file. Cannot stamp.")
        return
    
    if not os.path.exists(PRIVATE_KEY_FILE):
        print_error(f"Private key file '{PRIVATE_KEY_FILE}' not found.")
        print_info("Please generate an ID first using the 'generate-id' command.")
        return

    private_key_password_to_use = args.password
    if not private_key_password_to_use:
        print_info(f"Private key '{PRIVATE_KEY_FILE}' exists. It might be password protected.")
        prompt_for_pw = input("Do you want to provide a password to unlock it? (yes/no, default no): ").lower()
        if prompt_for_pw == 'yes':
            private_key_password_to_use = getpass.getpass(f"Enter password for private key '{PRIVATE_KEY_FILE}': ")
        elif not private_key_password_to_use:
             print_info("Attempting to load private key without a password.")
             private_key_password_to_use = None

    try:
        print_info(f"Processing file for stamping...")
        tsnue_stamp_data = create_tsnue_stamp(
            filepath,
            private_key_path=PRIVATE_KEY_FILE,
            private_key_password=private_key_password_to_use
        )

        if not args.no_store: 
            if add_stamp(tsnue_stamp_data):
                print_success("Tsnu'e Stamp created and added to local store.")
            else:
                print_error("Tsnu'e Stamp created, but FAILED to add to local store.")
        else:
            print_info("Tsnu'e Stamp created (local store addition skipped due to --no-store).")

        print("--- Stamp Details ---")
        print(json.dumps(tsnue_stamp_data, indent=2))
        print("---------------------")

        if publish_to_ipfs_flag:
            print_info("Attempting to publish stamp to IPFS...")
            cid = publish_stamp_to_ipfs(tsnue_stamp_data) 
            if cid:
                print_success(f"Stamp successfully published to IPFS with CID: {cid}")
                print_info(f"You can view it via an IPFS gateway, e.g., https://ipfs.io/ipfs/{cid} or http://localhost:8080/ipfs/{cid}")
            else:
                print_error("Failed to publish stamp to IPFS. Check IPFS daemon status and connection.")

    except FileNotFoundError as e:
        print_error(f"File not found during stamping process: {e}.")
    except (ValueError, TypeError) as e:
        if "decryption failed" in str(e).lower() or \
           "bad decrypt" in str(e).lower() or \
           "password was given but private key is not encrypted" in str(e).lower() or \
           "private key is encrypted but no password was sgiven" in str(e).lower().replace("given","sgiven"):
            print_error(f"Failed to load private key: Incorrect password or key encryption status issue.")
            print_info(f"Details: {e}")
        else:
            print_error(f"An issue occurred during stamping (ValueError/TypeError): {e}")
    except Exception as e:
        print_error(f"An unexpected error occurred during stamping: {e}")

def handle_verify_file(args): # MODIFIED TO HANDLE IPFS CID
    filepath_to_verify = args.filepath
    stamp_identifier = args.stamp_identifier
    print_info(f"Attempting to verify file: '{filepath_to_verify}'")

    if not os.path.exists(filepath_to_verify):
        print_error(f"File to verify not found at '{filepath_to_verify}'.")
        return

    actual_stamp_file_to_verify_with = None # This will be a local path to a stamp JSON
    stamp_source_info = ""
    temp_stamp_file_holder = None # Will hold NamedTemporaryFile object if IPFS/store used

    # Determine if stamp_identifier is an IPFS CID
    # Basic check: starts with "Qm" (CIDv0) or "bafy" (CIDv1) and is of typical length
    is_ipfs_cid = False
    if isinstance(stamp_identifier, str) and \
       (stamp_identifier.startswith("Qm") and len(stamp_identifier) == 46 or \
        stamp_identifier.startswith("bafy") and len(stamp_identifier) > 50): # CIDv1 are longer
        is_ipfs_cid = True

    if is_ipfs_cid:
        print_info(f"Stamp identifier '{stamp_identifier}' looks like an IPFS CID. Attempting to fetch from IPFS.")
        # Ensure IPFS daemon is running
        fetched_stamp_data = fetch_stamp_from_ipfs(stamp_identifier)
        if fetched_stamp_data:
            try:
                # Create a secure temporary file to write the fetched JSON stamp data
                temp_stamp_file_holder = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".tsnue-stamp.json", encoding='utf-8')
                json.dump(fetched_stamp_data, temp_stamp_file_holder)
                temp_stamp_file_holder.close() # Close it so verify_tsnue_stamp can open it
                actual_stamp_file_to_verify_with = temp_stamp_file_holder.name
                stamp_source_info = f"stamp fetched from IPFS (CID: {stamp_identifier})"
                print_info(f"Temporarily saved IPFS stamp to: {actual_stamp_file_to_verify_with}")
            except Exception as e_temp_write:
                print_error(f"Could not write fetched IPFS stamp data to temporary file: {e_temp_write}")
                if temp_stamp_file_holder and os.path.exists(temp_stamp_file_holder.name):
                    os.remove(temp_stamp_file_holder.name) # Clean up if created
                return
        else:
            print_error(f"Failed to fetch stamp data from IPFS for CID: {stamp_identifier}")
            return # Cannot proceed if IPFS fetch fails

    # If not an IPFS CID, try as direct file path
    elif os.path.exists(stamp_identifier) and \
         (stamp_identifier.endswith(".tsnue-stamp.json") or stamp_identifier.endswith(".json")):
        print_info(f"Using direct local stamp file: '{stamp_identifier}'")
        actual_stamp_file_to_verify_with = stamp_identifier
        stamp_source_info = f"direct local stamp file '{stamp_identifier}'"
    else:
        # Try as file_hash from local store
        print_info(f"Searching local stamp store for identifier (assumed file_hash): '{stamp_identifier}'")
        retrieved_stamp_data = get_stamp_by_file_hash(stamp_identifier)
        if retrieved_stamp_data:
            try:
                temp_stamp_file_holder = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".tsnue-stamp.json", encoding='utf-8')
                json.dump(retrieved_stamp_data, temp_stamp_file_holder)
                temp_stamp_file_holder.close()
                actual_stamp_file_to_verify_with = temp_stamp_file_holder.name
                stamp_source_info = f"stamp from local store (found by hash: {args.stamp_identifier})"
                print_info(f"Temporarily saved store stamp to: {actual_stamp_file_to_verify_with}")
            except Exception as e_temp_write:
                print_error(f"Could not write store stamp data to temporary file: {e_temp_write}")
                if temp_stamp_file_holder and os.path.exists(temp_stamp_file_holder.name):
                    os.remove(temp_stamp_file_holder.name)
                return
        else:
            # Fallback: calculate hash of current file and check store
            print_info(f"Stamp not found by identifier '{stamp_identifier}'.")
            print_info(f"Calculating hash of '{filepath_to_verify}' to check store as a fallback...")
            try:
                current_file_hash = calculate_file_hash(filepath_to_verify)
                print_info(f"Current file hash: {current_file_hash}")
                retrieved_stamp_data_by_current_hash = get_stamp_by_file_hash(current_file_hash)
                if retrieved_stamp_data_by_current_hash:
                    print_info(f"Found matching stamp in store by current file hash: {current_file_hash}")
                    temp_stamp_file_holder = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".tsnue-stamp.json", encoding='utf-8')
                    json.dump(retrieved_stamp_data_by_current_hash, temp_stamp_file_holder)
                    temp_stamp_file_holder.close()
                    actual_stamp_file_to_verify_with = temp_stamp_file_holder.name
                    stamp_source_info = f"stamp from local store (found by current file hash: {current_file_hash})"
                    print_info(f"Temporarily saved store stamp to: {actual_stamp_file_to_verify_with}")
                else:
                    print_warning(f"No stamp found in local store for current file hash '{current_file_hash}'.")
                    print_info("The file may not have been stamped, or its content has changed from any known stamp.")
                    return
            except Exception as e_hash:
                print_error(f"Error calculating file hash for fallback check: {e_hash}")
                return

    if not actual_stamp_file_to_verify_with:
        print_error("Could not identify or prepare a valid stamp to verify against. Verification aborted.")
        # Cleanup if temp_stamp_file_holder was somehow set but actual_stamp_file_to_verify_with wasn't
        if temp_stamp_file_holder and os.path.exists(temp_stamp_file_holder.name):
            try: os.remove(temp_stamp_file_holder.name)
            except OSError as e_del: print_warning(f"Could not remove temp file '{temp_stamp_file_holder.name}': {e_del}")
        return

    try:
        print_info(f"Verifying '{filepath_to_verify}' using {stamp_source_info}...")
        verification_result = verify_tsnue_stamp(filepath_to_verify, actual_stamp_file_to_verify_with)
        
        print("\n--- Verification Result ---")
        print(json.dumps(verification_result, indent=2))
        print("-------------------------")

        if verification_result["verified"]:
            print_success("File is Authentic and Integrity is Intact.")
        else:
            print_error("File FAILED verification.")
            # ... (detailed failure reasons) ...
            if not verification_result["checks"]["protocol_version_match"]: print_warning("Protocol version mismatch.")
            if not verification_result["checks"]["file_integrity_match"]: print_warning("File integrity check FAILED.")
            if not verification_result["checks"]["signature_valid"]: print_warning("Signature verification FAILED.")
    except Exception as e:
        print_error(f"An unexpected error occurred during verification: {e}")
    finally:
        # Clean up the temporary file if it was created from IPFS or store
        if temp_stamp_file_holder and os.path.exists(actual_stamp_file_to_verify_with): # Check actual path used
            try:
                os.remove(actual_stamp_file_to_verify_with)
                print_info(f"Cleaned up temporary stamp file: {actual_stamp_file_to_verify_with}")
            except OSError as e_del:
                print_warning(f"Could not remove temporary stamp file '{actual_stamp_file_to_verify_with}': {e_del}")

def handle_show_id(args):
    print_info("Attempting to display Tsnu'e ID...")
    try:
        if not os.path.exists(PUBLIC_KEY_FILE):
            print_error(f"Public key file '{PUBLIC_KEY_FILE}' not found.")
            print_info("Please generate an ID first using the 'generate-id' command.")
            return

        public_key = load_public_key()
        tsnue_id = get_tsnue_id(public_key)
        print_success(f"Current Tsnu'e ID: {tsnue_id}")
        if args.show_key:
            print("\n--- Public Key (PEM) ---")
            print(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'))
            print("------------------------")
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")

def handle_list_stamps(args):
    limit = args.limit
    filename_filter = args.filename

    print_info(f"Listing stamps from store: '{STAMP_STORE_FILE}'")
    if not os.path.exists(STAMP_STORE_FILE):
        print_warning(f"Stamp store file '{STAMP_STORE_FILE}' not found. No stamps to list.")
        return
        
    stamps_to_show = []
    if filename_filter:
        print_info(f"Filtering by filename: '{filename_filter}'")
        stamps_data_full = get_stamps_by_filename(filename_filter)
        results = []
        for s_data in stamps_data_full:
            results.append({
                "file_hash": s_data.get("file_hash"),
                "original_filename": s_data.get("original_filename"),
                "tsnue_id": s_data.get("tsnue_id"),
                "timestamp_utc": s_data.get("timestamp_utc"),
                "added_to_store_utc": s_data.get("_store_metadata", {}).get("added_to_store_utc")
            })
        results.sort(key=lambda x: x.get("added_to_store_utc", 0) if x.get("added_to_store_utc") is not None else 0, reverse=True)
        if limit is not None and limit > 0 :
            stamps_to_show = results[:limit]
        else:
            stamps_to_show = results
    else:
        stamps_to_show = list_all_stamps(limit=limit if limit is not None and limit > 0 else None)

    if not stamps_to_show:
        print_info("No stamps found matching your criteria.")
        return

    print_success(f"Found {len(stamps_to_show)} stamp(s):")
    for i, stamp_preview in enumerate(stamps_to_show):
        print(f"\n--- Stamp {i+1} of {len(stamps_to_show)} ---")
        print(json.dumps(stamp_preview, indent=2))
        print("--------------------")

def main():
    parser = argparse.ArgumentParser(
        description="Tsnu'e-Mahtem: Content Authenticity & Provenance CLI",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands (use <command> -h for more help)", required=True)

    parser_generate_id = subparsers.add_parser("generate-id", help="Generate a new Tsnu'e ID (key pair).")
    parser_generate_id.add_argument("--force", action="store_true", help="Force overwrite if keys already exist.")
    parser_generate_id.add_argument("--no-password", action="store_true", help="Generate private key without password encryption.")
    parser_generate_id.set_defaults(func=handle_generate_id)

    parser_show_id = subparsers.add_parser("show-id", help="Display the current Tsnu'e ID and optionally the public key.")
    parser_show_id.add_argument("--show-key", action="store_true", help="Also display the public key PEM.")
    parser_show_id.set_defaults(func=handle_show_id)

    parser_stamp = subparsers.add_parser("stamp", help="Create a Tsnu'e Stamp for a file.")
    parser_stamp.add_argument("filepath", help="Path to the file to stamp.")
    parser_stamp.add_argument("-p", "--password", help="Password for the private key (if encrypted). If not provided, will be prompted.", default=None)
    parser_stamp.add_argument("--publish-ipfs", action="store_true", help="Publish the generated stamp to IPFS.")
    parser_stamp.add_argument("--no-store", action="store_true", help="Do not add the stamp to the local JSON store.")
    parser_stamp.set_defaults(func=handle_stamp_file)

    parser_verify = subparsers.add_parser("verify", help="Verify a file against a Tsnu'e Stamp.") # MODIFIED help
    parser_verify.add_argument("filepath", help="Path to the file to verify.")
    parser_verify.add_argument("stamp_identifier",
        help="Identifier for the stamp. Can be:\n"
             "  - An IPFS CID of the stamp.\n" # MOVED UP
             "  - The file_hash of the stamp in the local store.\n"
             "  - Path to a specific .tsnue-stamp.json file.\n"
             "If a local file_hash is given and not found, the tool will try to\n"
             "calculate the hash of the current <filepath> and search the store again."
    )
    parser_verify.set_defaults(func=handle_verify_file)

    parser_list = subparsers.add_parser("list-stamps", help="List stamps from the local store.")
    parser_list.add_argument("-n", "--limit", type=int, help="Limit the number of stamps displayed (most recent first).")
    parser_list.add_argument("-f", "--filename", type=str, help="Filter stamps by original filename.")
    parser_list.set_defaults(func=handle_list_stamps)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        print_error("No command specified or command not recognized.")
        parser.print_help(sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()