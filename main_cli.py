import argparse
import os
import json
import sys
import getpass

from cryptography.hazmat.primitives import serialization

try:
    from identity_manager import (
        generate_key_pair, save_private_key, save_public_key,
        load_private_key, load_public_key, get_tsnue_id,
        PRIVATE_KEY_FILE, PUBLIC_KEY_FILE
    )
    from stamper import create_tsnue_stamp, calculate_file_hash
    from verifier import verify_tsnue_stamp
    from stamp_store import add_stamp, get_stamp_by_file_hash, get_stamps_by_filename, list_all_stamps, STAMP_STORE_FILE
except ImportError as e:
    print(f"[ERROR] Critical module import failed: {e}")
    print("Please ensure all Tsnu'e-Mahtem Python files (identity_manager.py, stamper.py, etc.) are in the same directory as main_cli.py.")
    sys.exit(1)

def print_success(message):
    print(f"[SUCCESS] {message}")

def print_error(message):
    print(f"[ERROR] {message}")

def print_warning(message):
    print(f"[WARNING] {message}")

def print_info(message):
    print(f"[INFO] {message}")

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
                # Optional: allow limited retries or exit
                # For now, let's allow another try by continuing loop.
                # To exit on mismatch:
                # print_error("Passwords do not match. Aborting generation.")
                # return
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
    print_info(f"Attempting to stamp file: {filepath}")

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
        # Only prompt if key exists and no password given via CLI
        print_info(f"Private key '{PRIVATE_KEY_FILE}' exists. It might be password protected.")
        prompt_for_pw = input("Do you want to provide a password to unlock it? (yes/no, default no): ").lower()
        if prompt_for_pw == 'yes':
            private_key_password_to_use = getpass.getpass(f"Enter password for private key '{PRIVATE_KEY_FILE}': ")
        elif not private_key_password_to_use: # Catches 'no' or blank input at prompt
             print_info("Attempting to load private key without a password.")
             private_key_password_to_use = None

    try:
        print_info(f"Processing file for stamping...")
        tsnue_stamp_data = create_tsnue_stamp(
            filepath,
            private_key_path=PRIVATE_KEY_FILE,
            private_key_password=private_key_password_to_use
        )

        if add_stamp(tsnue_stamp_data):
            print_success("Tsnu'e Stamp created and added to store.")
            print("--- Stamp Details ---")
            print(json.dumps(tsnue_stamp_data, indent=2))
            print("---------------------")
        else:
            print_error("Tsnu'e Stamp created, but FAILED to add to store.")
            print_info("The stamp data that was created (but not stored):")
            print(json.dumps(tsnue_stamp_data, indent=2))

    except FileNotFoundError as e: # Should be caught by earlier checks, but good fallback
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
        # import traceback # Consider adding for more detailed debugging if needed by user
        # traceback.print_exc()

def handle_verify_file(args):
    filepath_to_verify = args.filepath
    stamp_identifier = args.stamp_identifier
    print_info(f"Attempting to verify file: '{filepath_to_verify}'")

    if not os.path.exists(filepath_to_verify):
        print_error(f"File to verify not found at '{filepath_to_verify}'.")
        return

    actual_stamp_file_to_verify_with = None
    stamp_source_info = ""
    temp_stamp_file_path = None # To keep track of temporary file for cleanup

    # Try to use stamp_identifier as a direct file path first
    if os.path.exists(stamp_identifier) and \
       (stamp_identifier.endswith(".tsnue-stamp.json") or stamp_identifier.endswith(".json")):
        print_info(f"Using direct stamp file: '{stamp_identifier}'")
        actual_stamp_file_to_verify_with = stamp_identifier
        stamp_source_info = f"direct stamp file '{stamp_identifier}'"
    else:
        # Assume stamp_identifier is a file_hash for store lookup
        print_info(f"Searching stamp store for identifier (assumed file_hash): '{stamp_identifier}'")
        retrieved_stamp_data = get_stamp_by_file_hash(stamp_identifier)
        if retrieved_stamp_data:
            temp_stamp_file_path = f"_temp_stamp_for_verify_{stamp_identifier.replace('/', '_').replace(':', '_')}.json"
            try:
                with open(temp_stamp_file_path, 'w') as tsf:
                    json.dump(retrieved_stamp_data, tsf)
                actual_stamp_file_to_verify_with = temp_stamp_file_path
                stamp_source_info = f"stamp from store (found by hash: {args.stamp_identifier})"
            except Exception as e_write:
                print_error(f"Could not write temporary stamp file '{temp_stamp_file_path}': {e_write}")
                return # Cannot proceed if temp file fails
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
                    temp_stamp_file_path = f"_temp_stamp_for_verify_{current_file_hash.replace('/', '_').replace(':', '_')}.json"
                    with open(temp_stamp_file_path, 'w') as tsf:
                        json.dump(retrieved_stamp_data_by_current_hash, tsf)
                    actual_stamp_file_to_verify_with = temp_stamp_file_path
                    stamp_source_info = f"stamp from store (found by current file hash: {current_file_hash})"
                else:
                    print_warning(f"No stamp found in store for current file hash '{current_file_hash}'.")
                    print_info("The file may not have been stamped, or its content has changed significantly from any known stamp.")
                    return
            except Exception as e_hash:
                print_error(f"Error calculating file hash for fallback check: {e_hash}")
                return

    if not actual_stamp_file_to_verify_with:
        print_error("Could not identify or prepare a valid stamp to verify against. Verification aborted.")
        # Clean up just in case, though unlikely to be created if this path is hit
        if temp_stamp_file_path and os.path.exists(temp_stamp_file_path):
            try:
                os.remove(temp_stamp_file_path)
            except OSError as e_del:
                print_warning(f"Could not remove temporary stamp file '{temp_stamp_file_path}': {e_del}")
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
            if not verification_result["checks"]["protocol_version_match"]:
                print_warning("Protocol version mismatch detected in the stamp.")
            if not verification_result["checks"]["file_integrity_match"]:
                print_warning("File integrity check FAILED: Content has changed since stamping.")
            if not verification_result["checks"]["signature_valid"]:
                print_warning("Signature verification FAILED: The signature in the stamp is not valid for the claimed original data.")
    except Exception as e:
        print_error(f"An unexpected error occurred during verification: {e}")
    finally:
        if temp_stamp_file_path and os.path.exists(temp_stamp_file_path):
            try:
                os.remove(temp_stamp_file_path)
            except OSError as e_del:
                print_warning(f"Could not remove temporary stamp file '{temp_stamp_file_path}': {e_del}")

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

    parser_stamp = subparsers.add_parser("stamp", help="Create a Tsnu'e Stamp for a file and add it to the store.")
    parser_stamp.add_argument("filepath", help="Path to the file to stamp.")
    parser_stamp.add_argument("-p", "--password", help="Password for the private key (if encrypted). If not provided, will be prompted.", default=None)
    parser_stamp.set_defaults(func=handle_stamp_file)

    parser_verify = subparsers.add_parser("verify", help="Verify a file against a Tsnu'e Stamp from store or file.")
    parser_verify.add_argument("filepath", help="Path to the file to verify.")
    parser_verify.add_argument("stamp_identifier",
        help="Identifier for the stamp. Can be:\n"
             "  - The file_hash of the stamp in the local store.\n"
             "  - Path to a specific .tsnue-stamp.json file.\n"
             "If a hash is given and not found, the tool will try to\n"
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
        # This case should ideally not be reached if subparsers are required
        # and a default func is set for each, or if len(sys.argv)==1 is handled.
        # However, as a fallback:
        print_error("No command specified or command not recognized.")
        parser.print_help(sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()