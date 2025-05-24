import argparse
import os
import json
import sys
import getpass # For password input

# Direct import from cryptography library for components used in CLI
from cryptography.hazmat.primitives import serialization

# Import functions from our modules
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
    print(f"Error importing modules: {e}")
    print("Ensure main_cli.py is in the project root and all module files are present.")
    print("If running from a subdirectory, Python's import resolution might be an issue.")
    sys.exit(1)


def handle_generate_id(args):
    """Handles the 'generate-id' command."""
    if not args.force and (os.path.exists(PRIVATE_KEY_FILE) or os.path.exists(PUBLIC_KEY_FILE)):
        print(f"Key files ('{PRIVATE_KEY_FILE}', '{PUBLIC_KEY_FILE}') already exist.")
        print("Use --force to overwrite existing keys.")
        try:
            if os.path.exists(PUBLIC_KEY_FILE):
                public_key = load_public_key()
                tsnue_id = get_tsnue_id(public_key)
                print(f"Existing Tsnu'e ID: {tsnue_id}")
            else:
                print(f"Public key file '{PUBLIC_KEY_FILE}' not found to display existing ID.")
        except Exception as e:
            print(f"Error loading existing public key: {e}")
        return

    print("Generating new Tsnu'e ID (key pair)...")
    key_password = None
    if not args.no_password:
        while True: # Loop for password confirmation
            key_password_temp = getpass.getpass("Enter password to encrypt new private key (leave blank or use --no-password for none): ")
            if not key_password_temp: # User pressed Enter for blank password
                print("No password entered. Private key will NOT be encrypted.")
                key_password = None
                break
            key_password_confirm = getpass.getpass("Confirm password: ")
            if key_password_temp == key_password_confirm:
                key_password = key_password_temp
                break
            else:
                print("Passwords do not match. Please try again.")
    else:
        print("Option --no-password selected. Private key will NOT be encrypted.")
        key_password = None

    private_key_obj, public_key_obj = generate_key_pair()
    try:
        save_private_key(private_key_obj, PRIVATE_KEY_FILE, password=key_password)
        print(f"Private key saved to: {PRIVATE_KEY_FILE}")
        save_public_key(public_key_obj, PUBLIC_KEY_FILE)
        print(f"Public key saved to: {PUBLIC_KEY_FILE}")
        tsnue_id = get_tsnue_id(public_key_obj)
        print(f"New Tsnu'e ID generated: {tsnue_id}")
        if key_password:
            print("Private key is ENCRYPTED.")
        else:
            print("Private key is NOT encrypted.")
    except Exception as e:
        print(f"Error saving keys: {e}")

def handle_stamp_file(args):
    """Handles the 'stamp' command."""
    filepath = args.filepath
    if not os.path.exists(filepath):
        print(f"Error: File not found at '{filepath}'")
        return
    if not os.path.isfile(filepath):
        print(f"Error: '{filepath}' is not a file.")
        return

    private_key_password_to_use = args.password # Password from CLI argument, if provided

    # If no password was provided via CLI, and the private key file exists,
    # we should prompt. This implies the key *might* be encrypted.
    if not private_key_password_to_use and os.path.exists(PRIVATE_KEY_FILE):
        # A simple way to check if we should even bother asking for a password
        # is to try loading it without one. If it fails with a password-like error, then prompt.
        # For now, a simpler prompt:
        print(f"Private key '{PRIVATE_KEY_FILE}' exists. It might be password protected.")
        prompt_for_pw = input("Do you want to provide a password to unlock it? (yes/no, default no): ").lower()
        if prompt_for_pw == 'yes':
            private_key_password_to_use = getpass.getpass(f"Enter password for private key '{PRIVATE_KEY_FILE}': ")
        elif not private_key_password_to_use: # If still no password (e.g. user said 'no' or entered blank)
             private_key_password_to_use = None


    try:
        print(f"Stamping file: {filepath}...")
        tsnue_stamp_data = create_tsnue_stamp(
            filepath,
            private_key_path=PRIVATE_KEY_FILE, # Assuming default key file for now
            private_key_password=private_key_password_to_use
        )

        if add_stamp(tsnue_stamp_data):
            print("Tsnu'e Stamp created and added to store successfully:")
            print(json.dumps(tsnue_stamp_data, indent=2))
        else:
            print("Tsnu'e Stamp created, but FAILED to add to store.")
            print(json.dumps(tsnue_stamp_data, indent=2))

    except FileNotFoundError as e:
        print(f"Error: {e}. This could be the file to stamp or the private key file if not found.")
        print(f"Ensure your Tsnu'e ID (key pair using '{PRIVATE_KEY_FILE}') has been generated.")
    except (ValueError, TypeError) as e:
        if "decryption failed" in str(e).lower() or \
           "bad decrypt" in str(e).lower() or \
           "password was given but private key is not encrypted" in str(e).lower() or \
           "private key is encrypted but no password was sgiven" in str(e).lower().replace("given","sgiven"): # Handle typo in some lib versions
            print(f"Error loading private key for stamping: Incorrect password or key encryption status issue. ({e})")
        else:
            print(f"An error occurred during stamping (ValueError/TypeError): {e}")
    except Exception as e:
        print(f"An unexpected error occurred during stamping: {e}")
        import traceback
        traceback.print_exc()

def handle_verify_file(args):
    """Handles the 'verify' command."""
    filepath_to_verify = args.filepath
    stamp_identifier = args.stamp_identifier

    if not os.path.exists(filepath_to_verify):
        print(f"Error: File to verify not found at '{filepath_to_verify}'")
        return

    retrieved_stamp_data = None
    stamp_source_info = ""
    actual_stamp_file_to_verify_with = None

    if os.path.exists(stamp_identifier) and (stamp_identifier.endswith(".tsnue-stamp.json") or stamp_identifier.endswith(".json")):
        print(f"Attempting to verify using direct stamp file: {stamp_identifier}")
        actual_stamp_file_to_verify_with = stamp_identifier
        stamp_source_info = f"direct stamp file '{stamp_identifier}'"
    else:
        print(f"Attempting to find stamp in store using identifier (assumed file_hash): {stamp_identifier}")
        retrieved_stamp_data = get_stamp_by_file_hash(stamp_identifier)
        if retrieved_stamp_data:
            temp_stamp_file = f"_temp_stamp_for_verify_{stamp_identifier.replace('/', '_').replace(':', '_')}.json"
            with open(temp_stamp_file, 'w') as tsf:
                json.dump(retrieved_stamp_data, tsf)
            actual_stamp_file_to_verify_with = temp_stamp_file
            stamp_source_info = f"stamp store (hash: {args.stamp_identifier})"
        else:
            print(f"No stamp found in store by identifier/hash '{stamp_identifier}'.")
            # Optionally, try to find by current file's hash as a last resort
            print(f"Calculating hash of '{filepath_to_verify}' to check store as a fallback...")
            try:
                current_file_hash = calculate_file_hash(filepath_to_verify)
                print(f"Current file hash: {current_file_hash}")
                retrieved_stamp_data_by_current_hash = get_stamp_by_file_hash(current_file_hash)
                if retrieved_stamp_data_by_current_hash:
                    print(f"Found matching stamp in store by current file hash: {current_file_hash}")
                    temp_stamp_file = f"_temp_stamp_for_verify_{current_file_hash.replace('/', '_').replace(':', '_')}.json"
                    with open(temp_stamp_file, 'w') as tsf:
                        json.dump(retrieved_stamp_data_by_current_hash, tsf)
                    actual_stamp_file_to_verify_with = temp_stamp_file
                    stamp_source_info = f"stamp store (found by current file hash: {current_file_hash})"
                else:
                    print(f"No stamp found in store by current file hash '{current_file_hash}' either.")
                    return
            except Exception as e_hash:
                print(f"Error calculating hash for fallback check: {e_hash}")
                return

    if not actual_stamp_file_to_verify_with:
        print("Could not identify a valid stamp to verify against.")
        return

    try:
        print(f"Verifying '{filepath_to_verify}' using {stamp_source_info}...")
        verification_result = verify_tsnue_stamp(filepath_to_verify, actual_stamp_file_to_verify_with)
        print("\nVerification Result:")
        print(json.dumps(verification_result, indent=2))
        if verification_result["verified"]:
            print("\nCONCLUSION: File is Authentic and Integrity is Intact.")
        else:
            print("\nCONCLUSION: File FAILED verification.")
    except Exception as e:
        print(f"An error occurred during verification: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if 'temp_stamp_file' in locals() and os.path.exists(temp_stamp_file):
            os.remove(temp_stamp_file)

def handle_show_id(args):
    """Handles the 'show-id' command."""
    try:
        if not os.path.exists(PUBLIC_KEY_FILE):
            print(f"Error: Public key file '{PUBLIC_KEY_FILE}' not found. Has an ID been generated yet?")
            return

        public_key = load_public_key()
        tsnue_id = get_tsnue_id(public_key)
        print(f"Current Tsnu'e ID: {tsnue_id}")
        if args.show_key:
            print("\nPublic Key (PEM):")
            print(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'))
    except FileNotFoundError: # Should be caught by os.path.exists above, but good to have
        print(f"Error: Public key file '{PUBLIC_KEY_FILE}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def handle_list_stamps(args):
    """Handles the 'list-stamps' command."""
    limit = args.limit
    filename_filter = args.filename

    print(f"Listing stamps from store: '{STAMP_STORE_FILE}'")
    stamps_to_show = []
    if filename_filter:
        print(f"Filtering by filename: '{filename_filter}'")
        stamps_data_full = get_stamps_by_filename(filename_filter)
        # Convert full stamp data to previews
        results = []
        for s_data in stamps_data_full:
            results.append({
                "file_hash": s_data.get("file_hash"),
                "original_filename": s_data.get("original_filename"),
                "tsnue_id": s_data.get("tsnue_id"),
                "timestamp_utc": s_data.get("timestamp_utc"),
                "added_to_store_utc": s_data.get("_store_metadata", {}).get("added_to_store_utc")
            })
        # Sort these by added_to_store_utc descending
        results.sort(key=lambda x: x.get("added_to_store_utc", 0) if x.get("added_to_store_utc") is not None else 0, reverse=True)
        if limit is not None:
            stamps_to_show = results[:limit]
        else:
            stamps_to_show = results
    else:
        stamps_to_show = list_all_stamps(limit=limit) # Already returns previews and sorted

    if not stamps_to_show:
        print("No stamps found matching criteria.")
        return

    print(f"\nFound {len(stamps_to_show)} stamp(s):")
    for i, stamp_preview in enumerate(stamps_to_show):
        print(f"\n--- Stamp {i+1} ---")
        print(json.dumps(stamp_preview, indent=2))

def main():
    parser = argparse.ArgumentParser(
        description="Tsnu'e-Mahtem: Content Authenticity & Provenance CLI",
        formatter_class=argparse.RawTextHelpFormatter # For better help text formatting
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands", required=True)

    # --- generate-id command ---
    parser_generate_id = subparsers.add_parser("generate-id", help="Generate a new Tsnu'e ID (key pair).")
    parser_generate_id.add_argument("--force", action="store_true", help="Force overwrite if keys already exist.")
    parser_generate_id.add_argument("--no-password", action="store_true", help="Generate private key without password encryption.")
    parser_generate_id.set_defaults(func=handle_generate_id)

    # --- show-id command ---
    parser_show_id = subparsers.add_parser("show-id", help="Display the current Tsnu'e ID and optionally the public key.")
    parser_show_id.add_argument("--show-key", action="store_true", help="Also display the public key PEM.")
    parser_show_id.set_defaults(func=handle_show_id)

    # --- stamp command ---
    parser_stamp = subparsers.add_parser("stamp", help="Create a Tsnu'e Stamp for a file and add it to the store.")
    parser_stamp.add_argument("filepath", help="Path to the file to stamp.")
    parser_stamp.add_argument("-p", "--password", help="Password for the private key (if encrypted). If not provided, will be prompted.", default=None)
    # TODO: Add argument for --private-key path if not using default PRIVATE_KEY_FILE
    parser_stamp.set_defaults(func=handle_stamp_file)

    # --- verify command ---
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

    # --- list-stamps command ---
    parser_list = subparsers.add_parser("list-stamps", help="List stamps from the local store.")
    parser_list.add_argument("-n", "--limit", type=int, help="Limit the number of stamps displayed (most recent).")
    parser_list.add_argument("-f", "--filename", type=str, help="Filter stamps by original filename.")
    parser_list.set_defaults(func=handle_list_stamps)

    if len(sys.argv) == 1: # If no command is given, print help
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()