import argparse
import os
import json
import sys # For sys.exit()

# Import functions from our modules
# This structure assumes main_cli.py is in the project root alongside the other .py files
try:
    from cryptography.hazmat.primitives import serialization
    
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
        # Optionally, load and display existing ID
        try:
            public_key = load_public_key()
            tsnue_id = get_tsnue_id(public_key)
            print(f"Existing Tsnu'e ID: {tsnue_id}")
        except FileNotFoundError:
            print("Could not load existing public key to display ID.")
        except Exception as e:
            print(f"Error loading existing public key: {e}")
        return

    print("Generating new Tsnu'e ID (key pair)...")
    private_key, public_key = generate_key_pair()
    # TODO: Add password protection option args.password
    save_private_key(private_key, PRIVATE_KEY_FILE)
    save_public_key(public_key, PUBLIC_KEY_FILE)
    tsnue_id = get_tsnue_id(public_key)
    print(f"New Tsnu'e ID generated: {tsnue_id}")
    print(f"Private key saved to: {PRIVATE_KEY_FILE}")
    print(f"Public key saved to: {PUBLIC_KEY_FILE}")

def handle_stamp_file(args):
    """Handles the 'stamp' command."""
    filepath = args.filepath
    if not os.path.exists(filepath):
        print(f"Error: File not found at '{filepath}'")
        return
    if not os.path.isfile(filepath):
        print(f"Error: '{filepath}' is not a file.")
        return

    try:
        print(f"Stamping file: {filepath}...")
        # TODO: Allow specifying private key and password from args
        tsnue_stamp_data = create_tsnue_stamp(filepath) # Uses default private key path

        # Add to stamp store
        if add_stamp(tsnue_stamp_data):
            print("Tsnu'e Stamp created and added to store successfully:")
            print(json.dumps(tsnue_stamp_data, indent=2))
        else:
            print("Tsnu'e Stamp created, but FAILED to add to store.")
            print(json.dumps(tsnue_stamp_data, indent=2)) # Still show it

    except FileNotFoundError as e: # e.g. private key not found
        print(f"Error: {e}. Ensure your Tsnu'e ID (key pair) has been generated.")
    except Exception as e:
        print(f"An error occurred during stamping: {e}")
        import traceback
        traceback.print_exc()

def handle_verify_file(args):
    """Handles the 'verify' command."""
    filepath_to_verify = args.filepath
    stamp_identifier = args.stamp_identifier # Could be a file_hash or path to a .tsnue-stamp.json file

    if not os.path.exists(filepath_to_verify):
        print(f"Error: File to verify not found at '{filepath_to_verify}'")
        return

    retrieved_stamp_data = None
    stamp_source_info = ""

    # Try to see if stamp_identifier is a direct path to a stamp file
    if os.path.exists(stamp_identifier) and stamp_identifier.endswith(".tsnue-stamp.json"):
        print(f"Attempting to verify using direct stamp file: {stamp_identifier}")
        # We'll use verify_tsnue_stamp directly which loads from file
        # For consistency, we'll pass the stamp file path to it.
        # This part of verify_tsnue_stamp needs to be robust.
        stamp_source_info = f"direct stamp file '{stamp_identifier}'"
        # The existing verify_tsnue_stamp takes the stamp_filepath as second arg
    else:
        # Assume stamp_identifier is a file_hash to look up in the store
        print(f"Attempting to find stamp in store using identifier (assumed file_hash): {stamp_identifier}")
        retrieved_stamp_data = get_stamp_by_file_hash(stamp_identifier)
        if retrieved_stamp_data:
            # Save this retrieved stamp to a temporary file for verify_tsnue_stamp
            # This is a bit clunky due to verify_tsnue_stamp expecting a filepath
            # TODO: Refactor verify_tsnue_stamp to also accept stamp data directly
            temp_stamp_file = f"_temp_stamp_for_verify_{stamp_identifier}.json"
            with open(temp_stamp_file, 'w') as tsf:
                json.dump(retrieved_stamp_data, tsf)
            stamp_identifier = temp_stamp_file # Point to the temp file
            stamp_source_info = f"stamp store (hash: {args.stamp_identifier})"
        else:
            # If not found by hash, try to find stamps by original filename
            # and use the latest one if multiple found (or let user choose - too complex for now)
            print(f"Stamp not found by hash '{stamp_identifier}'. Trying to find by filename '{os.path.basename(filepath_to_verify)}' in store...")
            # First, calculate the current file's hash to see if we have an exact match in store
            current_file_hash = calculate_file_hash(filepath_to_verify)
            retrieved_stamp_data = get_stamp_by_file_hash(current_file_hash)
            if retrieved_stamp_data:
                print(f"Found matching stamp in store by current file hash: {current_file_hash}")
                temp_stamp_file = f"_temp_stamp_for_verify_{current_file_hash}.json"
                with open(temp_stamp_file, 'w') as tsf:
                    json.dump(retrieved_stamp_data, tsf)
                stamp_identifier = temp_stamp_file
                stamp_source_info = f"stamp store (hash: {current_file_hash})"
            else:
                print(f"No stamp found in store by current file hash '{current_file_hash}'.")
                print(f"This file may not have been stamped, or was stamped with different content.")
                # Could also try get_stamps_by_filename and pick the latest, but this gets complex.
                # For now, we require a hash or direct stamp file.
                return


    try:
        print(f"Verifying '{filepath_to_verify}' using {stamp_source_info}...")
        verification_result = verify_tsnue_stamp(filepath_to_verify, stamp_identifier)
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
        # Clean up temporary stamp file if created
        if 'temp_stamp_file' in locals() and os.path.exists(temp_stamp_file):
            os.remove(temp_stamp_file)

def handle_show_id(args):
    """Handles the 'show-id' command."""
    try:
        public_key = load_public_key() # Uses default PUBLIC_KEY_FILE
        tsnue_id = get_tsnue_id(public_key)
        print(f"Current Tsnu'e ID: {tsnue_id}")
        if args.show_key:
            print("\nPublic Key (PEM):")
            print(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'))
    except FileNotFoundError:
        print("Error: Public key file not found. Has an ID been generated yet?")
        print(f"Expected at: {PUBLIC_KEY_FILE}")
    except Exception as e:
        print(f"An error occurred: {e}")

def handle_list_stamps(args):
    """Handles the 'list-stamps' command."""
    limit = args.limit
    filename_filter = args.filename

    print(f"Listing stamps from store: '{STAMP_STORE_FILE}'")
    if filename_filter:
        print(f"Filtering by filename: '{filename_filter}'")
        stamps = get_stamps_by_filename(filename_filter)
        # get_stamps_by_filename returns full stamps, let's make previews
        results = []
        for s_data in stamps:
            results.append({
                "file_hash": s_data.get("file_hash"),
                "original_filename": s_data.get("original_filename"),
                "tsnue_id": s_data.get("tsnue_id"),
                "timestamp_utc": s_data.get("timestamp_utc"),
                "added_to_store_utc": s_data.get("_store_metadata", {}).get("added_to_store_utc")
            })
        # Sort these by added_to_store_utc descending
        results.sort(key=lambda x: x.get("added_to_store_utc", 0), reverse=True)
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
    parser = argparse.ArgumentParser(description="Tsnu'e-Mahtem: Content Authenticity & Provenance CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands", required=True)

    # --- generate-id command ---
    parser_generate_id = subparsers.add_parser("generate-id", help="Generate a new Tsnu'e ID (key pair).")
    parser_generate_id.add_argument("--force", action="store_true", help="Force overwrite if keys already exist.")
    # TODO: parser_generate_id.add_argument("--password", help="Password to encrypt the private key.")
    parser_generate_id.set_defaults(func=handle_generate_id)

    # --- show-id command ---
    parser_show_id = subparsers.add_parser("show-id", help="Display the current Tsnu'e ID and optionally the public key.")
    parser_show_id.add_argument("--show-key", action="store_true", help="Also display the public key PEM.")
    parser_show_id.set_defaults(func=handle_show_id)

    # --- stamp command ---
    parser_stamp = subparsers.add_parser("stamp", help="Create a Tsnu'e Stamp for a file and add it to the store.")
    parser_stamp.add_argument("filepath", help="Path to the file to stamp.")
    # TODO: Add arguments for --private-key and --password if not using default
    parser_stamp.set_defaults(func=handle_stamp_file)

    # --- verify command ---
    parser_verify = subparsers.add_parser("verify", help="Verify a file against a Tsnu'e Stamp from store or file.")
    parser_verify.add_argument("filepath", help="Path to the file to verify.")
    parser_verify.add_argument("stamp_identifier", help="File hash of the stamp in the store, OR path to a .tsnue-stamp.json file.")
    parser_verify.set_defaults(func=handle_verify_file)

    # --- list-stamps command ---
    parser_list = subparsers.add_parser("list-stamps", help="List stamps from the local store.")
    parser_list.add_argument("-n", "--limit", type=int, help="Limit the number of stamps displayed (most recent).")
    parser_list.add_argument("-f", "--filename", type=str, help="Filter stamps by original filename.")
    parser_list.set_defaults(func=handle_list_stamps)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()