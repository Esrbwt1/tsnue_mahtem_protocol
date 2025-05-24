import json
import os
import time

# The filename for our simple JSON-based stamp store
STAMP_STORE_FILE = "tsnue_stamp_store.json"

def _load_store_data(store_filepath=STAMP_STORE_FILE):
    """
    Helper function to load data from the JSON store file.
    Returns an empty dictionary if the file doesn't exist or is invalid.
    """
    if not os.path.exists(store_filepath):
        return {}
    try:
        with open(store_filepath, 'r') as f:
            data = json.load(f)
            # Basic validation: expect a dictionary
            if not isinstance(data, dict):
                print(f"Warning: Stamp store file '{store_filepath}' does not contain a valid JSON object (dictionary). Starting fresh.")
                return {}
            return data
    except json.JSONDecodeError:
        print(f"Warning: Could not decode JSON from stamp store file '{store_filepath}'. Starting fresh if saving.")
        return {} # In case of corruption, treat as empty
    except Exception as e:
        print(f"Error loading stamp store '{store_filepath}': {e}. Starting fresh.")
        return {}

def _save_store_data(data, store_filepath=STAMP_STORE_FILE):
    """
    Helper function to save data to the JSON store file.
    """
    try:
        with open(store_filepath, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving stamp store to '{store_filepath}': {e}")
        # Potentially raise the error or handle more gracefully depending on requirements

def add_stamp(tsnue_stamp_data, store_filepath=STAMP_STORE_FILE):
    """
    Adds a Tsnu'e Stamp to the store.
    The key in the store will be the 'file_hash' from the stamp.
    If a stamp for that file_hash already exists, it will be overwritten (or we could add versioning later).
    """
    if not tsnue_stamp_data or "file_hash" not in tsnue_stamp_data:
        print("Error: Invalid stamp data or missing 'file_hash'. Cannot add to store.")
        return False

    file_hash = tsnue_stamp_data["file_hash"]
    store_data = _load_store_data(store_filepath)

    # Add some metadata to the stored stamp
    tsnue_stamp_data["_store_metadata"] = {
        "added_to_store_utc": time.time(),
        "last_accessed_utc": time.time()
    }

    store_data[file_hash] = tsnue_stamp_data
    _save_store_data(store_data, store_filepath)
    print(f"Stamp for file hash '{file_hash}' added/updated in store '{store_filepath}'.")
    return True

def get_stamp_by_file_hash(file_hash, store_filepath=STAMP_STORE_FILE):
    """
    Retrieves a Tsnu'e Stamp from the store using the file's hash.
    Returns the stamp data if found, None otherwise.
    Updates last_accessed_utc metadata.
    """
    store_data = _load_store_data(store_filepath)
    stamp = store_data.get(file_hash)

    if stamp and "_store_metadata" in stamp:
        stamp["_store_metadata"]["last_accessed_utc"] = time.time()
        # No need to save just for an access time update for this simple store,
        # but a real DB would handle this.
        # If we wanted to persist this for JSON store:
        # _save_store_data(store_data, store_filepath)
    elif stamp and "_store_metadata" not in stamp: # For older stamps before this metadata
         stamp["_store_metadata"] = { "last_accessed_utc": time.time() }


    return stamp

def get_stamps_by_filename(original_filename, store_filepath=STAMP_STORE_FILE):
    """
    Retrieves all Tsnu'e Stamps from the store that match the original filename.
    Since multiple files could have the same name, or a file could be stamped multiple times
    (if content changes, hash changes, new stamp), this returns a list of stamps.
    """
    store_data = _load_store_data(store_filepath)
    matching_stamps = []
    for file_hash, stamp_data in store_data.items():
        if stamp_data.get("original_filename") == original_filename:
            if "_store_metadata" in stamp_data: # Update access time
                stamp_data["_store_metadata"]["last_accessed_utc"] = time.time()
            matching_stamps.append(stamp_data)
    # If we wanted to persist access time updates for JSON store:
    # if matching_stamps: _save_store_data(store_data, store_filepath)
    return matching_stamps

def list_all_stamps(store_filepath=STAMP_STORE_FILE, limit=None):
    """
    Lists all stamps in the store.
    Returns a list of (file_hash, stamp_preview_dict).
    `limit` can be used to get the N most recently added stamps. (Simple implementation for now)
    """
    store_data = _load_store_data(store_filepath)
    
    # For simplicity with current structure, sorting by added time requires iterating.
    # A real DB would do this efficiently.
    # We'll sort by added_to_store_utc if available, otherwise no specific order.
    
    stamps_with_add_time = []
    for file_hash, stamp_data in store_data.items():
        added_time = stamp_data.get("_store_metadata", {}).get("added_to_store_utc", 0)
        stamps_with_add_time.append((added_time, file_hash, stamp_data))

    # Sort by added_time descending (most recent first)
    stamps_with_add_time.sort(key=lambda x: x[0], reverse=True)
    
    results = []
    count = 0
    for added_time, file_hash, stamp_data in stamps_with_add_time:
        if limit is not None and count >= limit:
            break
        # Create a preview (e.g., filename, timestamp, tsnue_id)
        preview = {
            "file_hash": file_hash,
            "original_filename": stamp_data.get("original_filename"),
            "tsnue_id": stamp_data.get("tsnue_id"),
            "timestamp_utc": stamp_data.get("timestamp_utc"),
            "added_to_store_utc": added_time
        }
        results.append(preview)
        count += 1
        
    return results


# --- Main execution for testing ---
if __name__ == "__main__":
    print("Tsnu'e-Mahtem Stamp Store Manager")
    print("---------------------------------")

    # Clean up old store file for fresh test run if it exists
    if os.path.exists(STAMP_STORE_FILE):
        os.remove(STAMP_STORE_FILE)
        print(f"Removed existing store file '{STAMP_STORE_FILE}' for fresh test.")

    # Mock stamp data (normally this would come from stamper.py)
    mock_stamp1 = {
        "protocol_version": "Tsnu'eMahtem-1.0",
        "tsnue_id": "id_user123",
        "timestamp_utc": time.time() - 3600, # an hour ago
        "original_filename": "report.docx",
        "file_hash_algorithm": "sha256",
        "file_hash": "hash_of_report_v1", # Placeholder hash
        "signature_algorithm": "RSASSA-PKCS1-v1_5-SHA256",
        "signature": "sig_for_report_v1",
        "public_key_pem": "pem_for_user123"
    }
    mock_stamp2 = {
        "protocol_version": "Tsnu'eMahtem-1.0",
        "tsnue_id": "id_user456",
        "timestamp_utc": time.time() - 1800, # 30 mins ago
        "original_filename": "image.jpg",
        "file_hash_algorithm": "sha256",
        "file_hash": "hash_of_image_xyz", # Placeholder hash
        "signature_algorithm": "RSASSA-PKCS1-v1_5-SHA256",
        "signature": "sig_for_image_xyz",
        "public_key_pem": "pem_for_user456"
    }
    mock_stamp3 = { # Same filename as mock_stamp1, but different hash (simulating a new version)
        "protocol_version": "Tsnu'eMahtem-1.0",
        "tsnue_id": "id_user123",
        "timestamp_utc": time.time(), # now
        "original_filename": "report.docx",
        "file_hash_algorithm": "sha256",
        "file_hash": "hash_of_report_v2", # Placeholder hash for new version
        "signature_algorithm": "RSASSA-PKCS1-v1_5-SHA256",
        "signature": "sig_for_report_v2",
        "public_key_pem": "pem_for_user123"
    }

    print("\n--- Test: Adding stamps ---")
    add_stamp(mock_stamp1)
    time.sleep(0.1) # Ensure slightly different store timestamps for sorting test
    add_stamp(mock_stamp2)
    time.sleep(0.1)
    add_stamp(mock_stamp3)

    print("\n--- Test: Get stamp by file hash (hash_of_report_v2) ---")
    retrieved_stamp = get_stamp_by_file_hash("hash_of_report_v2")
    if retrieved_stamp:
        print("Found:")
        print(json.dumps(retrieved_stamp, indent=2))
    else:
        print("Not found.")

    print("\n--- Test: Get stamp by file hash (non_existent_hash) ---")
    retrieved_stamp_non_existent = get_stamp_by_file_hash("non_existent_hash")
    if retrieved_stamp_non_existent:
        print("Found (Error - should not happen):")
        print(json.dumps(retrieved_stamp_non_existent, indent=2))
    else:
        print("Not found (Correct).")


    print("\n--- Test: Get stamps by filename ('report.docx') ---")
    report_stamps = get_stamps_by_filename("report.docx")
    if report_stamps:
        print(f"Found {len(report_stamps)} stamp(s) for 'report.docx':")
        for s in report_stamps:
            print(json.dumps(s, indent=2))
    else:
        print("No stamps found for 'report.docx'.")

    print("\n--- Test: List all stamps (most recent first) ---")
    all_stamps = list_all_stamps()
    if all_stamps:
        print(f"Found {len(all_stamps)} stamp(s) in store:")
        for s_preview in all_stamps:
            print(json.dumps(s_preview, indent=2))
    else:
        print("Store is empty.")
        
    print("\n--- Test: List all stamps (limit 1, most recent) ---")
    limited_stamps = list_all_stamps(limit=1)
    if limited_stamps:
        print(f"Found {len(limited_stamps)} stamp(s) in store (limit 1):")
        for s_preview in limited_stamps:
            print(json.dumps(s_preview, indent=2))
    else:
        print("Store is empty.")

    # The tsnue_stamp_store.json file will be created/updated in your project directory.
    # You can inspect it.