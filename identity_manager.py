from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes # For get_tsnue_id

# For password input
import getpass # Standard library for securely getting passwords
import os

# Define constants for key storage
PRIVATE_KEY_FILE = "tsnue_private_key.pem"
PUBLIC_KEY_FILE = "tsnue_public_key.pem"

def generate_key_pair():
    """
    Generates an RSA private/public key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename=PRIVATE_KEY_FILE, password=None): # Added password arg
    """
    Saves a private key to a PEM file.
    Encrypts with the provided password if given.
    """
    if password:
        # Ensure password is bytes
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            password_bytes = password # Assume it's already bytes

        encryption_algorithm = serialization.BestAvailableEncryption(password_bytes)
        print(f"Encrypting private key with password for '{filename}'.")
    else:
        encryption_algorithm = serialization.NoEncryption()
        print(f"Saving private key without password encryption for '{filename}'.")


    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    with open(filename, 'wb') as f:
        f.write(pem)
    # Do not print "Private key saved" here, let the caller do it or handle context.

def save_public_key(public_key, filename=PUBLIC_KEY_FILE):
    """
    Saves a public key to a PEM file.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(pem)
    # Do not print "Public key saved" here.

def load_private_key(filename=PRIVATE_KEY_FILE, password=None): # Added password arg
    """
    Loads a private key from a PEM file.
    Decrypts with the provided password if the key is encrypted.
    """
    if password:
        # Ensure password is bytes
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            password_bytes = password # Assume it's already bytes
    else:
        password_bytes = None # Explicitly None if no password provided

    with open(filename, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password_bytes, # Pass None if key is not encrypted or no password given
            backend=default_backend()
        )
    return private_key

def load_public_key(filename=PUBLIC_KEY_FILE):
    """
    Loads a public key from a PEM file.
    """
    with open(filename, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

def get_tsnue_id(public_key):
    """
    Generates a string representation for the Tsnu'e ID from a public key.
    SHA256 hash of the public key's PEM representation, hex encoded.
    """
    # cryptography.hazmat.primitives.hashes is already imported at the top

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(pem)
    return digest.finalize().hex()

# --- Main execution for testing ---
if __name__ == "__main__":
    print("Tsnu'e-Mahtem Identity Manager (with Password Protection)")
    print("-------------------------------------------------------")

    # --- Option to delete existing keys for a clean test ---
    # For testing, you might want to delete old keys.
    # Be careful with this in a real scenario!
    if os.path.exists(PRIVATE_KEY_FILE) or os.path.exists(PUBLIC_KEY_FILE):
        choice = input(f"Key files ('{PRIVATE_KEY_FILE}', '{PUBLIC_KEY_FILE}') may exist. "
                       "Do you want to delete them and generate new ones? (yes/no): ").lower()
        if choice == 'yes':
            if os.path.exists(PRIVATE_KEY_FILE):
                os.remove(PRIVATE_KEY_FILE)
                print(f"Deleted {PRIVATE_KEY_FILE}")
            if os.path.exists(PUBLIC_KEY_FILE):
                os.remove(PUBLIC_KEY_FILE)
                print(f"Deleted {PUBLIC_KEY_FILE}")
        else:
            print("Keeping existing key files (if any). Attempting to load.")


    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        print("\nGenerating new key pair...")
        password_1 = getpass.getpass("Enter a password to encrypt the private key (leave blank for no password): ")
        if password_1: # If a password was entered
            password_2 = getpass.getpass("Confirm password: ")
            if password_1 != password_2:
                print("Passwords do not match. Aborting.")
                exit()
            # Use the confirmed password (password_1)
        else: # No password entered, password_1 will be empty string
            print("No password entered. Private key will NOT be encrypted.")
            password_1 = None # Ensure it's None if empty for save_private_key logic

        priv_key, pub_key = generate_key_pair()
        try:
            save_private_key(priv_key, password=password_1) # Pass the password here
            print(f"Private key saved to {PRIVATE_KEY_FILE}")
            save_public_key(pub_key)
            print(f"Public key saved to {PUBLIC_KEY_FILE}")
            print("New key pair generated and saved.")
        except Exception as e:
            print(f"Error saving keys: {e}")
            exit()
    else:
        print("\nKey files found. Attempting to load existing keys...")

    # Test loading the keys
    # If private key was saved with password, it must be provided to load
    load_password = None
    print("\nTo load the private key, a password might be required.")
    # A simple heuristic: if the file seems like it could be encrypted (PKCS8 usually indicates this possibility)
    # For a more robust check, one might try loading without password first, and if it fails with a type error
    # related to decryption, then prompt. For now, we'll just ask.
    requires_password_prompt = input("Was the private key saved with a password? (yes/no): ").lower()
    if requires_password_prompt == 'yes':
        load_password = getpass.getpass("Enter password for private key: ")
    else:
        print("Attempting to load private key without a password.")


    try:
        priv_key_loaded = load_private_key(password=load_password)
        pub_key_loaded = load_public_key() # Public key is never encrypted
        print("Keys loaded successfully.")

        tsnue_id = get_tsnue_id(pub_key_loaded)
        print(f"\nYour Tsnu'e ID: {tsnue_id}")

        # Internal consistency check
        if pub_key_loaded.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == \
           priv_key_loaded.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo):
            print("Public key successfully derived from loaded private key (consistency check).")
        else:
            print("ERROR: Public key derivation check failed!")

    except FileNotFoundError:
        print("Error: Key files not found. Please generate them first.")
    except ValueError as e: # Often indicates wrong password or key format issue
        if "decryption failed" in str(e).lower() or "bad decrypt" in str(e).lower():
             print("Error loading private key: Decryption failed. Incorrect password or corrupted key.")
        else:
             print(f"Error loading keys (ValueError): {e}")
    except TypeError as e: # Can also indicate password issue with cryptography lib
        if "password was given but private key is not encrypted" in str(e).lower() or \
           "private key is encrypted but no password was Sgiven" in str(e).lower(): # Typo 'Sgiven' is in some lib versions
             print(f"Error loading private key: Password mismatch or key encryption status issue. {e}")
        else:
            print(f"Error loading keys (TypeError): {e}")
    except Exception as e:
        print(f"An unexpected error occurred loading keys: {e}")
        import traceback
        traceback.print_exc()