from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Define constants for key storage (we'll improve this later)
PRIVATE_KEY_FILE = "tsnue_private_key.pem"
PUBLIC_KEY_FILE = "tsnue_public_key.pem"

def generate_key_pair():
    """
    Generates an RSA private/public key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048, # RSA 2048 is a common, secure choice
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename=PRIVATE_KEY_FILE, password=None):
    """
    Saves a private key to a PEM file.
    Optionally encrypts with a password.
    """
    # For now, we will save without password encryption for simplicity.
    # Password encryption will be added as an enhancement.
    # TODO: Implement password-based encryption
    if password:
        print("WARNING: Password encryption for private key is not yet implemented.")
        encryption_algorithm = serialization.NoEncryption() # Placeholder
    else:
        encryption_algorithm = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    with open(filename, 'wb') as f:
        f.write(pem)
    print(f"Private key saved to {filename}")

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
    print(f"Public key saved to {filename}")

def load_private_key(filename=PRIVATE_KEY_FILE, password=None):
    """
    Loads a private key from a PEM file.
    Optionally decrypts with a password.
    """
    # TODO: Implement password-based decryption
    if password:
        print("WARNING: Password decryption for private key is not yet implemented.")

    with open(filename, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None, # For now, assuming no password
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
    For now, this will be a SHA256 hash of the public key's PEM representation, hex encoded.
    This ensures a fixed-length, shareable ID.
    """
    from cryptography.hazmat.primitives import hashes

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(pem)
    return digest.finalize().hex()

# --- Main execution for testing ---
if __name__ == "__main__":
    print("Tsnu'e-Mahtem Identity Manager")
    print("------------------------------")

    # Check if keys already exist
    import os
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        print(f"Keys already exist: {PRIVATE_KEY_FILE}, {PUBLIC_KEY_FILE}")
        print("Loading existing keys...")
        try:
            priv_key = load_private_key()
            pub_key = load_public_key()
            print("Keys loaded successfully.")
        except Exception as e:
            print(f"Error loading keys: {e}")
            print("Please delete existing key files or fix the issue and try again.")
            exit()
    else:
        print("Generating new key pair...")
        priv_key, pub_key = generate_key_pair()
        save_private_key(priv_key)
        save_public_key(pub_key)
        print("New key pair generated and saved.")

    tsnue_id = get_tsnue_id(pub_key)
    print(f"\nYour Tsnu'e ID: {tsnue_id}")

    # Example: Verifying public key can be derived from private key
    # This is an internal consistency check of the cryptography library
    if pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == \
       priv_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo):
        print("Public key successfully derived from private key (consistency check).")
    else:
        print("ERROR: Public key derivation check failed!")