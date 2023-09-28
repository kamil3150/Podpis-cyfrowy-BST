import hashlib
import ctypes
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

# Load Rust library as a Python module
rust_module = ctypes.CDLL('./letrng.dll')


class CustomRandomNumberSource:
    def __init__(self):
        pass

    def rand_bytes(self):
        # Call Rust TRNG to get random bytes
        random_value = rust_module.generate_32_bit()
        # Convert the 32-bit integer to bytes (4 bytes)
        random_bytes = random_value.to_bytes(4, byteorder='big')
        return random_bytes


# Function that generate private and public key using Rust TRNG
def generate_keys():
    custom_random_source = CustomRandomNumberSource()
    random_seed = custom_random_source.rand_bytes()
    os.urandom(len(random_seed))

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("private_key.pem", "wb") as key_file:
        key_file.write(private_pem)
    with open("public_key.pem", "wb") as key_file:
        key_file.write(public_pem)

    print("private_key and public_key generated and saved to file")


# Function that sign a file
def sign_file(private_key_file_path, file_path, signature_file_path):
    with open(private_key_file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    with open(file_path, 'rb') as file:
        file_data = file.read()
        sha3_hash = hashlib.sha3_256(file_data).digest()
        signature = private_key.sign(
            sha3_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA3_256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA3_256()
        )
        with open(signature_file_path, 'wb') as signature_file:
            signature_file.write(signature)
        print("File signed successfully")


# Function that verify if signature is valid
def verify_signature(public_key_file_path, file_path, signature_file_path):
    try:
        with open(public_key_file_path, 'rb') as public_key_file, \
                open(file_path, 'rb') as file, \
                open(signature_file_path, 'rb') as signature_file:
            public_key = serialization.load_pem_public_key(
                public_key_file.read(),
                backend=default_backend()
            )
            file_data = file.read()
            signature = signature_file.read()
            sha3_hash = hashlib.sha3_256(file_data).digest()
            try:
                public_key.verify(
                    signature,
                    sha3_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA3_256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA3_256()
                )
                print("Valid signature.")

                return "Valid signature."

            except Exception:
                print("Invalid signature.")

                return "Invalid signature."

    except IOError:
        print("Cannot read a file")

# generate_keys()


# sign_file('private_key.pem', 'obrazek.jpg', 'trng.bin')


verify_signature('public_key.pem', 'obrazek.jpg', 'trng.bin')