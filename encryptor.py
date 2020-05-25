import sys
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet


def print_help():
    print("-h, --help - print this message")
    print("-k, --key-path - path to the public key file")
    print("-n, --no-session-key - encrypt file using only the public key")
    print("-o, --out <filename> - specify the output file")
    print("-d, --detach <filename> - save session key in the specified file")
    pass


def save_session_key(key, filename):
    try:
        with open(filename, "wb") as out_file:
            out_file.write(key)
    except EnvironmentError:
        print("Error: Unable to create session key file.")
        exit(1)


def load_params():
    # Handle help call
    if "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        exit(0)

    # Get input file name
    input_file = os.path.basename(sys.argv[-1])

    # Get output file name
    if "-o" in sys.argv:
        output_file = sys.argv[sys.argv.index("-o") + 1]
    elif "--out" in sys.argv:
        output_file = sys.argv[sys.argv.index("--out") + 1]
    else:
        output_file = os.path.splitext(input_file)[0] + ".crypt"

    # Get public key file name
    if "-k" in sys.argv:
        pub_key_file = sys.argv[sys.argv.index("-k") + 1]
    elif "--key-path" in sys.argv:
        pub_key_file = sys.argv[sys.argv.index("--key-path") + 1]
    else:
        pub_key_file = input("Public key file: ")

    # Check if to generate session key
    if "-n" in sys.argv or "--no-session-key" in sys.argv:
        no_session_key = True
    else:
        no_session_key = False

    # Check how to store session key
    if not no_session_key and "-d" in sys.argv:
        session_key_file = sys.argv[sys.argv.index("-d") + 1]
    elif not no_session_key and "--detach" in sys.argv:
        session_key_file = sys.argv[sys.argv.index("--detach") + 1]
    else:
        session_key_file = None

    return input_file, output_file, pub_key_file, no_session_key, session_key_file


if __name__ == '__main__':

    # Read user params
    input_file, output_file, pub_key_file, no_session_key, session_key_file = load_params()

    # Open public key file
    try:
        with open(pub_key_file, "rb") as key_file:
            pub_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    except EnvironmentError:
        print("Error: Unable to open public key file.")
        exit(1)

    # Read data from input file
    try:
        with open(input_file, "rb") as in_file:
            data = in_file.read()
    except EnvironmentError:
        print("Error: Unable to open input file.")
        exit(1)

    # Add metadata
    data = len(data).to_bytes(8, byteorder="little", signed=False) + data
    data = input_file.encode() + data
    data = len(input_file.encode()).to_bytes(8, byteorder="little", signed=False) + data

    # Generate session key if needed and encrypt data
    if not no_session_key:
        session_key = Fernet.generate_key()
        session_f = Fernet(session_key)

        # Encrypt data
        token = session_f.encrypt(data)

        # Encrypt session key
        enc_session_key = pub_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        if session_key_file is not None:
            # Save session key
            save_session_key(enc_session_key, session_key_file)

    else:
        # Encrypt data
        enc_session_key = None
        token = pub_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # Save encrypted data
    try:
        with open(output_file, "wb") as out_file:
            if no_session_key or session_key_file is not None:
                out_file.write((0).to_bytes(2, byteorder="little", signed=False))
            else:
                out_file.write((len(enc_session_key)).to_bytes(2, byteorder="little", signed=False))
                out_file.write(enc_session_key)
            out_file.write(token)

    except EnvironmentError:
        print("Error: Unable to create output file.")
        exit(1)

    print("Encrypted file saved as " + output_file)
