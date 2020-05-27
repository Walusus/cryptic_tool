import sys
import os
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet


def print_help():
    print("-h, --help - print this message")
    print("-k, --key-path - path to the public key file")
    print("-n, --no-session-key - encrypt file using only a public key")
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

    parser = argparse.ArgumentParser(prog='Decryptor', description="Info: Encrypts given file")
    parser.add_argument('file-path')
    parser.add_argument('-k', '--key-path', dest='key-path', type=str, default="", required=False,
                        help='path to a public key file')
    parser.add_argument('-n', '--no-session-key', dest="no-session", action="store_true", required=False,
                        help="encrypt file using only a public key")
    parser.add_argument('-o', '--out', dest='output', type=str, default="", required=False,
                        help="specify the output file")
    parser.add_argument('-d', '--detach', dest="session-file", type=str, default="", required=False,
                        help="save session key in the specified file")

    parser.set_defaults()
    args = vars(parser.parse_args())

    # Get input file name
    input_file = args['file-path']

    # Get output file name
    if args['output'] is not "":
        output_file = args['output']
    else:
        output_file = os.path.splitext(input_file)[0] + ".crypt"

    # Get public key file name
    if args['key-path'] is not "":
        pub_key_file = args['key-path']
    else:
        pub_key_file = input("Public key file path: ")

    # Check if to generate a session key
    no_session_key = args['no-session']

    # Check how to store session key
    if not no_session_key and args['session-file'] is not "":
        session_key_file = args['session-file']
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
    data = len(input_file.encode()).to_bytes(2, byteorder="little", signed=False) + data

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
        try:
            token = pub_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except ValueError:
            print("Data size is to large to be encrypted using only the provided public key.\n"
                  "Try generating larger key or use symmetric session key (omit -n / --no-session-key option).")
            exit(1)

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
