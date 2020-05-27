import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

"""
    Schemat wywołania:
    generatot [<opcje>] <nazwa pliku do od>

Opcje:
    -p, --private-key <nazwa pliku> - Ścieżka do klucza prywatnego, na podstawie którego ma zostać wygenerowany publiczny.
    -s, --size <rozmiar> - Rozmiar klucza do wygenerowania w bajtach.
    -h, --help - Wyświetlenie tej notki mw.

Info:
    Generuje klucz publiczny lub parę kluczy (prywatny i publiczny). Domyślnym wyjściem są pliki public.pem i private.pem.
"""


def main(**args):
    if args['private-key'] is "":
        # generates two keys
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=args['size'], backend=default_backend())
        public_key = private_key.public_key()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        # saving private key
        try:
            with open(args['private-name'], 'wb') as pem_out:
                pem_out.write(pem)
        except EnvironmentError:
            print("Error: Unable to create private key file.")
            exit(1)

        if not args['private-only']:
            pub_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            # saving public keys
            try:
                with open(args['public-name'], 'wb') as pem_out:
                    pem_out.write(pub_pem)
            except EnvironmentError:
                print("Error: Unable to create public key file.")
                exit(1)
    else:
        # generates one public key suing existing private key
        try:
            with open(args['private-key'], "rb") as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
                public_key = private_key.public_key()
                pub_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                # saving public key
                try:
                    with open(args['public-name'], 'wb') as pem_out:
                        pem_out.write(pub_pem)
                except EnvironmentError:
                    print("Error: Unable to create public key file.")
                    exit(1)

        except EnvironmentError:
            print("Error: Unable to open private key file.")
            exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='generator',
        description="Info: \n Generates public key or pair of keys (public and private)"
                    " default output is filename.pub and filename."
    )
    parser.add_argument('-k', '--key-path', dest="private-key", type=str, required=False, default="",
                        help="Path to a private key")
    parser.add_argument('--private-out', dest="private-name", type=str, required=False, default="private_key.pem",
                        help="Private key output file name (be default private_key.pem).")
    parser.add_argument('--public-out', dest="public-name", type=str, required=False, default="public_key.pem",
                        help="Public key output file name (be default public_key.pem).")
    parser.add_argument('-p', '--private-only', dest="private-only", action="store_true", required=False,
                        help="Generate private key only")
    parser.add_argument('-s', '--size', type=int, dest="size", default=2048, required=False,
                        help="Size of key to generate in bytes.")

    parser.set_defaults()
    args = parser.parse_args()
    args = vars(args)
    main(**args)
