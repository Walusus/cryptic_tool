import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def main(**args):
    if args['both']:
        # generates two keys
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=args['size'], backend=default_backend())
        public_key = private_key.public_key()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(args['private-key'], 'wb') as pem_out:
            pem_out.write(pem)
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(args['private-key']+".pub", 'wb') as pem_out:
            pem_out.write(pub_pem)
    else:
        print("Only public")
        with open(args['private-key'], "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
            public_key = private_key.public_key()
            pub_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(args['private_key'] + ".pub", 'wb') as pem_out:
                pem_out.write(pub_pem)


if __name__ == '__main__':
    # Terminal arguments
    parser = argparse.ArgumentParser(prog='generator', description='Info: \n Generuje klucz prywatny lub parę kluczy (prywatny i publiczny). Domyślnym wyjściem są pliki public.pem i private.pem.')
    parser.add_argument('-p', '--private-key', dest="private-key",type=str, required=True, help='Name of private key to use to genearte public key.')
    parser.add_argument('-s', '--size', type=int, dest="size",default=2048, required=False , help="Size of key to generate in bytes.")
    parser.add_argument('-b', '--both', type=bool, dest="both",default=True, required=False, help="Size of key to generate in bytes.")
    parser.add_argument('--password', type=str, required=False, help="Password used to acces private key.")
    parser.set_defaults()
    args = parser.parse_args()
    args = vars(args)
    main(**args)
