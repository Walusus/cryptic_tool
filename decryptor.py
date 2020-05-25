import argparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

import cryptography as cr

"""
Schemat wywołania:
    deszyfrator [<opcje>] <nazwa pliku do odszyfrowania>

Opcje:
    -k, --key-path <nazwa pliku> - Ścieżka do klucza prywatnego, używanego do deszyfrowania klucza sesyjnego lub danych. Jeżeli nie podano, użytkownik jest o nią poproszony w trakcie działania aplikacji.
    -s, --session-key <nazwa pliku> - Ścieżka do klucza danych, używanego do deszyfrowania lub danych. Jeżeli w danych rozmiar klucza sesyjnego nie jest równy 0, a został podany ten argument, to wyświetlany jest błąd.
    -o, --out <nazwa pliku> - Opcjonalna nazwa pliku wyjściowego. Jeżeli niezdefiniowana, plik otrzymuje pierwotną nazwę.
    -h, --help - Wyświetlenie tej notki mw.

Info:
    Jeżeli użytkownik nie podał opcji -s, a rozmiar klucza sesyjnego to 0, dane deszyfrowane są kluczem prywatnym.
"""

def main(**args):

    # sorting out arguments
    if args['key-path'] == 0:
        print("Podaj ścieżkę do klucza prywatnego")
        key_path = input()
    else:
        key_path = args['key-path']

    file_path = args['file-path']
    session_key_path = args['session-key']
    output_name = args['out']

    # loading the given private key, that's used to decrypt the session key
    with open(key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # opening the file, reading by bytes
    file = open(file_path, "rb")
    session_key_length = int.from_bytes(file.read(2), byteorder='little', signed=False) #first 2 bytes are the length of our session key

    # the rest of the file is metadata and the file itself that need to be decrypted


    if session_key_length != 0 and session_key_path != 0:
        print("Podano klucz sesji, mimo tego że klucz sesji jest podany w enkrypcji pliku! - koniec programu")
        return 0

    if session_key_length == 0 and session_key_path == 0:   # then we use the private key to decrypt the file
        encrypted_file = file.read()
        decrypted_file = private_key.decrypt(
            encrypted_file,
            padding.OAEP(
                mfg=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    else:

        if session_key_length == 0:
            encrypted_session_key = open(session_key_path, "rb").read(session_key_length)   # read the encrypted session key from the given file
        else:
            encrypted_session_key = file.read(session_key_length)   # read the encrypted session key from within the file to decrypt

        # decrypt the session key with the use of private key
        decrypted_session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mfg=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_file = file.read()
        # ---------------------- MOŻE ŹLE - zrzutować bajty na klucz?
        f = Fernet(decrypted_session_key)
        decrypted_file = f.decrypt(encrypted_file)

    # at this point we have the metadata + the file data itself decrypted in the form of bytes
    #TODO:  read 2 bytes (file_name_length) -> read file_name -> read file_length -> read file -> save file

    file_name_length = int.from_bytes(decrypted_file[0:2], "little", signed=False)
    file_name = bytes(decrypted_file[2:file_name_length + 1]).decode()
    if output_name == 0:
        output_name = file_name

    data_start_idx = 2 + file_name_length
    data_length = int.from_bytes(decrypted_file[data_start_idx:data_start_idx + 2])

    data = bytes(decrypted_file[data_start_idx + 2:data_start_idx + data_length + 1])
    out = open(output_name, 'wb')
    out.write(data)

    file.close()
    out.close()



if __name__ == '__main__':
    #Terminal arguments.
    # to run python name.py --integer <integer value>
    #Example:
    parser = argparse.ArgumentParser()
    parser.add_argument('file-path')
    parser.add_argument('-k', '--key-path', dest='key-path', type=str, default=0, required=False, help='Ścieżka do klucza prywatnego, używanego do deszyfrowania klucza sesyjnego lub danych. Jeżeli nie podano, użytkownik jest o nią poproszony w trakcie działania aplikacji.')
    parser.add_argument('-s', '--session-key', dest='session-key', type=str, default=0, required=False, help="Ścieżka do klucza danych, używanego do deszyfrowania lub danych. Jeżeli w danych rozmiar klucza sesyjnego nie jest równy 0, a został podany ten argument, to wyświetlany jest błąd.")
    parser.add_argument('-o', '--out', type=str, default=0, required=False, help="Opcjonalna nazwa pliku wyjściowego. Jeżeli niezdefiniowana, plik otrzymuje pierwotną nazwę.")
    #parser.add_argument('-h', '--help', type=str, required=False, help="Path to file.") #???

    parser.set_defaults()
    args = parser.parse_args()
    args = vars(args)

    main(**args)
