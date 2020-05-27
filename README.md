# Asymetryczny szyfrator plików
Aplikacja składa się z trzech komponentów. Służą one do generowania kluczy, szyfrowania i odszyfrowywania plików.


## generator.py
Schemat wywołania:
* python generator.py [opcje]

Opcje:
* -k, --key-path &lt;nazwa pliku&gt; - Ścieżka do klucza prywatnego, na podstawie którego ma zostać wygenerowany publiczny.
* -s, --size &lt;rozmiar&gt; - Rozmiar klucza prywatnego do wygenerowania w bajtach.
* -p, --private-only - Generowanie tylko klucza prywatnego.
* --private-out &lt;nazwa pliku&gt; - Nazwa pliku wyjściowego z kluczem prywatnym.
* --public-out &lt;nazwa pliku&gt; - Nazwa pliku wyjściowego z kluczem publicznym.
* -h, --help - Wyświetlenie pomocy i zakończenie programu.

Informacje:
* Generuje klucz prywatny lub parę kluczy (prywatny i publiczny). Domyślnym wyjściem są pliki public_key.pem i private_key.pem.


## encryptor.py
Schemat wywołania:
* python encryptor.py [opcje] &lt;Ścieżka pliku do zaszyfrowania&gt;

Opcje:
* -k, --key-path - Ścieżka do klucza publicznego, używanego do szyfrowania klucza sesyjnego lub danych. Jeżeli nie podano, użytkownik jest o nią poproszony w trakcie działania aplikacji.
* -d, --detach &lt;nazwa pliku&gt; - Klucz sesyjny w osobnym pliku.
* -n, --no-session-key - Szyfrowanie tylko z użyciem klucza publicznego.
* -o, --out &lt;nazwa pliku&gt; - Nazwa pliku wyjściowego. Domyślna to <nazwa pliku wejściowego>.crypt.
* -h, --help - Wyświetlenie pomocy i zakończenie programu.

Informacje:
* Szyfruje kopię podanego jako argument pliku.


## decryptor.py
Schemat wywołania:
* python decryptor.py [opcje] &lt;nazwa pliku do odszyfrowania&gt;

Opcje:
* -k, --key-path &lt;nazwa pliku&gt; - Ścieżka do klucza prywatnego, używanego do odszyfrowania klucza sesyjnego lub danych. Jeżeli nie podano, użytkownik jest o nią poproszony w trakcie działania aplikacji.
* -s, --session-key &lt;nazwa pliku&gt; - Ścieżka do zaszyfrowanego klucza sesyjnego, używanego do odszyfrowania lub danych.
* -o, --out &lt;nazwa pliku&gt; - Opcjonalna nazwa pliku wyjściowego. Jeżeli niezdefiniowana, plik otrzymuje pierwotną nazwę.
* -h, --help - Wyświetlenie pomocy i zakończenie programu.

Informacje:
* Odszyfrowuje kopię podanego jako argument pliku.
