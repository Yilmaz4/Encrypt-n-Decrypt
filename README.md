# Encrypt'n'Decrypt
Hello everyone, this project is my second Python project and first project that I published in GitHub. This program can encrypt and decrypt plain texts with `cryptography.fernet` symmetric key encryption. Program uses *Python 3.7.9*. First version of program (v0.1) is compatible with all OS's including Linux and MacOS except Windows XP and below but later versions currently only compatible with Windows OS's except Windows XP and below. Windows XP and below is not compatible with program due to *Python 3.4* (Last python compatible with Windows XP) *end-of-life*. 

> Python 3.4 has reached end-of-life. Python 3.4.10 is the final release of 3.4.

### About Encryption Standart that program uses:
`cryptography.fernet` encryption is a symmetric key encryption standart which uses 44-characters long encryption key. Encryption key must be a `base64.urlsafe_b64encode` encoded key. In fact this `cryptography.fernet` key is 32 characters long `AES-256` key but after encoding, key turns into 44-characters long key because `cryptography.fernet` only supports `base64.urlsafe_b64encode` encoded 44-characters long keys.
## Future plans:
In future releases, I'm planning to add GUI to program and support for encrypting files. Also I'm planning to change encryption standart to `AES-256`, `AES-192` and `AES-128` encryption standarts. I'm also planning to add `RSA-1024` and above asymmetric key encryption standarts. I am currently working on GUI update. It will be released soon.

The libraries that going to be used in future releases are `pycryptodome` and `pycryptodomex` libraries. These libraries are alternatives to *dead* `PyCrypto` library that fully replaces this library. These libraries can be used for both symmetric and asymmetric key encryptions and for asymmetric encryption, these libraries can support up to 16Kb (16384-bit) private RSA key. For symmetric key encryption, these libraries supports `AES-256` `AES-192` and `AES-128` encryption keys.
## For developers:
This project uses some libraries that must be installed using pip order to use them. Here are the all libraries must be installed using pip:
```
pip install cryptography
```
All libraries used in this project are listed below:
```
from cryptography.fernet import Fernet # Used for encryption
from time import sleep #U sed for delay
from sys import exit # Used to exit the program
from ctypes import windll # Used to change title of window
from tkinter.filedialog import asksaveasfilename # Used for save-as function
from tkinter import Tk # Used to close tkinter window after save-as.
```

## Version comparison
Version|GUI|Fernet Encryption|AES Encryption|RSA Encryption|Save key to a file|Use key from a file|File Encryption|
|--|--|--|--|--|--|--|--|
| Version 0.1.0 |   | ✔ |    |   |   |   |   |
| Version 0.2.0 |   | ✔ |    |   | ✔ |   |   |
| Version 0.2.1 |   | ✔ |    |   | ✔ |   |   |
| Version 0.2.2 |   | ✔ |    |   | ✔ | ✔ |   |
