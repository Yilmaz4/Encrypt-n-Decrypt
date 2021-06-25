# About Encrypt'n'Decrypt:
[![made-with-python](https://img.shields.io/badge/Made%20With-Python%203%2E7%2E9-ff0000.svg?style=plastic)](https://www.python.org/)
[![made-for-windows](https://img.shields.io/badge/Made%20For-%E2%8A%9E%20Windows-ff4f00.svg?style=plastic)](https://www.python.org/)
[![GitHub license](https://img.shields.io/badge/License-MIT-ff9200?style=plastic)](https://github.com/Yilmaz4/Encrypt-n-Decrypt/blob/master/LICENSE)
[![Maintaner](https://img.shields.io/badge/Maintainer-Yilmaz4-ffff00?style=plastic)](https://GitHub.com/Yilmaz4)
[![GitHub Download Count](https://img.shields.io/github/downloads/Yilmaz4/Encrypt-n-Decrypt/total.svg?style=plastic)]()
[![Maintenance](https://img.shields.io/badge/Maintained%3F-Yes-0000ff.svg?style=plastic)](https://GitHub.com/Yilmaz4/Encrypt-n-Decrypt/graphs/commit-activity)
[![Open Source?](https://img.shields.io/badge/Open%20Source%3F-Of%20Course%21%20%E2%9D%A4-4b0082.svg?style=plastic)](https://GitHub.com/Yilmaz4/Encrypt-n-Decrypt/graphs/commit-activity)
[![Stable?](https://img.shields.io/badge/Release-v0%2E2%2E2%20%7C%20Stable-9400d3.svg?style=plastic)](https://GitHub.com/Yilmaz4/Encrypt-n-Decrypt/graphs/commit-activity)

Hello everyone, this project is my second Python project and first project that I published in GitHub. This program can encrypt and decrypt plain texts with `cryptography.fernet` symmetric key encryption. Program uses *Python 3.7.9*. First version of program (v0.1) is compatible with all OS's including Linux and MacOS except Windows XP and below but later versions currently only compatible with Windows OS's except Windows XP and below. Windows XP and below is not compatible with program because the Python version that program uses does not support them.

> Python 3.4 has reached end-of-life. Python 3.4.10 is the final release of 3.4.

### About **Fernet** library and it's encryption standart:
>Fernet guarantees that a message encrypted using it cannot be manipulated or read without the key. [Fernet](https://github.com/fernet/spec/) is an implementation of symmetric (also known as “secret key”) authenticated cryptography. Fernet also has support for implementing key rotation via `MultiFernet`.

`cryptography.fernet` encryption is a symmetric key encryption standard which uses 44-characters long encryption key. Encryption key must be a `base64.urlsafe_b64encode` encoded key (The urlsafe stands for *not containing url encoded restricted chacarters* or *only contains url encoding safe charaters*). In fact, this `cryptography.fernet` key is 32 characters long base64 encoded `AES-256` key. The reason behind this 44-charaters long key's length is base64's encoding algorithm. 
> ### Limitations
> Fernet is ideal for encrypting data that easily fits in memory. As a design feature it does not expose unauthenticated bytes. This means that the complete message contents must be available in memory, making Fernet generally unsuitable for very large files at this time.

> ### Implementation
> Fernet is built on top of a number of standard cryptographic primitives. Specifically it uses:
> - `AES` in `CBC` mode with a 128-bit key for encryption; using `PKCS7` padding.
> - `HMAC` using `SHA256` for authentication.
> - Initialization vectors are generated using `os.urandom()`.
> For complete details consult the [specification](https://github.com/fernet/spec/blob/master/Spec.md).

###### Source: [Cryptography Fernet official website](https://cryptography.io/en/latest/fernet/)

---
## System requirements:
- **Operating System:** Microsoft® Windows® Vista or later, Microsoft® Windows® 11 is recommended
- **Processor:** Intel® Pentium® 4 Processor 1.30 GHz or later, a dual-core 2GHz processor recommended
- **RAM (Random Access Memory):** 1GB or larger, 2GB is recommended
- **Screen resolution:** 640x480 or larger, 1280x720 is recommended
---
## Future plans:
In future releases, I'm planning to add GUI to program and support for encrypting files. Also I'm planning to change encryption standart to `AES-256`, `AES-192` and `AES-128` encryption standarts. I'm also planning to add `RSA-1024` and above asymmetric key encryption standarts. I am currently working on GUI update. It will be released soon.

The libraries that going to be used in future releases are `pycryptodome` and `pycryptodomex` libraries. These libraries are alternatives to *dead* `PyCrypto` library that fully replaces this library. These libraries can be used for both symmetric and asymmetric key encryptions and for asymmetric encryption, these libraries can support up to infinitive bytes of Private Key. For symmetric key encryption, these libraries supports `AES-256` `AES-192` and `AES-128` encryption keys.

Also the library that is going to be used for GUI is `tkinter` and `ttk` librarires. I am also planning to change GUI library to `PyQt5` or `PyQt6` to improve user interface and visuality in future releases.
### System requirements for the upcoming `v0.3.0` version:
- **Operating System:** Microsoft® Windows® Vista or later, Microsoft® Windows® 11 is recommended
- **Processor:** At least 1.5GHz dual-core processor or later, 2GHz dual-core processor is recommended
- **RAM (Random Access Memory):** 2GB or larger, 4GB is recommended
- **Screen resolution:** 800x600 or larger, 1280x720 is recommended
#### Source code requirements:
- Python 3.5 and up, Python 3.7.9 recommended
- `ttkwidgets` version `3.2.2` and up
- `cryptography` version `3.4.7` and up
- `pywin32` version `300` and up
- `pywin32-ctypes` version `0.2.0` and up
- `pyperclip` version `1.8.2` and up
- `typing-extensions` version `3.10.0.0` and up
- `pycryptodome` version `3.10.1` and up
- `pycryptodomex` version `3.10.1` and up
- `requests` version `2.25.1` and up
- `requests-cache` version `0.6.3` and up
- `markdown` version `3.3.4` and up
- `tkinterweb` version `3.9.1` and up
---
## For developers:
This project uses some libraries that must be installed using pip order to use them. Here are the all libraries must be installed using pip:
```python
pip install cryptography
```
All libraries used in this project are listed below:
```python
from cryptography.fernet import Fernet # Used for encryption
from time import sleep # Used for delay
from sys import exit # Used to exit the program
from ctypes import windll # Used to change title of window
from tkinter.filedialog import asksaveasfilename # Used for save-as function
from tkinter import Tk # Used to close tkinter window after save-as.
```
---
## Version status:
>### Current stable release: `v0.2.2`
>
>### Current beta release in development: `v0.2.3`
>
>### Current major release in development: `v0.3.0`

I am planning to release `v0.2.3` next week and `v0.3.0` next month.
