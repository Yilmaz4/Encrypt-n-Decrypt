# About Encrypt'n'Decrypt:
[![made-with-python](https://img.shields.io/badge/Made%20With-Python%203%2E9%2E7-396F9E.svg?style=plastic)](https://www.python.org/)
[![made-for-windows](https://img.shields.io/badge/Made%20For-Windows-00A4E3.svg?style=plastic)](https://www.microsoft.com/)
[![GitHub license](https://img.shields.io/badge/License-MIT-A10000?style=plastic)](https://github.com/Yilmaz4/Encrypt-n-Decrypt/blob/master/LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-Actively-009e0a.svg?style=plastic)](https://GitHub.com/Yilmaz4/Encrypt-n-Decrypt/graphs/commit-activity)
[![Open Source?](https://img.shields.io/badge/Open%20source%3F-Of%20course%21%20%E2%9D%A4-3C9E44.svg?style=plastic)](https://GitHub.com/Yilmaz4/Encrypt-n-Decrypt/graphs/commit-activity)
[![Stable?](https://img.shields.io/badge/Release-v0%2E2%2E2%20%7C%20Stable-3C9E44.svg?style=plastic)](https://GitHub.com/Yilmaz4/Encrypt-n-Decrypt/graphs/commit-activity)

[//]: <> (009e0a Stable | ffc700 Prerelease | ff0000 Beta)

Hello everyone, this is my second Python project and first project that I've published to GitHub which can encrypt plain text & files using AES and RSA algorithm.

### About **Fernet** library and its encryption standard:
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
## Future plans:
In future releases, I'm planning to add a GUI (Graphical User Interface) to the program and support for encrypting files. Also I'm planning to change encryption standart to `AES-256`, `AES-192` and `AES-128` encryption standarts. I'm also planning to add `RSA-1024` and above asymmetric key encryption standarts. I am currently working on GUI update. It will be released soon.

The libraries that going to be used in future releases are `pycryptodome` and `pycryptodomex` libraries. These libraries are alternatives to *dead* `PyCrypto` library that fully replaces this library. These libraries can be used for both symmetric and asymmetric key encryptions and for asymmetric encryption, these libraries can support up to infinitive bytes of Private Key. For symmetric key encryption, these libraries supports `AES-256` `AES-192` and `AES-128` encryption keys.

Also the library that is going to be used for GUI is `tkinter` and `ttk` librarires. I am also planning to change GUI library to `PyQt5` or `PyQt6` to improve user interface and visuality in future releases.

#### Source code requirements:
- Python 3.9 and up.
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
import pyperclip, os, base64, time, collections

from tkinter import *
from tkinter.commondialog import Dialog
from tkinter import filedialog
from tkinter import ttk
from tkinter.ttk import *

from Crypto.Cipher import AES, PKCS1_OAEP, DES3
from Crypto.Util import Counter
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from requests import get, head
from webbrowser import open as openweb
from random import randint, choice
from string import ascii_letters, digits
from sys import exit, platform, exc_info
from markdown import markdown
from tkinterweb import HtmlFrame
from getpass import getuser
from ctypes import windll
from zipfile import ZipFile
from traceback import format_exc
from time import strftime
from typing import Union, Any, Optional
```
---
## Version status:
>### Current stable release: `v0.2.2`
>
>### Current release in development: `v0.3.0`

# License

Copyright 2017-2022 Yilmaz Alpaslan

Permission is hereby granted, free ofy person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be included in all copies
or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
