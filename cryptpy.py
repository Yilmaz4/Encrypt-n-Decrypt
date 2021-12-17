"""

████████████████████  ████  ██████████████
████████████████████  ████  ██████████████
████    ████    ████  ████       ████
████    ████    ████  ████       ████
████    ████    ████  ████       ████
██      ████      ██  ████       ██
  ██    ████    ██    ████         ██
██      ████      ██  ████       ██
  ██    ████    ██    ████         ██


Copyright 2021 Yilmaz Alpaslan

Permission is hereby granted, free of charge, to any person obtaining a copy of this
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
"""

from Crypto.Cipher import AES as CryptoAES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import DES3 as CryptoDES3
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto import Random

from typing import Union
from string import ascii_letters, digits
from asyncio import run as asyncrun
from random import randint, choice

import base64

# Exceptions
class InvalidKey(Exception):
    def __init__(self, message):
        super().__init__(message)

class InvalidKeyLength(Exception):
    def __init__(self, message):
        super().__init__(message)

class EncryptionError(Exception):
    def __init__(self, message):
        super().__init__(message)

# Generate AES key function
def generateKey(length: Union[str, int] = 32):
    if not type(length) == int:
        try:
            length = int(length)
        except:
            raise InvalidKeyLength("Key length can only be an integer; and can be only 16, 24 or 32.")
        else:
            if not length in [16, 24, 32]:
                raise InvalidKeyLength("Key length can be either 16, 24 or 32.")
    key = ""
    for _ in range(length):
        random = randint(1,32)
        if random < 25:
            key += str(choice(ascii_letters))
        elif random >= 25 and random < 30:
            key += str(choice(digits))
        elif random >= 30:
            key += str(choice("!'^+%&/()=?_<>#${[]}\|__--$__--"))
    return key


# Key object class decleration
class Key:
    def __init__(self, key: Union[str, bytes] = None):
        if not type(key) == bytes:
            key = bytes(key, "utf-8")
        self.key = key
        self.length = len(key)
    def changeKey(self, key: Union[str, bytes]):
        pass

# AES class decleration
class AES:
    def __init__(self, key: Union[str, bytes], iv: Union[str, bytes] = get_random_bytes(CryptoAES.block_size)):
        if not type(key) == bytes:
            key = bytes(key, "utf-8")
        if not len(key) in [16, 24, 32]:
            raise InvalidKeyLength("Key length is invalid! It can be either 16, 24 or 32 characters long.")
        if not type(iv) == bytes:
            iv = bytes(iv, "utf-8")
        self.key, self.iv = key, iv
    def encryptData(self, data: Union[str, bytes, int]):
        if not type(data) == bytes:
            data = bytes(data, "utf-8")
        try:
            cipher = CryptoAES.new(self.key, CryptoAES.MODE_CFB, iv=self.iv)
        except:
            raise EncryptionError("Encryption failed! This maybe be due to invalid IV or key.")
        else:
            try:
                result = base64.urlsafe_b64encode(self.iv + cipher.encrypt(data)).decode("utf-8")
                return result
            except:
                raise EncryptionError("Encryption failed! This maybe be due to invalid IV or key.")
            else:
                iv_result = base64.urlsafe_b64decode(bytes(result, "utf-8"))[:16]
                data_result = base64.urlsafe_b64decode(bytes(result, "utf-8")).replace(iv_result, "")
                cipher_verify = CryptoAES.new(self.key, CryptoAES.MODE_CFB, iv=self.iv)
                cipher_verify.decrypt(data_result)
        
            
        
            
