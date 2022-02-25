# About Encrypt'n'Decrypt

[![made-with-python](https://img.shields.io/badge/Made%20with-Python%203%2E9%2E7-396F9E.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![made-for-windows](https://img.shields.io/badge/Made%20for-Windows-00A4E3.svg?style=flat&logo=microsoft)](https://www.microsoft.com/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-Yup-009e0a.svg?style=flat&logo=powershell&logoColor=white)](https://GitHub.com/Yilmaz4/Encrypt-n-Decrypt/graphs/commit-activity)
[![Open Source?](https://img.shields.io/badge/Open%20source%3F-Of%20course%21%20%E2%9D%A4-009e0a.svg?style=flat)](https://GitHub.com/Yilmaz4/Encrypt-n-Decrypt/graphs/commit-activity)
[![Stable?](https://img.shields.io/badge/Release-v1%2E0%2E0%20%7C%20Beta-ffc700.svg?style=flat)](https://GitHub.com/Yilmaz4/Encrypt-n-Decrypt/graphs/commit-activity)

[//]: <> (009e0a Stable | ffc700 Prerelease | ff0000 Beta)

Hi everyone, welcome to the GitHub repository of my first ever Python project which is capable of encrypting and decrypting data using diverse encryption algorithms such as AES (Advanced Encryption Standard), 3DES (Triple Data Encryption Standard) or RSA (Rivest Shamir Adleman).

In cryptography, encryption is the process of encoding information. This process converts the original representation of the information, known as plaintext, into an alternative form known as ciphertext. Ideally, only authorized parties can decipher a ciphertext back to plaintext and access the original information. Encryption does not itself prevent interference but denies the intelligible content to a would-be interceptor.

To decrypt the data that you've encrypted using a symmetric key encryption algorithm (AES or 3DES) using this program, you need to have the key called "encryption key" which was used to encrypt the data. Similarly, to decrypt a piece of asymmetrically encrypted data (using RSA algorithm), you need to have a key called "private key".

## Introduction

As you can see in the screenshot below, the interface of the program consists of 5 tabs: Encryption, Decryption, Miscellaneous, Logs and Help & About respectively.

![encrypt-n-decrypt](https://user-images.githubusercontent.com/77583632/155799060-40b90545-2447-4039-abba-cc9cb7b5f072.png)

### Encryption

The encryption tab is for encrypting, as its name suggests. The program allows you to either enter some text or select a file to encrypt. Right below the area which you select what to encrypt, you can choose whether to generate a new encryption key or use a pre-generated key. If you choose to generate a new encryption key, you have two options as algorithm to use while encrypting which follow as AES or 3DES. Once you choose the algorithm you would like to use too, you can decide how long should the encryption key be. Longer keys are more secure against brute-force attacks (it's currently impossible to brute-force an AES-256 key). The number after either AES or 3DES represents the lenght of the key in bits. When you divide the number with 8, you can find out the amount of characters that are going to be in the key.

# License

Copyright © 2017-2022 Yılmaz Alpaslan

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
