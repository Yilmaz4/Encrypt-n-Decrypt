<p align="center">
  <img alt="Logo" src="icon.ico" width="100px" />
  <h1 align="center">Encrypt-n-Decrypt</h1>
</p>

[![made-with-python](https://img.shields.io/badge/Made%20with-Python%203%2E11%2E0-396F9E.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![made-for-windows](https://img.shields.io/badge/Made%20for-Windows-00A4E3.svg?style=flat&logo=microsoft)](https://www.microsoft.com/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-No-ff0000.svg?style=flat&logo=powershell&logoColor=white)](https://GitHub.com/Yilmaz4/Encrypt-n-Decrypt/graphs/commit-activity)
[![Open Source?](https://img.shields.io/badge/Open%20source%3F-Of%20course%21%20%E2%9D%A4-009e0a.svg?style=flat)](https://GitHub.com/Yilmaz4/Encrypt-n-Decrypt/graphs/commit-activity)
[![Stable?](https://img.shields.io/badge/Release-v1%2E0%2E0%20%7C%20Stable-009e0a.svg?style=flat)](https://GitHub.com/Yilmaz4/Encrypt-n-Decrypt/graphs/commit-activity)

[//]: <> (009e0a Stable | ffc700 Prerelease | ff0000 Beta)

Hello! Welcome to the GitHub repository Encrypt-n-Decrypt! As its name would imply, this program can encrypt your data, and decrypt it; along with some additional features like KDF, hash and base64 encoding.

Encryption is turning your data into something unreadable, which can only be turned back to its original form using a digital key. This program lets you do this.

To decrypt the data that you had encrypted using a symmetric key encryption algorithm (AES or 3DES) with this program, you need to have the key called "the encryption key", which you had used to encrypt your data, or was generated and shown to you. This key consists of either 16, 24 or 32 random characters. Since the same key can be used to both encrypt and decrypt, these kinds of algorithms are called symmetric. Similarly, to decrypt a piece of asymmetrically encrypted data (using RSA algorithm), you need to have a key called "private key" which is usually longer than 1024 characters. In order to have two or more pieces of data be decryptable using the same private key, you need to encrypt them with the same public key, which can be extracted from the private key. Because there are two different keys involved in this process, these algorithms are called asymmetric.

Asymmetric key encryption is not available yet though. It'll be available in the next update.

## Features

- Multi-threaded plain-text or file encryption/decryption using AES and 3DES algorithms.
- Ability to generate, enter or browse an encryption key; and ability to save an encryption key to a file.
- Plain-text or file encoding/decoding using base64 encoding.
- Plain-text or file hash calculation using SHA-1, SHA-256, SHA-512 and MD-5.
- Ability to derivate an encryption key from a password (KDF).
- Usage of SQLite3 for saving the configurations made (such as what to encrypt or the length of the key to generate) to a database file when the user closes the program, and load the saved configurations in the next start-up.
- Lots of visual themes coming from the [ttkthemes](https://github.com/TkinterEP/ttkthemes) package.

Despite being memory efficient though, encrypting/decrypting files whose sizes are bigger than the amount of RAM installed on the computer can cause the program to run out of memory and therefore fail.

## Introduction

As you can see in the screenshots below, the user interface of the program consists of 5 tabs: Encryption, Decryption, Miscellaneous, Logs and Help & About respectively.

### Encryption

![Screenshot 2022-03-19 011502](https://user-images.githubusercontent.com/77583632/159093647-2e476933-2d80-4ff8-96c2-ec17d09d3043.png)

The encryption tab is for encrypting as its name suggests. The program allows you to either enter some text or select a file to encrypt. Right below the area which you select what to encrypt, you can choose whether to generate a new encryption key or use a pre-generated key.

If you choose to generate a new encryption key, you have two options as algorithm to use while encrypting which follow as AES or 3DES. Once you choose the algorithm you would like to use too, you can decide how long should the encryption key be. Longer keys are more secure against brute-force attacks (it's currently impossible to brute-force an AES-256 key). The number after either AES or 3DES represents the lenght of the key in bits. When you divide the number with 8, you can find out the amount of characters that are going to be in the key.

If you choose to enter an existent encryption key, you basically can. You also can select a key file (*.key or *.txt) that you've saved with the "Save as..." button in the output pane. When you enter the key, you can select which algorithm you want to encrypt the data with below the entry.

Finally, you can either press Enter key on your keyboard or click the "Encrypt" button to encrypt the data. The encrypted data will appear in the right pane with the encryption key which you can use to decrypt the data later. If you had selected a file to encrypt, the encrypted data will be written on the file unless you uncheck the "Write encrypted data to the file" checkbox next to the button.

### Decryption

![decryption](https://user-images.githubusercontent.com/77583632/155800966-5fc8650b-2077-4bc4-8f4e-56e8fc750712.png)

The decryption tab as its name suggests like the encryption tab, is for decrypting the data that you've encryped in the encryption tab. You can enter the encrypted data to the big entry under "Encrypted text" radiobutton, or you can select an encrypted file using the "Browse" button under "Encrypted file" radiobutton.

Under the encrypted data selection area, you can see another entry for the encryption key that was given alongside the encrypted data in the right pane in encryption tab. You can either enter the key directly or select a key file which ends with *.key or *.txt extensions. Above the entry, you can choose the algorithm which was used while encrypting the data.

Finally, like in the encryption tab, you can click the "Decrypt" button to decrypt the data. If you've entered the correct encryption key, the decrypted data should appear below the button. If you had selected a file to decrypt, the decrypted data will be written on the file.

# License

Copyright © 2017-2023 Yılmaz Alpaslan

Permission is hereby granted, free of charge to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
