from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64

keyPair = RSA.generate(1024)

pubKey = keyPair.publickey()
pubKeyPEM = pubKey.exportKey()
print("Public Key:", base64.urlsafe_b64encode(pubKeyPEM).decode())

privKeyPEM = keyPair.exportKey()
privKey = base64.urlsafe_b64encode(privKeyPEM)
print("Private Key:", privKey.decode())

msg = bytes('Herkese merhaba arkadaşlar, ben Yılmaz. Buraya sizinle birlikte işlem yapmaya geldim.', "utf-8")
encryptor = PKCS1_OAEP.new(pubKey)
encrypted = encryptor.encrypt(msg)
print("Encrypted:", base64.urlsafe_b64encode(encrypted).decode())

decryptor = PKCS1_OAEP.new(RSA.import_key(privKeyPEM))
decrypted = decryptor.decrypt(encrypted)
print('Decrypted:', decrypted.decode())