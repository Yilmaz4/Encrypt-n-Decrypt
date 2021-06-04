from Crypto.Cipher import DES3
from base64 import urlsafe_b64encode
from os import urandom

iv = [65, 110, 68, 26, 69, 178, 200, 219]
keyStr = ""
ivStr = ""
for i in iv: ivStr += chr(i)
key = urlsafe_b64encode(urandom(18))
cipher = DES3.new(key, DES3.MODE_CFB)
plaintext = bytes('Herkese merhaba, ben Yılmaz. Buraya sizinle beraber şifreleme ve deşifreleme yapmak için geldim.','utf-8')
msg = cipher.iv + cipher.encrypt(plaintext)
print(key.decode())
print(urlsafe_b64encode(msg).decode())
cipher = DES3.new(key, DES3.MODE_CFB)
print(cipher.decrypt(msg)[8:].decode())
