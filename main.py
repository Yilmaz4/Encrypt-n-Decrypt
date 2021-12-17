from cryptpy import *

cipher = AES(key = generateKey(32))
print(cipher.encryptData(data="hi everybody"))
