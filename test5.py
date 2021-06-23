from twofish import Twofish
from base64 import urlsafe_b64encode
BLOCK_SIZE = 16
twofish_passphrase = b'Herkese Merhabalar'
T = Twofish(twofish_passphrase)
def encryptTwofish(text):
    fileContent = bytes(text, "utf-8")
    paddingBytesLength = BLOCK_SIZE - (len(fileContent) % BLOCK_SIZE)
    paddingBytes = ''
    for i in range(paddingBytesLength):paddingBytes += ' '
    fileContent = fileContent.decode('utf-8') + paddingBytes
    iteration_count = int(len(fileContent) / BLOCK_SIZE)
    encryptedText = ''.encode()
    for i in range(iteration_count):encryptedText += T.encrypt(fileContent[BLOCK_SIZE * i : (i+1) * BLOCK_SIZE].encode())
    return encryptedText

def decryptTwofish(encryptedText):
    iteration_count = int(len(encryptedText) / BLOCK_SIZE)
    decryptedFileContent = ""
    for i in range(iteration_count):
        decryptedFileContent += T.decrypt(encryptedText[BLOCK_SIZE * i : (i+1) * BLOCK_SIZE]).decode()
    return decryptedFileContent.strip()
x = encryptTwofish("Herkese merhanar")
print(urlsafe_b64encode(x).decode())
print(decryptTwofish(x))