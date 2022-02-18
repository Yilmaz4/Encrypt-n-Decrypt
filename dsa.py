from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# Create a new DSA key
key = DSA.generate(1024)

# Sign a message
message = b"Hello"
hash_obj = SHA256.new(message)
print(hash_obj)
signer = DSS.new(key, 'fips-186-3')
print(signer)
signature = signer.sign(hash_obj)
print(signature)

# Load the public key
hash_obj = SHA256.new(message),
pub_key = DSA.import_key(key.publickey().export_key())
print(pub_key)
verifier = DSS.new(pub_key, 'fips-186-3')
print(verifier)

