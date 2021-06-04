import random, string, base64

# Random characters
"""key = ''
for i in range(30):
    choice = random.randint(1,45)
    if choice < 30:
        key = key +str(random.choice(string.ascii_letters))
    elif choice > 30 and choice < 32: 
        key = key + str(random.choice("_-/+"))
    else: 
        key = key + str(random.choice(string.digits))
key = key + '=='"""
#print(base64.urlsafe_b64encode(base64.urlsafe_b64decode(bytes(key, 'utf-8'))).decode())


