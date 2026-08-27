# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from Crypto.Protocol.KDF import PBKDF2
# import base64

# def get_key(password):
#     salt = b'static_salt'
#     key = PBKDF2(password, salt, dkLen=32)
#     return key

# def encrypt(message, password):
#     key = get_key(password)
#     cipher = AES.new(key, AES.MODE_EAX)

#     ciphertext, tag = cipher.encrypt_and_digest(message.encode())

#     return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

# def decrypt(encrypted_data, password):
#     key = get_key(password)

#     data = base64.b64decode(encrypted_data.encode())

#     nonce = data[:16]
#     tag = data[16:32]
#     ciphertext = data[32:]

#     cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

#     message = cipher.decrypt_and_verify(ciphertext, tag)

#     return message.decode()


from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

# FIX: salt is now randomly generated per encryption and stored alongside
# the ciphertext (salt 16B | nonce 16B | tag 16B | ciphertext).
# The old format was (nonce 16B | tag 16B | ciphertext) with a hardcoded
# static salt — that made every password deterministic and rainbow-table-able.

SALT_SIZE = 16

def _derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32)

def encrypt(message, password):
    salt   = get_random_bytes(SALT_SIZE)          # FIX: fresh random salt
    key    = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    # Layout: salt | nonce | tag | ciphertext
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()

def decrypt(data, password):
    raw  = base64.b64decode(data.encode())
    salt, nonce, tag, ciphertext = (
        raw[:SALT_SIZE],
        raw[SALT_SIZE:SALT_SIZE+16],
        raw[SALT_SIZE+16:SALT_SIZE+32],
        raw[SALT_SIZE+32:],
    )
    key    = _derive_key(password, salt)          # FIX: use stored salt
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()