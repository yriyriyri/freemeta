from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

with open('private_key.pem', 'r') as private_file:
    private_key = RSA.import_key(private_file.read())

with open('public_key.pem', 'r') as public_file:
    public_key = RSA.import_key(public_file.read())

public_key_pem = public_key.export_key().decode('utf-8')

# Example prompt for ChatGPT to encrypt a message

print(f"""ChatGPT, please encrypt your  message using the following public key with RSA encryption and PKCS1_OAEP padding:

{public_key_pem}

Respond with the encrypted message in hex format.""")

# Decryption part
encrypted_message_hex = input("\nencrypted ai response: ")
encrypted_message = binascii.unhexlify(encrypted_message_hex)

cipher = PKCS1_OAEP.new(private_key)
decrypted_message = cipher.decrypt(encrypted_message)
decrypted_message = decrypted_message.decode('utf-8')

print(f'\ndecrypted msg ;;; {decrypted_message}')
