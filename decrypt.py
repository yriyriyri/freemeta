from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

encrypted_message_hex = input("encrypted message  ;;(hexformat): ")

encrypted_message = binascii.unhexlify(encrypted_message_hex)

with open('private_key.pem', 'r') as private_file:
    private_key = RSA.import_key(private_file.read())
=
cipher = PKCS1_OAEP.new(private_key)
decrypted_message = cipher.decrypt(encrypted_message)
decrypted_message = decrypted_message.decode('utf-8')

print(f'decrypted Message ;; {decrypted_message}')
