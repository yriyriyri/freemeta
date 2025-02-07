from Crypto.PublicKey import RSA
import binascii

# 1024bit 
key = RSA.generate(1024)
private_key_pem = key.export_key().decode('utf-8')
public_key_pem = key.publickey().export_key().decode('utf-8')

with open('private_key.pem', 'w') as private_file:
    private_file.write(private_key_pem)

with open('public_key.pem', 'w') as public_file:
    public_file.write(public_key_pem)

print("RSA key pair generated and saved 'private_key.pem' + 'public_key.pem'.")
