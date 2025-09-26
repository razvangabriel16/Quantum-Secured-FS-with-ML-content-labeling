import sys
import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from dotenv import load_dotenv
from pathlib import Path

envpath = Path('.') / '.env' #PosixPath type not str
load_dotenv(dotenv_path=envpath)
METADATA_FILE = os.getenv('METADATA_FILE', f'{envpath}/keys.json')
QUANTUM_KEY_PATH = os.getenv('QUANTUM_KEY_PATH', '/default/path')
QUANTUM_KEY_SCRIPT = os.getenv('QUANTUM_KEY_SCRIPT', '/default/path')
def load_metadata() -> dict:
    if not os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, 'wt') as fd:
            json.dump({'files': {}}, fd)
    with open(METADATA_FILE, 'rt') as fd:
        return json.load(fd)
    
def save_metadata(metadata: dict) -> None:
    with open(METADATA_FILE, 'wt') as fd:
        json.dump(metadata, fd, indent= 3)

def generate_store(inode: int ) -> tuple: #fuse_ino_t is 64bit but python int handles it
    metas = load_metadata()
    privatekey = x25519.X25519PrivateKey.generate()
    publickey = privatekey.public_key()
    privatekey_bytes = privatekey.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    publickey_bytes = publickey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    metas['files'][inode] = {
        'privatekey': base64.b64encode(privatekey_bytes).decode('utf-8'),
        'publickey': base64.b64encode(publickey_bytes).decode('utf-8')
        #the .b64encode returns Base64 bytes and then .decode('utf-8') returns storable for json bytes
    }
    save_metadata(metadata=metas)
    return privatekey, publickey

def load_keypair(inode: int) -> tuple:
    metas = load_metadata()
    try:
        filedata = metas['files'][inode]
    except KeyError:
        raise ValueError(f"no keypair found for inode: {inode}")
    private_key_bytes = base64.b64decode(filedata['privatekey'])
    public_key_bytes = base64.b64decode(filedata['publickey'])
    
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
    public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
    
    return private_key, public_key

def transform_quantum_key_to_private_key(quantum_key: str, thresh: int = 30) -> x25519.X25519PrivateKey:
    if len(quantum_key) < thresh or not all(c in '01' for c in quantum_key):
        raise ValueError("Quantum key must be binary and meet minimum length threshold")
    
    quantum_int = int(quantum_key, 2)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'quantum_to_x25519_expansion',
    )
    
    quantum_bytes_needed = (len(quantum_key) + 7) // 8
    quantum_key_bytes = quantum_int.to_bytes(quantum_bytes_needed, byteorder='big')
    expanded_key_bytes = hkdf.derive(quantum_key_bytes)
    
    return x25519.X25519PrivateKey.from_private_bytes(expanded_key_bytes)

def generate_shared_secret(quantum_key: str, public_key: x25519.X25519PublicKey) -> bytes:
    quantum_private_key = transform_quantum_key_to_private_key(quantum_key)
    return quantum_private_key.exchange(public_key)

def hkdf_from_shared_secret(shared_secret: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'quantum_key_derivation',
    )
    return hkdf.derive(shared_secret)

def encrypt_in_place(file_path: str, key: bytes) -> None:
    nonce = os.urandom(12)
    
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    with open(file_path, 'wb') as file:
        file.write(nonce + ciphertext)

def decrypt_in_place(file_path: str, key: bytes) -> None:
    with open(file_path, 'rb') as file:
        data = file.read()
    
    if len(data) < 12:
        raise ValueError("Encrypted file too short to contain nonce")
    
    nonce = data[:12]
    ciphertext = data[12:]
    
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Decryption failed - incorrect key or corrupted file")
    
    with open(file_path, 'wb') as file:
        file.write(plaintext)


def take_quantum_key(file_path: str = QUANTUM_KEY_PATH, threshold: float = 0.5) -> dict:
    dictionary_info = {}
    efficiency_found = False
    
    with open(file_path, 'rt') as f:
        first_line = f.readline().strip()
        dictionary_info['key'] = first_line
        
        f.seek(0)
        for line in f:
            line = line.strip()
            if "efficiency" in line:
                dictionary_info['efficiency'] = float(line.split(':')[1].strip())
                efficiency_found = True
                if dictionary_info['efficiency'] < threshold:
                    print(f"Efficiency {dictionary_info['efficiency']:.2%} is below threshold {threshold:.2%}. Need to recompute")
                    os.system(QUANTUM_KEY_SCRIPT)
                    return take_quantum_key(file_path, threshold)
                break
    
    if not efficiency_found:
        raise ValueError("File doesn't contain efficiency field")
    
    return dictionary_info


def encrypt_file(file_path: str, inode: int, quantum_key_file: str = QUANTUM_KEY_PATH) -> None:
    threshold = 0.5
    
    try:
        quantum_key_info = take_quantum_key(quantum_key_file, threshold)
        
        try:
            file_private_key, file_public_key = load_keypair(inode)
        except ValueError:
            file_private_key, file_public_key = generate_store(inode)
        
        shared_secret = generate_shared_secret(quantum_key_info['key'], file_public_key)
        derived_key = hkdf_from_shared_secret(shared_secret)
        
        encrypt_in_place(file_path, derived_key)
        print(f"encryption completed. file encrypted in place. inode {inode}")
            
    except Exception as e:
        print(f"encryption failed: {e}")
        raise

def decrypt_file(file_path: str, inode: int, quantum_key_file: str = QUANTUM_KEY_PATH) -> None:
    threshold = 0.5
    
    try:
        quantum_key_info = take_quantum_key(quantum_key_file, threshold)
        
        file_private_key, file_public_key = load_keypair(inode)
        
        shared_secret = generate_shared_secret(quantum_key_info['key'], file_public_key)
        derived_key = hkdf_from_shared_secret(shared_secret)
        
        decrypt_in_place(file_path, derived_key)
        print(f"decryption completed. fle decrypted in place with inode {inode}")
            
    except Exception as e:
        print(f"decryption failed: {e}")
        raise

if __name__ == '__main__':
    #for encryption we call from fuse: python3 encrypt.py encrypt <fuse_ino_t> <path_of_the_file>
    #for decryption we call from fuse: python3 encrypt.py decrypt <fuse_ino_t> <path_of_the_file>
    if len(sys.argv) < 4:
        sys.exit(1)
    todo = sys.argv[1]
    fuse_ino = sys.argv[2]
    path_file = sys.argv[3]
    try:
        if todo == 'encrypt':
            if os.path.exists(path= path_file):
                encrypt_file(path_file, fuse_ino)
            else:
                print(f"path {path_file} is not existent for encryption of file with {fuse_ino}")
                sys.exit(4)

        elif todo == 'decrypt':
            if os.path.exists(path= path_file):
                decrypt_file(path_file, fuse_ino)
            else:
                print(f"path {path_file} is not existent for decryption of file with {fuse_ino}")
                sys.exit(4)

        else:
            print("todo not set(encrypt / decrypt) internal mistake fuse .c file call")
            sys.exit(3)
            
    except Exception as e:
        print(f"operation fail {e}")
        sys.exit(2)