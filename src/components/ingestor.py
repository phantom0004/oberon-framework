"""Helper utilities for receiving and storing large pieces of data."""

from components.networking import decrypt_message
import os
import uuid

def reliable_recieve(conn_obj, data_size):
    """Reliably receive ``data_size`` bytes from ``conn_obj``."""
    from components.logging import log_activity

    log_activity(
        f"Connection timeout changed to suit {data_size} bytes of data.", "info"
    )
    conn_obj.settimeout(max(10, data_size / (1024 * 1024)))  # Set dynamic timeout based on size
    
    received_data = b''
    print("[!] Collecting data from target, processing time depends on item size")
    while len(received_data) < data_size:
        packet = conn_obj.recv(min(4096, data_size - len(received_data)))  # Receive in chunks
        if not packet:
            log_activity(
                "Connection closed or data ended unexpectedly when receiving screenshot data. Try again in a little moment.",
                "error",
            )
            return None
        received_data += packet

    return received_data

def process_and_check_recieved_data(received_data, data_size, key: bytes):
    """Validate and decrypt received data using ``key``."""
    from components.logging import log_activity

    if isinstance(data_size, str):
        log_activity(
            f"Supposed to recieve the data size but got type 'str' instead, output : {data_size}",
            "error",
        )
        return f"[-] Error when getting file data {data_size}. Please try again."
    
    # Check data integrity
    if len(received_data) != data_size:
        log_activity(
            f"Received data size ({len(received_data)}) does not match the expected size ({data_size}).",
            "error",
        )
        return "Received data size does not match the expected size."
    
    # If all data is received properly, process it
    decrypted_data = decrypt_message(received_data, key)
    if decrypted_data is None:
        log_activity(
            "Failed to decrypt screenshot or else data is corrupted. Try again in a little moment.",
            "error",
        )
        return "Data is corrupted or else is in an invalid format"
    
    return decrypted_data

def createfile_nocollision(header, footer=None):
    """Create a filename that does not currently exist on disk."""

    if footer is None:
        footer = ""
    
    def generate_filename(header, footer):
        if "." in header:
            file_parts = header.split(".")
            return f"{file_parts[0]}_{str(uuid.uuid4())[:4]}.{file_parts[1]}"
        else:
            return f"{header}_{str(uuid.uuid4())[:4]}{footer}"
    
    filename = generate_filename(header, footer)
    
    while os.path.exists(filename):
        filename = generate_filename(header, footer)
        
    return filename
