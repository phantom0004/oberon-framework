from components.networking import attempt_exchange

def handle_reconnections(port, conn_obj):
    print(colored("[-] A fatal error has occurred, the target terminated the connection", "red"))
    connection_retry = input("Retry Connection (y/n)? > ").strip().lower()
    if connection_retry == "y":
        print("\n[!] Reattempting . . .")
        conn_obj = connect_target(port)
        print(colored("[+] Reconnected to target!", "green", attrs=['bold']))
        log_activity("Reconnected to target successfully.", "info")
        symmetric_key = attempt_exchange(conn_obj)
        if symmetric_key is None:
            log_activity("Failed to establish a symmetric key with the client during the Diffie-Hellman exchange after reconnection. Check network conditions and client configurations.", "error")
            conn_obj.close()
            exit()

        return conn_obj, symmetric_key
    else:
        log_activity("Program ended because the user did not want to reconnect with the target again.", "info")
        exit("Program ended")
        
def connect_target(port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to avaliable interface on the specified port
    listener.bind(('0.0.0.0', port))

    # Listen for incoming connections
    listener.listen(1)
    print(f"[!] Listening for incoming connections on port {port} ...")

    # Accept a connection when the client connects
    conn_obj, addr = listener.accept()
    
def disconnect_target(conn_obj, shutdown_signal):
    try:
        conn_obj.close()
        log_activity("Exited th3executor, connection terminated successfully on server end", "info")
    except Exception as err:
        print("[-] Program ended abruptly, no connection was probably established with target")
        log_activity(f"Exited th3executor, could not terminate connection on server side -> {err}", "error")

    if not shutdown_signal or shutdown_signal == "connection_not_closed":
        print(colored("[-] Target did not terminate the connection on their end", "red"))
        print(colored("[!] This can be due to a network problem, please wait a few moments before re-connecting", "yellow"))
        
        log_activity("Exited th3executor, connection was not terminated on targets end.", "error")
    elif shutdown_signal == "shutdown_confirmed":
        print(colored("[+] Connection terminated successfully on targets end", "green"))
        
        log_activity("Exited th3executor, connection terminated normally between both parties.", "info")
    else:
        print(colored("[-] Unknown shutdown code retireved, unable to parse output. Connection is probably still open", "red"))
        print(colored("[!] This can be due to a network problem, please wait a few moments before re-connecting", "yellow"))
        
        log_activity("Unknown shutdown code retireved, unable to parse output. Connection is probably still open.", "error")