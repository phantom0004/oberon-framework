<!-- README.md -->

<h1 align="center">
  <img src="https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiGDfWyb_D349gyXXS_i5BIVRWc0XVP85D0dOhd-1u9u3C6_qFrhVpsz0ASxbFjHREeF6WA2SGGDUaKTWgoKVCdVK5bms8XQ6JbqMM7H8xWkmmX_3eT3f6nzEeUoBBBHw5drpejI2I_qnWN-awunE3vAByF2y4tuatjdaRAGL1r5m7djsgnUVh0f8Pq/s728-rw-e365/rat-malware.png" width="120" alt="Th3Executor logo"><br/>
  Th3Executor
</h1>

<p align="center">
  A comprehensive offensive-security framework for <strong>penetration testers</strong> and <strong>security researchers</strong>.
  <br/><br/>
  <a href="#-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-usage-workflow">Usage Workflow</a> •
  <a href="#-screenshots">Screenshots</a> •
  <a href="#-disclaimer">Disclaimer</a> •
  <a href="#-license">License</a>
</p>

---

## ✨ Features

- 🖥️ **Remote Command Execution** — Run commands and scripts on remote systems  
- 📝 **System Intelligence Gathering** — Collect detailed OS, network, and hardware data  
- 🔒 **Persistence** — Create startup registry entries on Windows targets  
- 📦 **Payload Conversion** — Package Python payloads as standalone executables  
- 🕵️ **Payload Obfuscation** — Evade antivirus engines with packing and obfuscation  
- 🔄 **Reverse TCP** — Establish covert reverse connections  
- 📸 **Screenshot Capture** — Snap the target desktop in real time  
- 💻 **Interactive Remote Shell** — Gain a fully interactive CLI session  
- ⌨️ **Keylogger Generation** — Record keystrokes silently  
- 🔐 **Robust Encryption** — Protect C2 traffic with strong algorithms  
- 🔑 **Hot-Swap Keys** — Rotate encryption keys during active sessions  

---

## 🚀 Quick Start

# 1 • Configure payload and server
```bash
python3 executor_setup.py
```

# 2 • Launch the C2 server
```bash
python3 th3executor.py
```

# 3 • (Optional) Run the payload locally for testing
```bash
python3 payload.py
```

---

## 🛠️ Usage Workflow

1. Setup — Define payload and server options via executor_setup.py  
2. Serve — Start th3executor.py; wait for inbound sessions  
3. Deliver — Supply the generated executable or raw Python payload to the target  
4. Connect — A session appears automatically in the C² console  
5. Operate — Execute commands, deploy modules, and maintain access  

---

## 🖼️ Screenshots

### TO BE ADDED
<p align="center">
  <p></p>
</p>

---

## ❗ Disclaimer

**Th3Executor is intended for authorised penetration testing and security research purposes only.**

Any unauthorised or malicious use is strictly prohibited. You are solely responsible for your actions.

---

## 📄 License

Distributed under the MIT License. See the LICENSE file for more details.
