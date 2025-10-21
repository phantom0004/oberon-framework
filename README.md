<!-- README.md -->

<h1 align="center">
  <img src="https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiGDfWyb_D349gyXXS_i5BIVRWc0XVP85D0dOhd-1u9u3C6_qFrhVpsz0ASxbFjHREeF6WA2SGGDUaKTWgoKVCdVK5bms8XQ6JbqMM7H8xWkmmX_3eT3f6nzEeUoBBBHw5drpejI2I_qnWN-awunE3vAByF2y4tuatjdaRAGL1r5m7djsgnUVh0f8Pq/s728-rw-e365/rat-malware.png" width="120" alt="Oberon Framework logo"><br/>
  Oberon Framework
</h1>

<p align="center">
  <strong>A comprehensive offensive-security framework for penetration testing and security research</strong>
  <br/><br/>
  <a href="#-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#%EF%B8%8F-usage-workflow">Usage Workflow</a> •
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

### 1️⃣ Configure Payload and Server
```bash
python3 src/payload_setup.py
```

### 2️⃣ Launch the C2 Server
```bash
python3 src/oberon_framework.py
```

### 3️⃣ (Optional) Test Payload Locally
```bash
python3 src/payload.py
```

---

## 🛠️ Usage Workflow

1. **Setup** — Define payload and server options via `payload_setup.py`
2. **Serve** — Start `oberon_framework.py` and wait for inbound sessions
3. **Deliver** — Supply the generated executable or raw Python payload to the target
4. **Connect** — A session appears automatically in the C² console
5. **Operate** — Execute commands, deploy modules, and maintain access

---

## ❗ Disclaimer

> **⚠️ EDUCATIONAL PURPOSE ONLY**
>
> **Oberon Framework** is developed exclusively for **educational purposes**, **authorized penetration testing**, and **security research** in controlled environments.
>
> - ✅ Use only on systems you own or have **explicit written permission** to test
> - ✅ Intended for learning cybersecurity concepts and defensive strategies
> - ❌ **Any unauthorized or malicious use is strictly prohibited**
> - ❌ Do not use this tool for illegal activities or unauthorized access
>
> **You are solely responsible for your actions.** The developers assume no liability for misuse of this framework.

---

## 📄 License

Distributed under the MIT License. See the LICENSE file for more details.
