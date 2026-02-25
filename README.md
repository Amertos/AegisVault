<div align="center">

# 🔐 AegisVault

**A secure, offline-first password vault built with Python.**

![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![CustomTkinter](https://img.shields.io/badge/CustomTkinter-5.x-6C63FF?style=for-the-badge)
![Cryptography](https://img.shields.io/badge/AES--128--CBC-Fernet-4F8EF7?style=for-the-badge&logo=letsencrypt&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-3EC98A?style=for-the-badge)

</div>

---

## ✨ Features

- 🔒 **Zero-knowledge encryption** — master password is never stored anywhere
- 🛡️ **AES-128-CBC + HMAC-SHA256** via Fernet (authenticated encryption)
- 🔑 **PBKDF2HMAC** key derivation — 480 000 iterations, SHA-256
- 🗄️ **Fully encrypted vault** — `vault.json` is unreadable without the correct password
- 🎲 **Strong password generator** — cryptographically secure (20 chars)
- 📋 **Auto-clearing clipboard** — password erased after 30 seconds
- 🔍 **Real-time search** across all saved entries
- 👁️ **Show / Hide** password masking per entry
- 🗑️ **Delete with confirmation** dialog
- 🌑 **Dark mode UI** powered by CustomTkinter

---

## 🛡️ Security Architecture

```
Master Password + Salt
        │
        ▼
  PBKDF2HMAC (SHA-256, 480 000 iters)
        │
        ▼
   32-byte raw key
        │
        ▼
  base64url encode
        │
        ▼
   Fernet key  ──►  AES-128-CBC + HMAC-SHA256
        │
        ▼
 vault.json (full ciphertext — unreadable in Notepad)
```

| File | Contents | Secret? |
|------|----------|---------|
| `salt.bin` | 32 random bytes (generated once) | ❌ Not secret |
| `vault.json` | Fully encrypted JSON blob | ✅ Ciphertext only |
| Master password | **Never written anywhere** | 🔐 Lives in RAM only |

---

## 📦 Installation

```bash
pip install customtkinter cryptography pyperclip
```

> Requires **Python 3.12+**

---

## 🚀 Usage

```bash
python password_manager.py
```

**First launch** — create a master password (min. 8 characters).  
**Subsequent launches** — enter your master password to unlock the vault.

---

## 📁 File Structure

```
.
├── password_manager.py   # Entire application (single file)
├── vault.json            # Auto-generated — encrypted vault
└── salt.bin              # Auto-generated — PBKDF2 salt
```

---

## 🏗️ Architecture

| Class | Responsibility |
|-------|---------------|
| `CryptoManager` | PBKDF2HMAC key derivation + Fernet encrypt / decrypt |
| `VaultManager` | CRUD operations on the encrypted JSON vault |
| `LoginScreen` | First-run setup or unlock flow (CTkinter frame) |
| `Dashboard` | Main UI — add, search, copy, delete passwords |
| `PasswordRow` | Single entry widget with Show/Hide, Copy, Delete |

---

## 🖼️ Screenshots

> Light/dark screenshots can be added here.

---

## ⚠️ Important Notes

- **Do not delete `salt.bin`** — without it, the vault becomes permanently inaccessible.
- There is **no "forgot password"** feature by design. If you lose your master password, your data is gone.
- The vault is **local only** — no cloud sync, no telemetry.

---

## 📄 License

MIT — do whatever you want, just don't blame me if you forget your master password.

