# 🔐 Loggedium

**Loggedium** is a Python-based **Password Strength Checker** developed as part of my cybersecurity learning journey.  
The goal of this project is to build **practical, real-world security skills** while designing a tool that evaluates password strength using modern security concepts.

This project focuses not just on *length and complexity*, but also on **real attack models** such as data breaches and brute-force feasibility.

---

## 🎯 Project Motivation

As an aspiring cybersecurity professional, I wanted to move beyond theoretical concepts and build a **hands-on security tool** that reflects how passwords are evaluated in real systems.

KeyFortify helps users understand:
- Why certain passwords are weak
- How attackers think
- How breach exposure impacts password security

---

## 🔹 Current Features

### 🔑 Inputs
- **Password** to be evaluated
- **Website / Application name** where the password is used

### 🛡️ Security Checks
- ✅ Detects if the password contains the website or company name (including common aliases)
- ✅ Checks whether the password has appeared in known data breaches using the **Have I Been Pwned** API (k-Anonymity model)
- ✅ Detects common and weak passwords using a static blocklist

### 📊 Strength Analysis
- Evaluates password strength based on:
  - Length
  - Character diversity (uppercase, lowercase, digits, symbols)
  - Contextual weaknesses
- Estimates **brute-force crack time** using realistic attacker assumptions
- Provides a clear strength rating:
  - `Very Weak`
  - `Weak`
  - `Moderate`
  - `Strong`

---

## 🧠 How It Works (High-Level)

- Passwords are **never sent in plaintext** to external services
- Breach detection uses **SHA-1 hashing + partial hash lookup**
- Crack time estimation models worst-case brute-force scenarios
- Strength scoring applies **hybrid logic**, penalizing:
  - Common passwords
  - Website name reuse
  - High breach frequency

---

## 🚀 Usage

### 1️⃣ Activate virtual environment
```bash
source .venv/bin/activate
python3 main.py