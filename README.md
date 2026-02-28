# Sentinel V14 - Modular Architecture

## Project Structure

```
sentinel/
├── main.py                 # CLI entry point - command routing
├── config.py              # Configuration & constants (from env)
├── utils.py               # Shared utility functions
├── password_analyzer.py   # Single password analysis & generation
├── system_audit.py        # System-wide auditing & cracking
├── pam_enforcer.py        # PAM management & user creation
├── ai_chat.py             # AI chat interface
├── sentinel.py            # (Original monolithic - can be removed)
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

## Features

### 1. Password Analysis (`--analyze`)
- Length and character validation
- Have I Been Pwned breach check
- Entropy estimation (zxcvbn)
- Machine-generated pattern detection
- Optional John the Ripper simulation

### 2. System Audit (`--audit`)
- `/etc/shadow` analysis with grading
- SSH hardening checks
- Password cracking with John
- HTML report export
- AI-powered fixes (whitelisted commands only)

### 3. PAM Enforcer (`--pam`)
- PAM configuration review
- Hook installation/uninstall
- AI recommendations

### 4. Secure User Creation (`--create-user USER`)
- Validates password strength
- Checks breach database
- Sets expiration policies

### 5. Password Generator (`--generate`)
- Cryptographically strong generation
- Verifies against breach database
- Customizable character sets

### 6. AI Chat (`--chat`)
- Interactive conversation
- Security advice

## Installation

```bash
cd ~/Desktop/sentinel
pip install -r requirements.txt
```

## Usage

```bash
# Analyze a password
python3 main.py --analyze

# Generate a strong password
python3 main.py --generate

# Full system audit (requires root)
sudo python3 main.py --audit --time 60

# Create secure user (requires root)
sudo python3 main.py --create-user newuser

# Manage PAM (requires root)
sudo python3 main.py --pam

# AI chat
export GEMINI_API_KEY=your_key
python3 main.py --chat
```

## Module Breakdown

### `config.py`
- API key from environment
- System file paths
- Command whitelist for AI
- Default settings

### `utils.py`
- Hash type identification
- HIBP API queries
- Machine-generated pattern detection
- Password strength scoring

### `password_analyzer.py`
- Single password testing
- Brute-force simulation
- Password generation
- Entropy analysis

### `system_audit.py`
- Shadow file analysis
- SSH configuration auditing
- Password cracking orchestration
- HTML report generation
- Safe AI command execution

### `pam_enforcer.py`
- PAM configuration parsing
- Hook management
- Secure user creation
- Test user setup
- PAM password validation

### `ai_chat.py`
- Interactive chat loop
- Terminal input/output

### `main.py`
- Argument parsing
- Command routing
- AI initialization

## Security Features

✅ **API Key in Environment** - No hardcoded secrets
✅ **Command Whitelisting** - AI fixes validated before execution
✅ **Explicit Error Handling** - No silent failures
✅ **Type Hints** - Better code clarity
✅ **Modular Design** - Easy to test and maintain
✅ **Safe subprocess** - No dangerous shell operations

## Troubleshooting

**ImportError: No module named...**
- Run from sentinel directory: `cd ~/Desktop/sentinel && python3 main.py`

**Root required error**
- Use sudo for: `--audit`, `--create-user`, `--pam`, `--setup-test`

**John the Ripper not found**
- Ubuntu/Debian: `sudo apt-get install john`
- Fedora/RHEL: `sudo dnf install john`

**AI features disabled**
- Set API key: `export GEMINI_API_KEY=your_key_here`
