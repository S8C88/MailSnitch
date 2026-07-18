# MailSnitch

SMTP reconnaissance tool. Banner grab, open relay testing, VRFY enumeration. Nothing fancy.

## Usage

```bash
# Banner grab
python3 mailsnitch.py -t mail.example.com --banner

# Open relay test  
python3 mailsnitch.py -t mail.example.com --relay-test

# VRFY a single user
python3 mailsnitch.py -t mail.example.com --vrfy root

# Enumerate users from wordlist
python3 mailsnitch.py -t mail.example.com --enumerate users.txt
```

## License

MIT
