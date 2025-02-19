# simple_keystore

This is a simple key storage solution for development or on-prem use. Use secrets/other builtin more-secure provider methods for production.

Uses an SQLite database to store/retrieve encrypted keys with metadata including expiration dates. 

Uses PostgreSQL to track key usage.

There is a Dockerfile and .devcontainer for use with VSCode. 

## Requirements

If you are going to use the key usage / rate tracking (SKSRateTracker), you will need PostgreSQL. This is not necessary if just using SimpleKeystore.

```bash
sudo apt-get install -y postgresql
sudo service postgresql start 
sudo systemctl enable postgresql # If you want it to start on boot
```

## Installation
```bash
pip install simple_keystore
```
## Usage

You can set the encryption key either via environment variable or as an entry in your .netrc where the password is the key.

```bash
export SIMPLE_KEYSTORE_KEY = "myencryptionkeyphrase"
```

Create an SQLite DB to store keys in python:
```python
ks = SimpleKeyStore(KEYSTORE_FILE_NAME)

# See tests/test_simple_keystore.py for adding keys, etc.
```

Add/Remove keys manually / intractively in bash with:
```bash
manage_simple_keys <KEYSTORE_FILE_NAME>
```