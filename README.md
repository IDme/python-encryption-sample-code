# ID.me Sample Python Decryption Web App

This is a sample Python Web App that:
- Generates a key pair (public certificate and private key)
- Generates encoded and encrypted session key
- Generates encoded IV
- Generates encoded and encrypted data to use for testing purposes
- Decrypts the provided data

## Generate Test Session Key, IV, and Data

Run the following command to generate test data:

```bash
python3 generate_test_data.py
```

> Note: This script will generate a `private-key.pem` file within your directory.

### Example Response

```
Private Key (PEM):
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAkzj+EDGwUJa3MmmvBHmLoLyKx/uNyTtP6pPBndBNjdd/rBZf
...
-----END RSA PRIVATE KEY-----

Encrypted Session Key (Base64):
Id8ag5EpeTrVZkKKJbv61H5jHNInwsAD/nS1FPtN9TjyeIhPs5zoqA2eA1z7hZMR
...

Encrypted Data (Base64):
VQPEpUsAdXE3Qn8sZbb8MQ==

IV (Base64):
kwB9bgAEwiQLk6pE2QCysQ==
```

## Update `decrypt.py` Values

Plug the outputs above into the main method in `decrypt.py`:

```python
encoded_encrypted_session_key = "INSERT_ENCODED_ENCRYPTED_SESSION_KEY"
encoded_encrypted_data = "INSERT_ENCODED_ENCRYPTED_DATA"
encoded_iv = "INSERT_ENCODED_IV"
```

## Decrypt Response

Run the following command to decrypt the data:

```bash
python3 decrypt.py
```

### Example Response

```
RSA key size: 2048 bits
encryptme!
```

You will see that the encrypted data from `generate_test_data.py` is decrypted in the output of `decrypt.py`.