from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from typing import Optional


class Decryptor:
    """
    A class to handle decryption of data using RSA and AES algorithms.

    Attributes:
        private_key (RSAPrivateKey): The RSA private key used for decryption.
    """

    def __init__(self, private_key_path: str, password: Optional[bytes] = None):
        """
        Initialize the Decryptor with a RSA private key.

        Args:
            private_key_path (str): Path to the RSA private key file.
            password (Optional[bytes]): Password for the encrypted private key file.
        """
        try:
            with open(private_key_path, "rb") as key_file:
                try:
                    self.private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=password,
                        backend=default_backend()
                    )
                except ValueError as e:
                    print(f"Error loading private key: {e}")
                    raise
                except TypeError as e:
                    print(f"Incorrect password for private key: {e}")
                    raise
        except FileNotFoundError:
            print(f"Private key file not found: {private_key_path}")
            raise
        except IOError as e:
            print(f"IO error occurred: {e}")
            raise

        print(f"RSA key size: {self.private_key.key_size} bits")

    def decrypt_session_key(self, encrypted_key: str) -> Optional[bytes]:
        """
        Decrypt an RSA encrypted session key.

        Args:
            encrypted_key (str): The base64-encoded encrypted session key.

        Returns:
            Optional[bytes]: The decrypted session key or None if decryption fails.
        """
        try:
            decoded_key = base64.b64decode(encrypted_key)
            return self.private_key.decrypt(
                decoded_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except ValueError as e:
            print(f"Error in decrypting session key: {e}")
            return None

    @staticmethod
    def aes_decrypt(session_key: bytes, data: str, iv: str) -> Optional[bytes]:
        """
        Decrypt data using AES algorithm.

        Args:
            session_key (bytes): The session key for AES decryption.
            data (str): The base64-encoded data to be decrypted.
            iv (str): The base64-encoded initialization vector for AES decryption.

        Returns:
            Optional[bytes]: The decrypted data or None if decryption fails.
        """
        try:
            decipher = Cipher(
                algorithms.AES(session_key),
                modes.CBC(base64.b64decode(iv)),
                backend=default_backend()
            )
            decryptor = decipher.decryptor()
            return decryptor.update(base64.b64decode(data)) + decryptor.finalize()
        except Exception as e:
            print(f"Error during AES decryption: {e}")
            return None

    def execute(self, encoded_encrypted_session_key: str, encoded_encrypted_data: str, encoded_iv: str) -> str:
        """
        Execute the decryption process.

        Args:
            encoded_encrypted_session_key (str): Base64-encoded encrypted session key.
            encoded_encrypted_data (str): Base64-encoded encrypted data.
            encoded_iv (str): Base64-encoded initialization vector.

        Returns:
            str: Decrypted data as a string, or an error message.
        """
        decrypted_session_key = self.decrypt_session_key(encoded_encrypted_session_key)

        if decrypted_session_key is not None:
            decrypted_data = self.aes_decrypt(decrypted_session_key, encoded_encrypted_data, encoded_iv)
            if decrypted_data is not None:
                return decrypted_data.decode('utf-8')
            else:
                return "AES decryption failed"
        else:
            return "RSA decryption of session key failed"


def main():
    decryptor = Decryptor("private-key.pem")

    encoded_encrypted_session_key = "VtVSUzoxeg0xi41ffrjlt0tAt+fyQIrnSfYiQbQxtbqhHk9/z6qFQv1GedqmXrl24eI+ydJOu6iMwLb2UK6z7yt7Hd2Q36eO+1xuIHiW9jNA2SeiSpeqFgGWuTDgjmbbC6GJGhT/AosCAv6Pzm5fPHDmg5NQL6B8M6c6Jf5HSqXvzHEgUMeO1Yi5AG0pnuwOST45ZtoMlFM7glpP3fow0ql8v1E5n0QUcgI36PHSgjq56PNTq+h9sWBoMgZ1OXpOBTrWbCu7+Gr1wNGpGbL90oT0jjzPrn4/dam4brTy4w2NZHYHl35FMaRQdvJx00WptxTRDTIUTy8suHjjRcndEw=="
    encoded_encrypted_data = "Rm2N600M6QPA02lUDQZG3w=="
    encoded_iv = "kwB9bgAEwiQLk6pE2QCysQ=="

    result = decryptor.execute(encoded_encrypted_session_key, encoded_encrypted_data, encoded_iv)
    print(result)


if __name__ == "__main__":
    main()