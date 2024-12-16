import string
import urllib.parse
import numpy as np
import re

ERROR_MESSAGE = "An error occurred during the decryption process."

class CipherUtils:

    @staticmethod
    def mod_inverse(a, m):
        """Returns the modular inverse of a with respect to m."""
        m0, x0, x1 = m, 0, 1
        if m == 1:
            return 0
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        if x1 < 0:
            x1 += m0
        return x1

    @staticmethod
    def decrypt_hill_cipher(cipher_text, matrix_key):
        """Decrypts the ciphertext using the Hill cipher with the provided key matrix."""
        try:
            matrix_key = np.array(matrix_key)
            determinant = int(np.round(np.linalg.det(matrix_key)))
            # Compute modular inverse of determinant
            determinant_inv = CipherUtils.mod_inverse(determinant, 26)
            # Calculate the inverse matrix
            matrix_key_inv = determinant_inv * np.round(determinant * np.linalg.inv(matrix_key)).astype(int) % 26
            cipher_vectors = [ord(char.upper()) - ord('A') for char in cipher_text if char.isalpha()]
            plain_vectors = []

            for i in range(0, len(cipher_vectors), len(matrix_key)):
                vector = np.array(cipher_vectors[i:i+len(matrix_key)])
                decrypted_vector = np.dot(matrix_key_inv, vector) % 26
                plain_vectors.extend(decrypted_vector.astype(int))

            decrypted_text = ''.join(chr(int(v) + ord('A')) for v in plain_vectors)

            return decrypted_text
        except Exception as ex:
            print(ERROR_MESSAGE, ex)

    @staticmethod
    def decrypt_caesar_cipher(input_text, shift_key):
        """Decrypt using Caesar cipher"""
        try:
            decrypted_text = ""
            for char in input_text:
                if not (char >= 'A' and char <= 'Z' or char >= 'a' and char <= 'z'):
                    decrypted_text += char
                elif ord(char.upper()) - shift_key < ord('A'):
                    decrypted_text += chr(ord('Z') - ord('A') + ord(char.upper()) + 1 - shift_key)
                else:
                    decrypted_text += chr(ord(char.upper()) - shift_key)
            return decrypted_text
        except (ValueError, IndexError, Exception) as ex:
            print(ERROR_MESSAGE, ex)

    @staticmethod
    def decrypt_rot13_cipher(input_text):
        """Decrypt using ROT13 cipher"""
        try:
            decrypted_text = ""
            for char in input_text:
                if string.ascii_lowercase[:13].find(char, 0) != -1:
                    pos = string.ascii_lowercase[:13].find(char, 0)
                    opposite = string.ascii_lowercase[13:]
                    decrypted_text += opposite[pos]
                elif string.ascii_lowercase[13:].find(char, 0) != -1:
                    pos = string.ascii_lowercase[13:].find(char, 0)
                    opposite = string.ascii_lowercase[:13]
                    decrypted_text += opposite[pos]
                elif string.ascii_uppercase[:13].find(char, 0) != -1:
                    pos = string.ascii_uppercase[:13].find(char, 0)
                    opposite = string.ascii_uppercase[13:]
                    decrypted_text += opposite[pos]
                elif string.ascii_uppercase[13:].find(char, 0) != -1:
                    pos = string.ascii_uppercase[13:].find(char, 0)
                    opposite = string.ascii_uppercase[:13]
                    decrypted_text += opposite[pos]
                else:
                    decrypted_text += char
            return decrypted_text
        except (ValueError, IndexError) as ex:
            print(ERROR_MESSAGE, ex)

    @staticmethod
    def decrypt_rot5_cipher(input_text):
        """Decrypt using ROT5 cipher"""
        decrypted_text = ""
        for char in input_text:
            if char.isdigit():
                index = int(char) - 5
                while index < 0:
                    index += 10
                decrypted_text += str(index % 10)
            else:
                decrypted_text += char
        return decrypted_text

    ## Below this are the functions for decoding the Encoded text

    @staticmethod
    def decode_binary_data(binary_str: str) -> str:
        """Returns the decrypted text for Binary."""
        if " " not in binary_str and len(binary_str) > 8:
            raise ValueError("Input binary string seems to be missing spaces between bytes.")
        binary_translated = "".join(chr(int(i, 2)) for i in binary_str.strip().split(" "))
        return binary_translated

    @staticmethod
    def decode_hex_data(hex_str: str) -> str:
        """Returns the decrypted text for Hexadecimal."""
        if " " not in hex_str and len(hex_str) > 2:
            raise ValueError("Input hexadecimal string seems to be missing spaces between bytes.")
        hexadecimal_translated = "".join(chr(int(i, 16)) for i in hex_str.strip().split(" "))
        return hexadecimal_translated

    @staticmethod
    def decode_octal_data(octal_str: str) -> str:
        """Returns the decrypted text for Octal."""
        if " " not in octal_str and len(octal_str) > 3:
            raise ValueError("Input octal string seems to be missing spaces between bytes.")
        octal_translated = "".join(chr(int(i, 8)) for i in octal_str.strip().split(" "))
        return octal_translated

    @staticmethod
    def decode_ascii_data(ascii_str: str) -> str:
    
    # Check for HTML entities and extract numbers
     if "&#" in ascii_str:
        ascii_str = " ".join(re.findall(r'&#(\d+);', ascii_str))
    
     if " " not in ascii_str:
        raise ValueError("Input ASCII string seems to be missing spaces between numbers.")
    
     ascii_translated = "".join(chr(int(i)) for i in ascii_str.split(" "))
     return ascii_translated

    @staticmethod
    def decode_url_data(url_str: str) -> str:
        """Returns the decrypted text for URL Encoding."""
        return urllib.parse.unquote(url_str)

    @staticmethod
    def decode_unicode_data(unicode_str: str) -> str:
        """Returns the decrypted text for Unicode."""
        return "".join(chr(int(uni, 16)) for uni in str(unicode_str).split(" "))


import math

def menu():
    print("Welcome to the Cipher and Decoding Tool!")
    print("Choose an option from the menu below:")

    print("1. Caesar Cipher Decryption")
    print("2. ROT13 Cipher Decryption")
    print("3. Binary Decoding")
    print("4. Hexadecimal Decoding")
    print("5. Octal Decoding")
    print("6. ASCII Decoding")
    print("7. URL Decoding")
    print("8. Unicode Decoding")
    
    choice = int(input("Enter the number of the option you want to choose: "))

    if choice == 1:
        input_text = input("Enter the text to decrypt: ")
        shift_key = int(input("Enter the Caesar cipher key (shift value): "))
        decrypted_text = CipherUtils.decrypt_caesar_cipher(input_text, shift_key)
        print("Decrypted Text:", decrypted_text)

    elif choice == 2:
        input_text = input("Enter the text to decrypt using ROT13: ")
        decrypted_text = CipherUtils.decrypt_rot13_cipher(input_text)
        print("Decrypted Text:", decrypted_text)

    elif choice == 3:
        binary_str = input("Enter the binary string (with spaces between bytes): ")
        decrypted_text = CipherUtils.decode_binary_data(binary_str)
        print("Decoded Text:", decrypted_text)

    elif choice == 4:
        hex_str = input("Enter the hexadecimal string (with spaces between bytes): ")
        decrypted_text = CipherUtils.decode_hex_data(hex_str)
        print("Decoded Text:", decrypted_text)

    elif choice == 5:
        octal_str = input("Enter the octal string (with spaces between bytes): ")
        decrypted_text = CipherUtils.decode_octal_data(octal_str)
        print("Decoded Text:", decrypted_text)

    elif choice == 6:
        ascii_str = input("Enter the ASCII string (with spaces between numbers): ")
        decrypted_text = CipherUtils.decode_ascii_data(ascii_str)
        print("Decoded Text:", decrypted_text)

    elif choice == 7:
        url_str = input("Enter the URL-encoded string: ")
        decoded_text = CipherUtils.decode_url_data(url_str)
        print("Decoded Text:", decoded_text)

    elif choice == 8:
        unicode_str = input("Enter the Unicode string (with spaces between hex values): ")
        decoded_text = CipherUtils.decode_unicode_data(unicode_str)
        print("Decoded Text:", decoded_text)

    else:
        print("Invalid choice. Please select a valid option.")

    another = input("Do you want to try another operation? (y/n): ")
    if another.lower() == 'y':
        menu()
    else:
        print("Thank you for using the Cipher and Decoding Tool!")

# Run the menu function
menu()

