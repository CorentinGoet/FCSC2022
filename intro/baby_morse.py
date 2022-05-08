"""
@author Corentin Goetghebeur (github.com/CorentinGoet)

Python script for the FCSC 2022 baby_morse challenge.
"""

from pwn import *
import numpy as np

# Connection parameters
HOST = "challenges.france-cybersecurity-challenge.fr"
PORT = 2250

alphabet = {'A': '.-', 'B': '-...',
            'C': '-.-.', 'D': '-..', 'E': '.',
            'F': '..-.', 'G': '--.', 'H': '....',
            'I': '..', 'J': '.---', 'K': '-.-',
            'L': '.-..', 'M': '--', 'N': '-.',
            'O': '---', 'P': '.--.', 'Q': '--.-',
            'R': '.-.', 'S': '...', 'T': '-',
            'U': '..-', 'V': '...-', 'W': '.--',
            'X': '-..-', 'Y': '-.--', 'Z': '--..',
            '1': '.----', '2': '..---', '3': '...--',
            '4': '....-', '5': '.....', '6': '-....',
            '7': '--...', '8': '---..', '9': '----.',
            '0': '-----', ', ': '--..--', '.': '.-.-.-',
            '?': '..--..', '/': '-..-.', '-': '-....-',
            '(': '-.--.', ')': '-.--.-'}

rev_alphabet = {v: k for k, v in alphabet.items()}


def morse_encode(msg: str):
    """
    Encodes a message into morse code.
    """
    cipher = []

    for word in msg.split(' '):
        for char in word:
            cipher.append(alphabet.get(char))
            cipher.append(' ')
        cipher[-1] = ' '
    return "".join(cipher).strip()


def main():
    # Connect to the server
    c = remote(HOST, PORT)

    # Wait for the server to be ready
    c.recvuntil(b'> ')

    msg = "FLAG"
    morse_msg = morse_encode(msg)
    print(f"Message: {msg}, Morse encoded: {morse_msg}")
    c.sendline(bytes(morse_msg, 'utf8'))

    # Wait for server response
    flag = str(c.recv(), 'utf8')
    print(flag)


if __name__ == '__main__':
    main()
