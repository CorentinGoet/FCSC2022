# Baby Morse
Categories: intro, hardware

## Challenge
For this challenge, we have to send FLAG to the CTF server on a specific port.

```shell
nc challenges.france-cybersecurity-challenge.fr 2250
```

## Write-up
By reading the challenge name, we can guess that we have to send the word FLAG
in morse code to the server.
To translate into morse code and to communicate with the server, I used a Python script.
(available [here](baby_morse.py)).

```python
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
```

