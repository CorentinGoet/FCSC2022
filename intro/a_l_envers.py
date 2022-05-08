"""
@author Corentin Goetghebeur (github.com/CorentinGoet)

Python script for the FCSC 2022 à l'envers challenge.
"""

from pwn import *   # library used to connect to the server
import time

# Connection parameters
HOST = "challenges.france-cybersecurity-challenge.fr"
PORT = 2000


def main():
    # Establish connection with the server
    c = remote(HOST, PORT)
    while True:
        try:
            time.sleep(0.5)
            c.recvuntil(b'> ')
            word = c.recvline()[:-1]    # word sent by the server
            rev_word = word[::-1]       # reversed word
            print(f"Received: {word}, Sent: {rev_word}")
            c.sendline(rev_word)
        except EOFError as e:
            print(str(c.recv()))
            break


if __name__ == '__main__':
    main()
