# À l'envers
 
Categories: intro, programming

## Challenge
For this challenge you have to connect to a specific port of the CTF server
and send the strings you receive backwards until you receive the flag.

```shell
nc challenges.france-cybersecurity-challenge.fr 2000
```

## Write-up

To solve this problem, I used a Python script to managed both the
connection and the reversing of the strings.
You can find the script [here](a_l_envers.py).

To handle the connection to the server I used the `pwn` library.

```python
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
```
