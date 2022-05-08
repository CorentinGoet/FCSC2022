# Daddy Morse
Category: Hardware

## Challenge
For this challenge, we have to send: 'CAN I GET THE FLAG' to the server
encoded in morse code, modulated by amplitude and then encoded in base 64.

For the amplitude modulation:
- sample rate: 24 kHz
- timing for morse dot: 1 ms
- timing for morse dash: 5 ms
- time between letters: 5 ms
- time between words: 20 ms

To help with this challenge, we get:
- [server-side source code](server_d.py)
- [client example](client_d.py)
- [am signal example](signal_d.iq)

## Write-up

To solve this challenge I built a Python script (available [here](daddy_morse.py))
by using the client example and the intro challenge [baby morse](/intro/baby_morse.md).

The most important functions in this script are:

### The morse encoding function
This function encodes a string into Morse code using the Morse dictionnary 
called _alphabet_ found in the server code.
```python
def morse_encode(msg: str):
    """
    Encodes a str message into morse code
    """
    cipher = []

    for word in msg.split(' '):
        for char in word:
            cipher.append(alphabet.get(char))
            cipher.append('_')
        cipher[-1] = ' '
    return "".join(cipher).strip()
```
- the AM encoding function:
This function builds the signal by matching each Morse character (dot, dash and separators)
to a list of values of a variable length.
```python
def am_encode(msg: str):
    """
    Encodes a morse message into AM modulation
    """
    signal = []
    for i, char in enumerate(msg):
        if char == ".":
            signal += [1 + 1j] * int(SAMP_RATE * TIMING_DOT)
        elif char == "-":
            signal += [1 + 1j] * int(SAMP_RATE * TIMING_DASH)
        elif char == ' ':
            # Space between words
            signal += [0 + 0j] * int(SAMP_RATE * TIMING_SPACE)
        elif char == "_":
            # separation between letters
            signal += [0 + 0j] * int(SAMP_RATE * TIMING_SEP_LETTER)
        else:
            print(f"Caractère non conforme au code morse {char} dans le message {msg}.")

        if i < len(msg) - 1 and char in ['.', '-'] and msg[i+1] in ['-', '.']:
            # Separation between characters of a letter
            signal += [0 + 0j] * int(SAMP_RATE * TIMING_DOT)

    return np.array(signal, dtype=np.complex64)
```
- the main:
```python
def main():
    msg = 'CAN I GET THE FLAG'
    
    # Encode to morse
    morse_msg = morse_encode(msg)
    print(f"Message: {msg}, Morse encoded: {morse_msg}")
    
    # encode to am modulation
    signal = am_encode(morse_msg)
    
    # Encoded to base 64
    encoded_signal = base64.b64encode(signal.tobytes())
    
    # Test decoding
    decoded = am_decode(signal)
    decoded_msg = morse_decode(decoded)
    print(f"Decoded signal - Morse: {decoded}, Final: {decoded_msg}")

    # Send to the server
    c = remote(HOST, PORT)
    c.recvuntil(b"> ")
    c.sendline(encoded_signal)
    print(c.recvline())
```



