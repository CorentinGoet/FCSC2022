from pwn import *
import numpy as np
import base64
import matplotlib.pyplot as plt

HOST = "challenges.france-cybersecurity-challenge.fr"
PORT = 2252

SAMP_RATE = 24e3
MAX_LEN = 256000

FREQ_HIGH = 5e3
FREQ_LOW = 1e3

TIMING_DOT = 1/1000
TIMING_DASH = 5/1000
TIMING_SEP_LETTER = 5/1000
TIMING_SPACE = 20/1000
TIMING_SEP_CHAR = 1/1000



alphabet = { 'A':'.-', 'B':'-...',
            'C':'-.-.', 'D':'-..', 'E':'.',
            'F':'..-.', 'G':'--.', 'H':'....',
            'I':'..', 'J':'.---', 'K':'-.-',
            'L':'.-..', 'M':'--', 'N':'-.',
            'O':'---', 'P':'.--.', 'Q':'--.-',
            'R':'.-.', 'S':'...', 'T':'-',
            'U':'..-', 'V':'...-', 'W':'.--',
            'X':'-..-', 'Y':'-.--', 'Z':'--..',
            '1':'.----', '2':'..---', '3':'...--',
            '4':'....-', '5':'.....', '6':'-....',
            '7':'--...', '8':'---..', '9':'----.',
            '0':'-----', ', ':'--..--', '.':'.-.-.-',
            '?':'..--..', '/':'-..-.', '-':'-....-',
            '(':'-.--.', ')':'-.--.-'}

rev_alphabet = {v:k for k,v in alphabet.items()}


def morse_encode(msg: str):
    """
    Chiffre un message en utilisant le code morse.
    """
    cipher = []

    for word in msg.split(' '):
        for char in word:
            cipher.append(alphabet.get(char))
            cipher.append('_')
        cipher[-1] = ' '
    return "".join(cipher).strip()

def morse_decode(msg):
    res = ""
    for word in msg.split(" "):
        for letter in word.split("_"):
            if letter in rev_alphabet:
                res += rev_alphabet[letter]
            elif letter == "":
                continue
            else:
                raise ValueError(f"Not a correct Morse character: {letter}")
        res += " "
    return res

def decode_sample(sample):
    # Frequency should not be too far from the expected values
    if abs(sample-FREQ_HIGH) < 100:
        return 1
    elif abs(sample-FREQ_LOW) < 100:
        return 0
    else:
        raise ValueError("Frequency of your signal is off, try again")

# Compute the timing difference between the provided timing and the expected one
def diff(nb_samples, expected_timing):
    expected_nb_samples = expected_timing * SAMP_RATE
    d = abs(expected_nb_samples-nb_samples) / expected_nb_samples
    return d

def fm_decode(s):
    # Get instantaneous frequency
    freq = np.diff(np.unwrap(np.angle(s)))
    freq = (SAMP_RATE / (2*np.pi)) * freq

    timings = []

    current = decode_sample(freq[0])
    cnt = 1
    for c in freq[1:]:
        new = decode_sample(c)
        if new == current:
            cnt += 1
            continue
        else:
            timings.append(cnt)
            current = new
            cnt = 1
    timings.append(cnt)

    data = ""
    current_symbol = decode_sample(freq[0])
    for timing in timings:
        # This decoder allows up to 10% imprecision in timings.
        # That is, to receive a dot of 1ms, the decoder allows
        # pulses that last between 0.9 and 1.1ms.
        # To receive a dash of 5ms, the decoder allows pulses
        # that last between 4.5 and 5.5ms.
        if current_symbol == 1:
            current_symbol = 0
            if diff(timing, TIMING_DOT) < 0.10:
                data += "."
            elif diff(timing, TIMING_DASH) < 0.10:
                data += "-"
        else:
            current_symbol = 1
            if diff(timing, TIMING_SEP_LETTER) < 0.10:
                data += "_"
            elif diff(timing, TIMING_SPACE) < 0.10:
                data += " "
            else:
                # A correct decoder should handle this case,
                # not done here to keep the code simple
                continue
    return data


def generate_carrier(freq:float = 1000.0, duration: float = 1/1000) -> np.ndarray:
    """
    Génère une onde porteuse de fréquence et durée données en paramètres.

    Cette fonction utilise une fréquence d'échantillonage de SAMP_RATE = 24e3 mesures par secondes

    :param freq: fréquence en Hz de la porteuse à générer
    :param duration: durée en secondes du signal
    :return: tableau numpy contenant les valeurs de la porteuse.
    """

    SAMP_RATE = 24e3

    signal = np.arange(duration * SAMP_RATE)
    signal = 2 * np.pi * signal * freq / SAMP_RATE
    real = np.cos(signal)
    img = np.sin(signal)
    carrier = real + 1j * img
    return carrier


def fm_encode(msg: str):
    """
    Modulation en fréquence du message encoddé en morse
    """
    signal = []
    for i, word in enumerate(msg.split(' ')):
        for j, char in enumerate(word):
            if char == '.':
                # Porteuse pure de fréquence 5 kHz pendant 1 ms
                signal += list(generate_carrier(FREQ_HIGH, TIMING_DOT))
                signal += list(generate_carrier(FREQ_LOW, TIMING_SEP_CHAR))
            elif char == '-':
                # Porteuse pure de fréquence 5kHz pendant 5 ms
                signal += list(generate_carrier(FREQ_HIGH, TIMING_DASH))
                signal += list(generate_carrier(FREQ_LOW, TIMING_SEP_CHAR))
            elif char == '_':
                # séparation entre les lettres
                # Porteuse pure de fréquence 1 kHz pendant 5 ms
                signal = signal[:-int(SAMP_RATE*TIMING_SEP_CHAR)]
                signal += list(generate_carrier(FREQ_LOW, TIMING_SEP_LETTER))
            else:
                raise ValueError(f"Message non conforme - caractère interdit : {char}")
        signal += list(generate_carrier(FREQ_LOW, TIMING_SPACE))

    signal = signal[:-int(SAMP_RATE*TIMING_SEP_CHAR)]    # retire la derniere séparation entre caractères d'une lettre
    signal = signal[:-int(SAMP_RATE*TIMING_SPACE)]  # retire le dernier espace
    return np.array(signal, dtype=np.complex64)


def main():
    msg = "CAN I GET THE FLAG"
    morse_msg = morse_encode(msg)
    fm_msg = fm_encode(morse_msg)
    print(f"Message: {msg}\nMorse: {morse_msg}\nFM: {fm_msg}")



    # hello_signal = np.fromfile("signal.iq", dtype=np.complex64)
    # print(f"Hello Signal: {hello_signal}")
    #
    # print(f"Types - ref: {type(hello_signal)} generated {type(fm_msg)}")
    # print(f"shape of encoded message: {fm_msg.shape}, shape of reference message: {hello_signal.shape}")
    # plt.figure()
    # plt.title("HELLO de référence")
    # plt.plot(hello_signal)
    #
    # plt.figure()
    # plt.title("HELLO généré")
    # plt.plot(fm_msg)
    #
    # plt.figure()
    # plt.title('différences entre HELLO fourni et HELLO généré')
    # plt.plot(hello_signal-fm_msg[:1476])
    # plt.show()
    #
    #print(f"shape of encoded message: {fm_msg.shape}, shape of reference message: {hello_signal.shape}")
    encoded_signal = base64.b64encode(fm_msg.tobytes())


    signal = np.frombuffer(base64.b64decode(encoded_signal), dtype = np.complex64)
    decoded = fm_decode(signal)
    deciphered = morse_decode(decoded)
    print(f"FM decoded: {decoded}\nMorse decoded: {deciphered}")

    # Communication avec le server FCSC
    c = remote(HOST, PORT)
    c.recvuntil(b"> ")
    c.sendline(encoded_signal)
    print(c.recvline())

    # flag : FCSC{490b88345a22d35554b3e319b1200b985cc7683e975969d07841cd56dd488649}