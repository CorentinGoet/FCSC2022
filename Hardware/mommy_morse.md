# Mommy Morse

Category: Hardware

## Challenge
For this challenge, we have to send 'CAN I GET THE FLAG' to the server
in Morse code, encoded using frequency modulation and then encoded in base 64.

(same challenge as [Daddy Morse](daddy_morse.md) but more difficult because of the
FM instead of AM)

For the frequency modulation:
- sample rate: 24 kHz
- dot: pure 5 kHz carrier for 1 ms
- dash: pure 5 kHz carrier for 5 ms
- space between letters: pure 1 kHz carrier for 5 ms
- space between words: pure 1 kHz carrier for 20 ms

To help with this challenge, we get:
- [server side code](server_m.py)
- [client example](client_m.py)
- [FM signal example](signal_m.iq)

## Write-up

For this challenge I built a Python script based on the one I used for the 
daddy morse challenge.

The most different parts are the ones used for the FM modulation:
`generate_carrier`, which generates a pure carrier of a given frequency and length,
and `fm_encode` which matches the morse characters with the carriers.

```python
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
```

```python
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
```