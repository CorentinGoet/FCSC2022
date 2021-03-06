# Guess Me

Category: misc

## Challenge

For this challenge, we have 5 minutes to guess 16 random numbers.
After each guess the server answers:
- +1 if our guess is too low
- -1 if our guess is too high

We also get the [source code](guessme.py) for the server.

## Write-up

By looking into the server code, we find that the random numbers to guess
are between 0 and 2^64 - 1. Since there are so many different possibilities for
the guesses, I will use a binary search.

In the beginning, the limits are [0, 1<<64],
with each step, we guess the middle of the interval.

With this method, since there are 2^64 possibilities it takes 64 steps
to find each number.

I implemented this method into a [Python script](guessme_breaker.py).

```python
def main():
    """
    Main function

    Essai par recherche binaire du résultat.
    """
    c = remote(HOST, PORT)  # début de la connexion
    c.recvuntil(b"> ")
    num2guess = 16
    for i in range(16):
        a = (1 << 64) - 1  # borne haute de la recherche binaire
        b = 0  # borne basse
        step = 0
        mref = 0
        while True:

            if a - b == 1:      # pour éviter de rester coincé avec un intervalle de taille 1
                if mref == m:
                    m = a
                else:
                    m = b
                    mref = m
            else:
                m = (a + b) >> 1

            c.sendline(str(m))
            res = c.recvline()
            if res == b'+1\n':
                # la valeur recherchée est supérieur à notre essai
                b = m
            elif res == b'-1\n':
                # la valeur recherchée est inférieure à notre essai
                a = m + 1
            elif res == b'0\n':
                print('Nombre trouvé')
                print(c.recvline())
                if i < 15:
                    c.recvuntil(b"> ")
                break
            else:
                print(f"Valeur différente: {res}")
                print(c.recv())
                break
            step += 1
            print(f"Nb de num restant: {num2guess}, Essai n°{step} : [{b}, {a}]")
            c.recvuntil(b"> ")
        num2guess -= 1
    print(c.recv())
```

