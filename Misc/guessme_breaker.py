"""
@author Corentin Goetghebeur (github.com/CorentinGoet)
"""

from pwn import *

HOST = "challenges.france-cybersecurity-challenge.fr"
PORT = 2001


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


if __name__ == '__main__':
    main()
