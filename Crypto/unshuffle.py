"""
@author Corentin Goetghebeur (github.com/CorentinGoet)

Python script to solve the FCSC 2022 shuffled challenge
"""

import random


def unshuffle(shuffled_msg, seed):
    """
    Unshuffles a shuffled list knowing the seed.
    """
    l = list(shuffled_msg)
    ind = list(range(len(l)))
    random.seed(seed)
    random.shuffle(ind)
    output = [' ']*len(l)
    for i in range(len(l)):
        output[ind[i]] = l[i]

    return ''.join(output)


def main():
    output = "f668cf029d2dc4234394e3f7a8S9f15f626Cc257Ce64}2dcd93323933d2{F1a1cd29db"
    for seed in range(256):
        flag = unshuffle(output, seed)
        if 'FCSC' in flag:
            print(flag)


if __name__ == '__main__':
    main()

