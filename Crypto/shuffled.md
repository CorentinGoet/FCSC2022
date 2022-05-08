# Shuffled

Category: crypto

## Challenge

For this challenge, we get a flag that has been randomly shuffled.

We get:
- the [code](shuffled.py) used to shuffle the flag
- the [output](output.txt) of this code

## Write-up

In the source code of the shuffler, we can see that the seed used to randomly
shuffle the flag is chosen randomly between 0 and 256.

The solution I chose is to unshuffle the shuffled flag for each of these 
possibilities to find all possible flags. (in this [python script](unshuffle.py))
Since the flag starts with FCSC{, it is quite easy to find which of the results 
is the correct one.

```python
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
```

