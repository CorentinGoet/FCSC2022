# QR code

Categories: intro, misc

## Challenge
For this challenge, we have to read the information contained in a
faulty QR code:
![faulty_qr_code](flag.png)

## Write-up
In order to read this QR code, we have to add the missing black
squares in the corner.
This can be done using an image editor, but I made a Python script to
add the missing squares and read the QR code. (it can be found [here](QRcode.py)).

```python
from PIL import Image
import numpy as np
from pyzbar.pyzbar import decode


def add_square(img, x, y, s):
    """
    adds a black square of size s to the image img at the coordinates x,y.
    """
    for i in range(x, x+s):
        for j in range(y, y+s):
            img[i, j] = False
    return img


def main():
    faulty_qr = "flag.png"
    corrected_qr = "QRcorrected.png"

    # open the qr code picture
    img = Image.open(faulty_qr)
    img_array = np.array(img)

    # add the missing squares in the corners
    img_corrected = add_square(img_array, 60, 60, 30)
    img_corrected = add_square(img_corrected, 360, 60, 30)
    img_corrected = add_square(img_corrected, 60, 360, 30)

    # save the corrected qr code
    img_saved = Image.fromarray(img_corrected)
    img_saved.save(corrected_qr)

    # read the QR code
    decodeQR = decode(Image.open(corrected_qr))
    flag = decodeQR[0].data.decode("ascii")

    # print the result
    print(flag)


if __name__ == '__main__':
    main()
```

We get the corrected QR code picture:
![corrected qr](QRcorrected.png)

and the content of the QR code is the flag.