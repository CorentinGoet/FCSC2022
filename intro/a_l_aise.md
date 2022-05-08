# À l'aise

Categories: intro, crypto

## Challenge

For this challenge, we get a text encrypted by Vigenère using
the key: FCSC
We need to find the meeting location described in the encrypted message.
```text
Gqfltwj emgj clgfv ! Aqltj rjqhjsksg ekxuaqs, ua xtwk
n'feuguvwb gkwp xwj, ujts f'npxkqvjgw nw tjuwcz
ugwygjtfkf qz uw efezg sqk gspwonu. Jgsfwb-aqmu f
Pspygk nj 29 cntnn hqzt dg igtwy fw xtvjg rkkunqf.
```
## Write-up

Since we have both the cipher and the key, we can use CyberChef:
https://gchq.github.io/CyberChef/
and select Vigenère in the Encryption/Encoding section.

We get the plaintext:
```text
Bonjour cher agent ! Votre prochaine mission, si vous
l'acceptez bien sur, sera d'infiltrer le reseau
souterrain ou se cache nos ennemis. Rendez-vous a
Nantes le 29 avril pour le debut de votre mission.
```

The meeting location is: Nantes