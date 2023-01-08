# rsa-weakrack.py
A Python 3 script for searching factorDB for known factors in weak public keys, to then recreate the private key file.

## Use
Attempt to find a private key for a given public key file:

```
python3 rsa-weakrack.py --pubkey <pubkey path>
``` 

