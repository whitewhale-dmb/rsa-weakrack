# rsa-weakrack.py
A Python 3 script for searching factorDB for known factors in weak public keys, to then calculate the private key file.

## Use
Attempt to find a private key for a given public key file:

```
python3 rsa-weakrack.py --pubkey ~/.ssh/id_rsa.pub
``` 

