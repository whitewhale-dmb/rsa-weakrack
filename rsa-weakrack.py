#!/usr/bin/env python3

import sys
import requests
import json
import argparse
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse


print("    ____  _____ ___") 
print("   / __ \/ ___//   |") 
print("  / /_/ /\__ \/ /| |") 
print(" / _, _/___/ / ___ |") 
print("/_/ |_|/____/_/__|_|    __ __ ____  ___   ________ __")
print("| |     / / ____/   |  / //_// __ \/   | / ____/ //_/")
print("| | /| / / __/ / /| | / ,<  / /_/ / /| |/ /   / ,<") 
print("| |/ |/ / /___/ ___ |/ /| |/ _, _/ ___ / /___/ /| |") 
print("|__/|__/_____/_/  |_/_/ |_/_/ |_/_/  |_\____/_/ |_|") 
print("\n\n\n")
                                                     
# Retrieve args
parser = argparse.ArgumentParser(
                    prog = 'rsa-weakrack.py',
                    description = 'Runs the PK modulus through factorDB to try and find known factors, then regenerates the private key if successful')
parser.add_argument('-p', '--pubkey', required=True)
args = parser.parse_args()

# Retrieve public key
try:
    pkfile = open(args.pubkey).read()
    pk = RSA.importKey(pkfile)
except Exception as ex:
    print("[!] Error importing public key: %s" % ex)
    exit()

print("[*] Modulus 'n' = %i\n[*] Exponent 'e' = %i\n\n" % (pk.n,pk.e))

# Retrieve factors
response = requests.get("http://factordb.com/api", params={"query": str(pk.n)}).json()
if (response["status"] != "FF"):
    print("\n[!] No factors known at this time (FactorDB status: %s)" % response["status"])
    exit()
if (len(response["factors"]) != 2):
    print("\n[!] Unexpected number of factors found (%d)" % len(response["factors"]))
    exit()

# Retrieve p, q
p,q = response["factors"]
p,q = long(p[0]),long(q[0])
print("[*] Factor p = %i\n[*]Factor q = %i\n" % (p,q))

# Calculate phi and modinverse for private key
d = inverse(pk.e, (p-1)*(q-1))
print("[+] Private key found: %d\n" % d)

# Format into RSA private key PEM file
key = RSA.construct((pk.n, pk.e, d, p, q))

privkey = key.exportKey()
with open ("privkey.pem", "w") as privkeyfile:
    privkeyfile.write("{}".format(privkey.decode()))

print("[+] Wrote private key to 'privkey.pem'\n")
