#!/bin/python3

import sys
import secrets
import getopt
import string
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SECRETS_FILE = f"{os.path.expanduser('~')}{os.sep}.pysecgen_secret"
SALT_FILE = f"{SECRETS_FILE}_salt"


def printHelp():
    helpString = ""
    helpString +=  "Usage: pysecgen [options]\n"
    helpString +=  "Options:\n"
#    helpString += f"  -p <length>          Generate password of <length> [min {MIN_PASS_LEN}] characters\n"
#    helpString += f"  -u <length>          Generate URL-safe of <length> [min {MIN_URL_LEN}] bytes\n"
#    helpString += f"  -t <length>          Generate token of <length> [min {MIN_TOKEN_LEN} bytes] hex values\n"
#    helpString +=  "  -c <seq1> <seq2>     Checks if <seq1> and <seq2> are identical\n"
#    helpString +=  "  -b <length>          Generate binary key sequence of <length> digits\n"
#    helpString +=  "  -H <pass>            Hash using sha512_256 and print hashed <pass> to screen\n"
#    helpString +=  "Written by Costinteo for Informatics Systems Security course at University of Bucharest\n"
    print(helpString, end="")

def genPass(length):
    length = int(length)
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password)
                and sum(c.isupper() for c in password) >= length / 5
                and sum(c.isdigit() for c in password) >= length / 5
                and sum(c in string.punctuation for c in password) >= length / 5):
            break
    return password


optfuncs = {
    "-h" : printHelp,
    "-p" : genPass,
    "-s" : storePass,
    "-l" : loadPass,
    "-f" : setSecretFile
}

if __name__ == "__main__":
    optlist, args = getopt.gnu_getopt(sys.argv[1:], "hp:s:l:f:")

    print(SECRETS_FILE)

    if len(optlist) == 0:
        "No arguments given! See pysecgen --help for usage." 
        exit(1)

    for flag, arg in optlist:
        if flag == "-h":
            printHelp();
            exit(0)
        optfuncs[flag](arg)

# to do:
# check if script is being ran as root
# check if files exist, otherwise generate them as root (or maybe as special group)
# generate key from master pass using sha256 + salt (also stored in separate file)
# encrypt password and write to secret file
# use input() hiding characters so history logs are not stored

