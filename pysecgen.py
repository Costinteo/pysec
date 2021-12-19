#!/bin/python3

import sys
import secrets
import getopt
import string
import os
import getpass
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

HOME  = f"{os.path.expanduser('~')}"
LOAD  = "LOAD"
STORE = "STORE"


SECRETS_PATH = f"{HOME}{os.sep}.pysecgen_secret"
SALT_PATH = f"{HOME}{os.sep}.pysecgen_salt"
PLATFORM = None
MODE = None
NEWPASS = None
PRINTPASS = False

FERNET = False

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
    sys.exit(0)

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

def storePass(): 
    secretFile = open(SECRETS_PATH, getFileMode())
    print(f"{PLATFORM} {NEWPASS}")
    encryptedLine = FERNET.encrypt(bytes(f"{PLATFORM} {NEWPASS}", "UTF-8"))
    print(encryptedLine.decode())
    secretFile.write(f"{encryptedLine.decode('UTF-8')}\n")
    secretFile.close()

def loadPass():
    secretFile = open(SECRETS_PATH, getFileMode())

    for encryptedLine in secretFile.readlines():
        platform, decryptedPass = FERNET.decrypt(bytes(encryptedLine[:-1], "UTF-8")).decode("UTF-8").split(" ")
        if platform == PLATFORM:
            secretFile.close()
            return decryptedPass
    secretFile.close()
    sys.exit("Platform not found in secret file!")

def setMode(mode):
    global MODE

    if MODE:
        sys.exit("Arguments -l and -s are mutually exclusive and should only be inputted once!")
    
    MODE = mode

def setPlatform(platform):
    global PLATFORM

    PLATFORM = platform

def getFileMode():
    if MODE == STORE:
        return "a"
    else:
        return "r"

def genSecretFile():
    # generate only if not already generated
    if not os.path.isfile(SECRETS_PATH):
        print(f"Generated secret file at {SECRETS_PATH}")
        open(SECRETS_PATH,"w").close()
        os.chmod(SECRETS_PATH, 0o600)

def genSaltFile():
    # generate only if not already generated
    if not os.path.isfile(SALT_PATH):
        print(f"Generated salt file at {SALT_PATH}")
        saltFile = open(SALT_PATH, "w")
        saltFile.write(secrets.token_hex(16))
        os.chmod(SALT_PATH, 0o600)
        saltFile.close()

def setMasterKey():
    global MASTERKEY
    saltFile = open(SALT_PATH, "r")
    salt = bytes.fromhex(saltFile.readline())
    print(salt)
    saltFile.close()
    masterPass = bytes(getpass.getpass(prompt="Enter master pass: "), "UTF-8")
    #kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=256, salt=salt, iterations=390000,)
    kdf = Scrypt(salt=salt, length=32, n=2**16, r=8, p=1)
    MASTERKEY = base64.urlsafe_b64encode(kdf.derive(masterPass))

def setSecretPath(path):
    global SECRETS_PATH, SALT_PATH

    if os.path.isfile(path) or not os.path.isdir(path):
        sys.exit("Please input an existing directory to save the secret files to!")

    # trim ending slash
    if path[-1] == os.sep:
        path = path[:-1]

    SECRETS_PATH = f"{path}{os.sep}.pysecgen_secret"
    SALT_PATH = f"{path}{os.sep}.pysecgen_salt"

def isRoot():
    return os.geteuid() == 0

if __name__ == "__main__":
    if not isRoot():
        sys.exit("Please run as root.")

    try:
        optlist, args = getopt.gnu_getopt(sys.argv[1:], "hp:s:l:f:", ["help", "print"])
    except:
        sys.exit("Wrong arguments given! See pysecgen --help for usage.")

    if len(optlist) == 0:
        sys.exit("No arguments given! See pysecgen --help for usage.")

    for flag, arg in optlist:
        if flag == "-h" or flag == "--help":
            printHelp()
        elif flag == "-s":
            setMode(STORE)
            setPlatform(arg)
        elif flag == "-l":
            setMode(LOAD)
            setPlatform(arg)
        elif flag == "-f":
            setSecretPath(arg)
        elif flag == "-p":
            NEWPASS = genPass(arg)
        elif flag == "--print":
            PRINTPASS = True

    if not MODE:
        sys.exit("No mode and platform specified! See pysecgen --help for usage.")

    # generate files if not generated
    genSecretFile()
    genSaltFile()

    setMasterKey()
    FERNET = Fernet(MASTERKEY)

    if MODE == LOAD:
        pw = loadPass()
        print(pw)
    elif MODE == STORE:
        NEWPASS = getpass.getpass(f"New password for platform {PLATFORM}: ") if not NEWPASS else NEWPASS
        storePass()
        if PRINTPASS:
            print(NEWPASS)   
        

# to do:
# encrypt password and write to secret file

