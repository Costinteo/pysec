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

FERNET = None

def printHelp():
    helpString = ""
    helpString +=  "Simple password managing tool written in Python, using the cryptography module.\n"
    helpString +=  "Usage: pysecgen [options]\n"
    helpString +=  "Options:\n"
    helpString +=  "  -h, --help           Print this help and exit\n"
    helpString +=  "  -p <length>          Generate random password of <length> characters\n"
    helpString +=  "                       [Use with -s argument to store the newly generated pass]\n\n"
    helpString +=  "  -s <platform>        Encrypt and store password for <platform>\n"
    helpString +=  "  -l <platform>        Load and decrypt password for <platform>\n"
    helpString +=  "  -f <dirpath>         Path to directory in which to save the secret files\n"
    helpString +=  "                       [Defaults are /root/.pysecgen_secret and /root/.pysecgen_salt]\n\n"
    helpString +=  "Written by Costinteo. Licensed under GPL v3.\n"
    helpString +=  "For more information, access: <https://github.com/Costinteo>\n"
    print(helpString, end="")
    sys.exit(0)

def genPass(length):
    if NEWPASS:
        sys.exit("Only one password can be generated at a time!")
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
    encryptedLine = FERNET.encrypt(bytes(f"{PLATFORM} {NEWPASS}", "UTF-8"))
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

    PLATFORM = platform.lower()

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
    saltFile.close()
    masterPass = bytes(getpass.getpass(prompt="Enter master pass: "), "UTF-8")
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
