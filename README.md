# pysecgen

Simple security tool written in Python for generating and managing secure passwords. It uses the [cryptography](https://github.com/pyca/cryptography) module.

## Dependencies
```
Python        >=  3.8.10
OpenSSL       >=  1.1.1f
cryptography  >=  36.0.0
```

This is what I had when I wrote it. I haven't verified if the above versions are really required. You can probably get away with running it with older versions of the above packages.

## Installation

Make sure to have the dependencies up-to-date. 

You can probably get it on anything, but I've only tested on Linux.

```
$ git clone https://github.com/Costinteo/pysecgen.git
$ cd pysecgen
$ chmod +x pysecgen.py
```

You should also probably put it on $PATH and alias it. This is what I have (make sure to put in YOUR home, instead of "costinteo"):

```
alias pysecload='sudo /path/to/pysecgen.py -f /home/costinteo/ -l'
alias pysecstore='sudo /path/to/pysecgen.py -f /home/costinteo/ -p 20 --print -s'
```

So now you only need to call it like ``pysecload PLATFORM`` or ``pysecstore PLATFORM``.

## Example usage

The following usage generates a password of 20 characters and stores in an encrypted format in ``/root/.pysecgen_secret`` for the Steam platform. Then we load it.

```
$ sudo ./pysecgen.py -s Steam -p 20
$ sudo ./pysecgen.py -l Steam
```

For more info, check the usage text:

```
Simple password managing tool written in Python, using the cryptography module.
Usage: pysecgen [options]
Options:
  -h, --help           Print this help and exit
  -p <length>          Generate random password of <length> characters
                       [Use with -s argument to store the newly generated pass]

  -s <platform>        Encrypt and store password for <platform>
  -l <platform>        Load and decrypt password for <platform>
  -f <dirpath>         Path to directory in which to save the secret files
                       [Defaults are /root/.pysecgen_secret and /root/.pysecgen_salt]

Written by Costinteo. Licensed under GPL v3.
For more information, access: <https://github.com/Costinteo>
```
