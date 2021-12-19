# pysecgen

## Description

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
$ chmod +x pysecgen
```

You should also probably put it on $PATH and alias it.
