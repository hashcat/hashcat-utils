## *hashcat-utils* ##

**hashcat-utils** are a set of small utilities that are useful in advanced password cracking

### License ###

**hashcat-utils** is licensed under the MIT license. Refer to [docs/license.txt](docs/license.txt) for more information.

### Brief description ###

They all are packed into multiple stand-alone binaries.

All of these utils are designed to execute only one specific function.

Since they all work with STDIN and STDOUT you can group them into chains.

### Detailed description ###

See the hashcat wiki page of hashcat-utils: https://hashcat.net/wiki/doku.php?id=hashcat_utils

### Building ###

#### Native binaries only

Using gcc

```bash
$ make clean && make
```

Alternatively, using clang

```bash
$ make clean && make CC=clang
```

#### Windows binaries only

Using mingw

```bash
$ make clean && make windows
```

Alternatively, using clang

```bash
$ make clean && make windows CC_WINDOWS=clang
```

### Binary distribution ###

Binaries for Linux and Windows: https://github.com/hashcat/hashcat-utils/releases
