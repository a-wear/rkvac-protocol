# rkvac-protocol
This is a C implementation of the RKVAC (_Revocable Keyed-Verification Anonymous Credentials_) protocol.

## Table of Contents
- [Getting started](#getting-started)
    - [Dependencies](#dependencies)
- [Usage](#usage)
    - [Command line options](#command-line-options)
- [Build instructions](#build-instructions)
    - [Generic build options](#generic-build-options)
    - [MULTOS build options](#multos-build-options)
- [Install dependencies](#install-dependencies)
    - [Install dependencies using the package manager](#install-dependencies-using-the-package-manager)
    - [Install dependencies from source](#install-dependencies-from-source)
- [Benchmarks](#benchmarks)
- [Project structure](#project-structure)
    - [Source tree](#source-tree)
    - [Source description](#source-description)
- [License](#license)

## Getting started
These instructions will get you a copy of the project up and running on your local machine for development
and testing purposes.

### Dependencies
The following table summarizes the tools and libraries required to build. By default,
the build uses the library installed on the system. However, if no library is found
installed on the system, you have to specify the path where the necessary libraries
are installed.

| Dependency   | Tested version  | Debian/Ubuntu pkg    | Optional | Purpose         |
| ------------ | --------------- | -------------------- | -------- | --------------- |
| CMake        | 3.17            | `cmake`              | NO       | -               |
| Zlib         | 1.2.11          | `zlib1g-dev`         | NO       | For OpenSSL     |
| OpenSSL      | 1.1.1g          | `libssl-dev`         | NO       | For MCL library |
| GMP          | 6.2.0           | `libgmp-dev`         | NO       | For MCL library |
| MCL          | 1.11            | `-`                  | NO       | Cryptography    |
| PCSC         | 1.8.24          | `libpcsclite-dev`    | NO       | SmartCard PC/SC |
| PCSCD        | 1.8.24          | `pcscd`              | NO       | SmartCard PC/SC |

## Usage
1. Open a terminal within the folder with the executable
2. Start with `./rkvac-protocol [--attributes <XX>] [--disclosed-attributes <XX>]`

### Command line options
It is allowed to overwrite some of the settings via command line options.
Run `rkvac-protocol --help` to show all available command line options.

| Short option | Long option                | Description                                        |
|--------------|----------------------------|----------------------------------------------------|
| `-a`         | `--attributes`             | specifies the number of user attributes (1-9)      |
| `-d`         | `--disclosed-attributes`   | specifies the number of disclosed attributes (0-9) |
| `-h`         | `--help`                   | shows this help                                    |

## Build instructions
x86-64/ARM/ARM64 Linux and macOS are supported. If you have any problems during compilation,
please check the [Install dependencies](#install-dependencies) section.

### Generic build options
- **Note**: this will produce the following executable: `rkvac-protocol`

- `OPENSSL_ROOT_DIR` specify where the OpenSSL library is located
    - `cmake .. -DOPENSSL_ROOT_DIR=${openssl-dir}`
- `MCL_ROOT_DIR` specify where the MCL library is located
    - `cmake .. -DMCL_ROOT_DIR=${mcl-dir}`
- `PCSC_ROOT_DIR` specify where the PCSC library is located
    - `cmake .. -DPCSC_ROOT_DIR=${pcsc-dir}`
- `CMAKE_BUILD_TYPE` set the build type
    - valid options: `Release` or `Debug`

### MULTOS build options
- **Note**: this will produce the additional executable: `rkvac-protocol-multos`

- `RKVAC_PROTOCOL_MULTOS` allows to disable/enable the MULTOS support (default OFF)
    - `cmake .. -DRKVAC_PROTOCOL_MULTOS=ON`

## Install dependencies

### Install dependencies using the package manager
```sh
apt install cmake libssl-dev libgmp-dev libpcsclite-dev pcscd
```

### Install dependencies from source

#### Compiling `zlib-1.2.11`
```sh
wget https://www.zlib.net/zlib-1.2.11.tar.gz
tar xzf zlib-1.2.11.tar.gz
cd zlib-1.2.11

./configure --prefix=/usr/local/zlib-1.2.11 --static
make -j 4
make install
```

#### Compiling `openssl-1.1.1g`
```sh
wget https://www.openssl.org/source/openssl-1.1.1g.tar.gz
tar xzf openssl-1.1.1g.tar.gz
cd openssl-1.1.1g

./Configure threads zlib \
            --with-zlib-include=/usr/local/zlib-1.2.11/include \
            --with-zlib-lib=/usr/local/zlib-1.2.11/lib \
            --prefix=/usr/local/openssl-1.1.1g \
            --openssldir=/usr/local/openssl-1.1.1g/etc \
            linux-generic32
make -j 4
make install
```

#### Compiling `gmp-6.2.0`
```sh
apt install m4
```

```sh
wget https://gmplib.org/download/gmp/gmp-6.2.0.tar.bz2
tar xjf gmp-6.2.0.tar.bz2
cd gmp-6.2.0

./configure --prefix=/usr/local/gmp-6.2.0 --enable-cxx
make -j 4
make install
```

#### Compiling `cmake-3.17.3`
```sh
apt install libcurl4-openssl-dev libbz2-dev
```

```sh
wget https://github.com/Kitware/CMake/releases/download/v3.17.3/cmake-3.17.3.tar.gz
tar xzf cmake-3.17.3.tar.gz
mkdir cmake-3.17.3/build
cd cmake-3.17.3/build

../configure --prefix=/usr/local/cmake-3.17.3 --system-curl --parallel=4 -- \
              -DOPENSSL_ROOT_DIR=/usr/local/openssl-1.1.1g \
              -DZLIB_ROOT=/usr/local/zlib-1.2.11
make -j 4
make install
```

#### Compiling `mcl-1.11`
```sh
git clone https://github.com/herumi/mcl.git
mkdir mcl/build
cd mcl/build

# v1.11
git checkout 0928a1764765609a74bd16bcd6c09467f3d959db

cmake -DCMAKE_INSTALL_PREFIX=/usr/local/mcl-1.11 -DCMAKE_BUILD_TYPE=Release -DUSE_GMP=ON -DUSE_OPENSSL=ON \
      -DCMAKE_CXX_FLAGS='-I/usr/local/gmp-6.2.0/include -I/usr/local/openssl-1.1.1g/include' \
      -DCMAKE_SHARED_LINKER_FLAGS='-L/usr/local/gmp-6.2.0/lib -L/usr/local/openssl-1.1.1g/lib' \
      -DCMAKE_EXE_LINKER_FLAGS='-L/usr/local/gmp-6.2.0/lib -L/usr/local/openssl-1.1.1g/lib' ..
make -j 4
make install
```

#### *Note for Linux and Raspberry Pi OS users:*
You must create a file with the following content:

```sh
$ cat /etc/ld.so.conf.d/10-custom-libraries.conf
```

```sh
# openssl-1.1.1g
/usr/local/openssl-1.1.1g/lib

# gmp-6.2.0
/usr/local/gmp-6.2.0/lib

# mcl-1.11
/usr/local/mcl-1.11/lib
```

You must also patch the PCSC library using the following commands:

```sh
sed -i 's/#include <wintypes.h>/#include \"wintypes.h\"/g' /usr/include/PCSC/pcsclite.h
sed -i 's/#include <pcsclite.h>/#include \"pcsclite.h\"/g' /usr/include/PCSC/winscard.h
sed -i 's/#ifdef __APPLE__/#if !defined(WIN32)/g' /usr/include/PCSC/wintypes.h
```

## Benchmarks
The `benchmarking.sh` script can be used to automatically perform performance tests when the user works on
another platform.

It is possible to specify the number of iterations the script will perform for each disclosed attribute and
calculate the average more accurately, as well as to configure the path of the executable and the directory
where the results will be saved.

```sh
readonly ITERATIONS=25
readonly OUTPUT_DIR="benchmarks"
readonly EXECUTABLE="../build/rkvac-protocol-multos"
```

The script will generate two files:
- `<timestamp>_raw.txt`: all the times of each iteration
- `<timestamp>_csv.txt`: average time for each attributes/disclosed_attributes

Please, note that all times are expressed in seconds.

#### Structure of `<timestamp>_raw.txt`:

`attributes/disclosed_attributes: total_elapsed_time;proof_of_knowledge;total_communication;communication_stages`

#### Structure of `<timestamp>_csv.txt`:

`attributes/disclosed_attributes: total_elapsed_time;proof_of_knowledge;total_communication`

## Project structure

### Source tree

```sh
rkvac-protocol/
├── cmake
│   └── Modules
│       ├── FindMCL.cmake
│       └── FindPCSC.cmake
├── CMakeLists.txt
├── config
│   └── config.h
├── include
│   ├── attributes.h
│   ├── models
│   │   ├── issuer.h
│   │   ├── revocation-authority.h
│   │   ├── user.h
│   │   └── verifier.h
│   ├── multos
│   │   └── apdu.h
│   ├── system.h
│   └── types.h
├── lib
│   ├── apdu
│   │   ├── command.c
│   │   └── command.h
│   ├── helpers
│   │   ├── hash_helper.c
│   │   ├── hash_helper.h
│   │   ├── hex_helper.c
│   │   ├── hex_helper.h
│   │   ├── mcl_helper.c
│   │   ├── mcl_helper.h
│   │   ├── multos_helper.c
│   │   └── multos_helper.h
│   └── pcsc
│       ├── reader.c
│       └── reader.h
├── LICENSE.md
├── main.c
├── README.md
├── scripts
│   └── benchmarking.sh
└── src
    ├── controllers
    │   ├── issuer.c
    │   ├── issuer.h
    │   ├── multos
    │   │   ├── user.c
    │   │   └── user.h
    │   ├── revocation-authority.c
    │   ├── revocation-authority.h
    │   ├── user.c
    │   ├── user.h
    │   ├── verifier.c
    │   └── verifier.h
    ├── setup.c
    └── setup.h
```

### Source description

| Directory                   | File                           | Description                                                                                                             |
| --------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
|  `config/`                  |  `config.h`                    | constants (maximum number of user attributes, k and j values of the revocation authority, length of the user id, etc)   |
|  `include/`                 |  `attributes.h`                | the user attributes are defined in this file                                                                            |
|  `include/models/`          |  `*`                           | definition of the data structures (information) used by the issuer, the revocation authority, the user and the verifier |
|  `include/multos/`          |  `apdu.h`                      | header with APDU codes used for communication with the smart card                                                       |
|  `include/`                 |  `system.h`                    | the system parameters used in elliptic curve operations (curve type, G1 and G2)                                         |
|  `include/`                 |  `types.h`                     | custom defined data types used on other platforms (e.g. MULTOS)                                                         |
|  `lib/apdu/`                |  `command.{c,h}`               | functions defined to build and parse APDU packets                                                                       |
|  `lib/helpers/`             |  `hash_helper.{c,h}`           | function used by the verifier to compute the hash depending on the platform where the user is running (e.g. PC, MULTOS) |
|  `lib/helpers/`             |  `hex_helper.{c,h}`            | routines to convert the memory content into a hexadecimal string and vice versa                                         |
|  `lib/helpers/`             |  `mcl_helper.{c,h}`            | conversion of MCL library data types to types from other platforms (e.g. MULTOS)                                        |
|  `lib/helpers/`             |  `multos_helper.{c,h}`         | conversion of MULTOS data types to MCL library data types                                                               |
|  `lib/pcsc/`                |  `reader.{c,h}`                | functions defined for sending and receiving APDU packets, smart card communication                                      |
|  `scripts/`                 |  `benchmarking.sh`             | script used to automatically perform performance tests                                                                  |
|  `src/controllers/`         |  `issuer.{c,h}`                | code related to the operations performed by the issuer (signature of the user attributes)                               |
|  `src/controllers/multos/`  |  `user.{c,h}`                  | code related to the operations performed by the user, MULTOS (proof of knowledge computation, information storage)      |
|  `src/controllers/`         |  `revocation-authority.{c,h}`  | code related to the operations performed by the revocation authority (signature and revocation attribute)               |
|  `src/controllers/`         |  `user.{c,h}`                  | code related to the operations performed by the user, PC (proof of knowledge computation, information storage)          |
|  `src/controllers/`         |  `verifier.{c,h}`              | code related to the operations performed by the verifier (nonce and epoch generation, proof of knowledge verification)  |
|  `src/`                     |  `setup.{c,h}`                 | used to initialize the system parameters and the elliptic curve                                                         |
|  `-`                        |  `main.c`                      | main routine                                                                                                            |
|  `-`                        |  `CMakeLists.txt`              | used for compiling code and building the application                                                                    |

## License
This project is licensed under the GPLv3 License - see the [LICENSE.md](LICENSE.md) file for details.
