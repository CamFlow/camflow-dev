# CamFlow development [![Master Build Status](https://api.travis-ci.org/CamFlow/camflow-dev.svg?branch=master)](https://travis-ci.org/CamFlow/camflow-dev/branches) [![CircleCI](https://circleci.com/gh/CamFlow/camflow-dev/tree/master.svg?style=svg)](https://circleci.com/gh/CamFlow/camflow-dev/tree/master)

[![DOI](https://zenodo.org/badge/48607854.svg)](https://zenodo.org/badge/latestdoi/48607854)

If you simply wish to install CamFlow please visit [here](https://github.com/CamFlow/camflow-install).
The source code for the provenance userspace library is available [here](https://github.com/CamFlow/camflow-provenance-lib).

## Build Status

| Branch | CircleCI | Description |
|--------|----------|-------------|
| master |  [![CircleCI](https://circleci.com/gh/CamFlow/camflow-dev/tree/master.svg?style=svg)](https://circleci.com/gh/CamFlow/camflow-dev/tree/master) | latest release |
| dev    | [![CircleCI](https://circleci.com/gh/CamFlow/camflow-dev/tree/dev.svg?style=svg)](https://circleci.com/gh/CamFlow/camflow-dev/tree/dev) | development branch (unstable) |
| kernel    | [![CircleCI](https://circleci.com/gh/CamFlow/camflow-dev/tree/kernel.svg?style=svg)](https://circleci.com/gh/CamFlow/camflow-dev/tree/kernel) | master branch with latest supported kernel (unstable) |

## Warning

The code is neither feature complete nor stable.
We are working hard to improve this work, but it is an academic prototype.
Do not hesitate to fork the repository or to report bugs.

## Building

``` shell
sudo dnf groupinstall 'Development Tools'
sudo dnf install ncurses-devel cmake clang gcc-c++ wget git openssl-devel zlib ruby bison flex patch mosquitto uncrustify
```

```
make prepare
make config # select relevant modules in security
make compile # patience, password will be asked during compilation
make install # patience, password will be asked during installation
 ```
