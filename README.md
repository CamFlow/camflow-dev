# CamFlow development [![Master Build Status](https://api.travis-ci.org/CamFlow/camflow-dev.svg?branch=master)](https://travis-ci.org/CamFlow/camflow-dev/branches) [![CircleCI](https://circleci.com/gh/CamFlow/camflow-dev/tree/master.svg?style=svg)](https://circleci.com/gh/CamFlow/camflow-dev/tree/master)

[![DOI](https://zenodo.org/badge/48607854.svg)](https://zenodo.org/badge/latestdoi/48607854)

If you simply wish to install CamFlow please visit [here](https://github.com/CamFlow/camflow-install).
The source code for the provenance userspace library is available [here](https://github.com/CamFlow/camflow-provenance-lib).

## Build Status

| Branch | TravisCI | CircleCI | Description |
|--------|----------|----------|-------------|
| master | [![Master Build Status](https://api.travis-ci.org/CamFlow/camflow-dev.svg?branch=master)](https://travis-ci.org/CamFlow/camflow-dev/branches) |  [![CircleCI](https://circleci.com/gh/CamFlow/camflow-dev/tree/master.svg?style=svg)](https://circleci.com/gh/CamFlow/camflow-dev/tree/master) | latest release |
| dev    | [![Dev Build Status](https://api.travis-ci.org/CamFlow/camflow-dev.svg?branch=dev)](https://travis-ci.org/CamFlow/camflow-dev/branches) |  [![CircleCI](https://circleci.com/gh/CamFlow/camflow-dev/tree/dev.svg?style=svg)](https://circleci.com/gh/CamFlow/camflow-dev/tree/dev) | development branch (unstable) |
| kernel    | [![Dev Build Status](https://api.travis-ci.org/CamFlow/camflow-dev.svg?branch=kernel)](https://travis-ci.org/CamFlow/camflow-dev/branches) | [![CircleCI](https://circleci.com/gh/CamFlow/camflow-dev/tree/kernel.svg?style=svg)](https://circleci.com/gh/CamFlow/camflow-dev/tree/kernel) | master branch with latest supported kernel (unstable) |

### TravisCI

The automated Travis script runs the following operation:
- build the kernel;
- run [sparse](https://sparse.wiki.kernel.org/index.php/Main_Page);
- run [checkpatch](https://kernelnewbies.org/CheckpatchTips);
- run [flawfinder](https://www.dwheeler.com/flawfinder/);
- build the kernel patch.

### CircleCI

The automated CircleCI script runs the following operation:
- perform kernel source code analysis;
- generate report available in the `/docs` folder;
- commit and push those reports.

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
