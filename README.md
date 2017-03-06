# CamFlow

If you simply wish to install CamFlow please visit [here](https://github.com/CamFlow/camflow-install).
The source code for the provenance userspace library is available [here](https://github.com/CamFlow/camflow-provenance-lib).

# Build Status

| Branch | Status                                                                                  |
|--------|-----------------------------------------------------------------------------------------|
| Master | ![Master Build Status](https://api.travis-ci.org/CamFlow/camflow-dev.svg?branch=master) |
| Dev    | ![Dev Build Status](https://api.travis-ci.org/CamFlow/camflow-dev.svg?branch=dev)       |

## Warning

The code is neither feature complete nor stable.
We are working hard to improve this work, but it is an academic prototype.
Do not hesitate to fork the repository or to report bugs.

## Building

```
make prepare
make config # select relevant modules in security
make compile # patience, sudo password will be asked during compilation
make install # patience, sudo password will be asked during installation
 ```
