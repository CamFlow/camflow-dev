# CamFlow

[![DOI](https://zenodo.org/badge/48607854.svg)](https://zenodo.org/badge/latestdoi/48607854)

If you simply wish to install CamFlow please visit [here](https://github.com/CamFlow/camflow-install).
The source code for the provenance userspace library is available [here](https://github.com/CamFlow/camflow-provenance-lib).

# Build Status

| Branch | Status                                                                                  | SonarQube |
|--------|-----------------------------------------------------------------------------------------|-----------|
| master | [![Master Build Status](https://api.travis-ci.org/CamFlow/camflow-dev.svg?branch=master)](https://travis-ci.org/CamFlow/camflow-dev/branches)  |[![SonarQube Status](https://sonarqube.com/api/badges/gate?key=camflow%3Adev)](https://sonarqube.com/dashboard?id=camflow%3Adev)   |
| dev    | [![Dev Build Status](https://api.travis-ci.org/CamFlow/camflow-dev.svg?branch=dev)](https://travis-ci.org/CamFlow/camflow-dev/branches)      |[![SonarQube Status](https://sonarqube.com/api/badges/gate?key=camflow%3Adev%3Adev)](https://sonarqube.com/dashboard?id=camflow%3Adev%3Adev)   |

Automated Travis test run the following operation:
- build the kernel;
- run [sparse](https://sparse.wiki.kernel.org/index.php/Main_Page);
- run [checkpatch](https://kernelnewbies.org/CheckpatchTips);
- run [flawfinder](https://www.dwheeler.com/flawfinder/);
- run [smatch](https://lwn.net/Articles/691882/);
- run [SonarQube](https://sonarqube.com);
- build the kernel patch.

## Warning

The code is neither feature complete nor stable.
We are working hard to improve this work, but it is an academic prototype.
Do not hesitate to fork the repository or to report bugs.

## Building

``` shell
sudo dnf groupinstall 'Development Tools'
sudo dnf install ncurses-devel cmake clang gcc-c++ wget git openssl-devel zlib patch mosquitto
```

```
make prepare
make config # select relevant modules in security
make compile # patience, password will be asked during compilation
make install # patience, password will be asked during installation
 ```
