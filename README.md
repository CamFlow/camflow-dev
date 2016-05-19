# CamFlow

If you simply wish to install CamFlow please visit [here](https://github.com/CamFlow/camflow-install).
The source code for the provenance and ifc userspace libraries are available [here](https://github.com/CamFlow/camflow-provenance-lib) and [there](https://github.com/CamFlow/camflow-ifc-lib) respectively.

## Version

| CamFlow version | Kernel version | Date       |
| --------------- |----------------| ---------- |
| 0.1.2           | 4.4.6          | n/a        |
| 0.1.1           | 4.4.6          | 03/04/2016 |
| 0.1.0           | 4.2.8          | 28/03/2016 |

### v0.1.2

```
- Machine ID provided by kernel module.
- Added pseudo file to set the machine ID.
- Modified provenance data structure.
- Added dependency to userspace configuration service (loaded at boot time).
```

### v0.1.1

```
- Update kernel from version 4.2.8 to version 4.4.6.
- Reduce number of file name and address recorded, limit to tracked entities.
- Obfuscate tag value, to avoid side channel through created tags.
- Correct a bug that allowed the same tag to be added several times on files.
- Name of files should now be properly recorded.
- Security context recorded in audit.
```

### v0.1.0

```
- Initial release.
```

## Warning

The code is neither feature complete nor stable.
We are working hard to improve this work, but it is an academic prototype.
Do not hesitate to fork the repository or to report bugs.

## Building
* make prepare
* make config
 * select relevant modules in security
* make compile
 * be patient
 * it may ask for sudo password mid-way
* make install
 * continue to be patient
 * it may ask for sudo password

## Plan
* 0.1.3 look at some form of automated testing.
* 0.2.0 IFC tags and provenance data persistence across reboot.

## TODO
* Look at [keystore](https://lwn.net/Articles/210502/) to store tag related metadata (e.g. associated certificate for MW)
* Look at NetLabel, XFRM and IPSEC for labelled packet (may not be able to get what we want).
* Investigate audit data captured.
* Look at Coccinelle for patching /security/security.c and .h files.
* Finish/build command line tool(s) to manage the module.
