# CamFlow

If you simply wish to install CamFlow please visit [here](https://github.com/CamFlow/camflow-install).
The source code for the audit and ifc userspace libraries are available [here](https://github.com/CamFlow/camflow-audit-lib) and [there](https://github.com/CamFlow/camflow-ifc-lib) respectively.

## Version

| CamFlow version | Kernel version | Date       |
| --------------- |----------------| ---------- |
| 0.1.1           | 4.4.6          | n/a        |
| 0.1.0           | 4.2.8          | 28/03/2016 |

### v0.1.1

'''
- Update kernel from version 4.2.8 to version 4.4.6.
- Reduce number of file name and address recorded, limit to tracked entities.
'''

### v0.1.0

'''
- Initial release.
'''

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
* 0.1.1 update to kernel version 4.4.6
* 0.2.0 IFC tags and provenance data persistence across reboot

## TODO
* Look at NetLabel, XFRM and IPSEC for labelled packet (may not be able to get what we want).
* Investigate audit data captured.
* Look at Coccinelle for patching /security/security.c and .h files.
* Finish/build command line tool(s) to manage the module.
