# CamFlow

If you simply wish to install CamFlow please visit [here](https://github.com/CamFlow/camflow-install).
The source code for the provenance and IFC userspace libraries are available [here](https://github.com/CamFlow/camflow-provenance-lib) and [there](https://github.com/CamFlow/camflow-ifc-lib).

## Warning

The code is neither feature complete nor stable.
We are working hard to improve this work, but it is an academic prototype.
Do not hesitate to fork the repository or to report bugs.

## Building

```
make prepare
make config # select relevant modules in security
make compile # patience, sudo password will be asked during compilation
make install # patience, sudo password will be asked during instalation
 ```

## Version

| CamFlow version | Kernel version | Date       |
| --------------- |----------------| ---------- |
| 0.1.7           | 4.4.23         | 04/10/2016 |
| 0.1.6           | 4.4.21         | 19/09/2016 |
| 0.1.5           | 4.4.19         | 02/09/2016 |
| 0.1.4           | 4.4.16         | 18/08/2016 |
| 0.1.3           | 4.4.6          | 08/08/2016 |
| 0.1.2           | 4.4.6          | 26/05/2016 |
| 0.1.1           | 4.4.6          | 03/04/2016 |
| 0.1.0           | 4.2.8          | 28/03/2016 |

### v0.1.7

```
- Config change: by default IFC is not set.
- Recording IPv4 incoming and outgoing packets.
- More sensible settings for relay buffer.
- Update to kernel version 4.4.23.
```

### v0.1.6

```
- Add API to mark files as trusted (IFC).
- Merge several pseudo files interface into a single one.
- Added taint tracking support.
- Replace byte sized flag, by bit sized one.
- Update to kernel version 4.4.21.
```

### v0.1.5

```
- Nodes updated only when relations are recorded.
- Rework provenance tracking propagation.
- More detailed mmap provenance recording.
- Task inherit property from the file they execute (tracking and opaque).
- Fix issues with tracking exec.
- Update to kernel version 4.4.19.
```


### v0.1.4

```
- Add pseudofile to manipulate file provenance settings.
- Add pseudofile to flush relay buffer.
- Edge renamed relation to align with W3C PROV model.
- Update to kernel version 4.4.16.
```

### v0.1.3

```
- Provide facility to filter nodes and edges in kernel.
- Added a string to the disclosed provenance node data structure.
- Provided provenance tracking depth setting (how far tracked flag is propagated).
- Add pseudo file for a process to request to be provenance-tracked.
- Modified provenance internal data structure and working to align with W3C Prov model.
- IFC and Provenance LSM are now part of the default configuration.
```

### v0.1.2

```
- Machine ID provided by kernel module.
- Added pseudo file to set the machine ID.
- Modified provenance data structure.
- Added dependency to userspace configuration service (loaded at boot time).
- Prevent duplications in the list of allowed bridges.
- Build and install configuration service.
```

### v0.1.1

```
- Reduce number of file name and address recorded, limit to tracked entities.
- Obfuscate tag value, to avoid side channel through created tags.
- Correct a bug that allowed the same tag to be added several times on files.
- Name of files should now be properly recorded.
- Security context recorded in audit.
- Update kernel from version 4.2.8 to version 4.4.6.
```

### v0.1.0

```
- Initial release.
```

## Plan

### 0.1.8

* look at some form of automated testing.
* support for Raspberry Pi / ARM

### 0.2.0

* Clean-up code.
* IFC tags and provenance data persistence across reboot.
* Look at [keystore](https://lwn.net/Articles/210502/) to store tag related metadata (e.g. associated certificate for MW)
* Look at [NetLabel](https://www.kernel.org/doc/Documentation/netlabel/introduction.txt), [XFRM](http://man7.org/linux/man-pages/man8/ip-xfrm.8.html) and [IPSEC](http://kernelspec.blogspot.co.uk/2014/10/ipsec-implementation-in-linux-kernel.html) for labelled packet (may or may not do what we want).
* Look at [Coccinelle](http://coccinelle.lip6.fr/) for patching /security/security.c and .h files.
