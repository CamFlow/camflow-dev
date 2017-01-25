## Version

| CamFlow version | Kernel version | Date       |
| --------------- |----------------| ---------- |
| 0.2.1           | 4.9.5          | N/A				|
| 0.2.0           | 4.9.5          | 23/01/2017 |
| 0.1.11          | 4.4.36         | 05/12/2016 |
| 0.1.10          | 4.4.31         | 11/11/2016 |
| 0.1.9           | 4.4.28         | 28/10/2016 |
| 0.1.8           | 4.4.25         | 19/10/2016 |
| 0.1.7           | 4.4.23         | 04/10/2016 |
| 0.1.6           | 4.4.21         | 19/09/2016 |
| 0.1.5           | 4.4.19         | 02/09/2016 |
| 0.1.4           | 4.4.16         | 18/08/2016 |
| 0.1.3           | 4.4.6          | 08/08/2016 |
| 0.1.2           | 4.4.6          | 26/05/2016 |
| 0.1.1           | 4.4.6          | 03/04/2016 |
| 0.1.0           | 4.2.8          | 28/03/2016 |

### v0.2.1

```
- performance improvement.
```

### v0.2.0

```
- Improve stability.
- Add a makefile entry to run standard Linux kernel test on CamFlow.
- Handle shared state in provenance graph.
- Fix cases of ID overlap.
- Writing nodes or relation from user space requires capability: CAP_AUDIT_WRITE
- Replaced check for user 0, by check for capability CAP_AUDIT_CONTROL.
- Can target based on secctx.
- Can target based on cgroup.
- Can now record IP packets content.
- Record inode and task secid and secctx (from "major" LSM).
- Code cleanup.
- Support for IFC on a temporary hold (manpower and priority reason), code
remain available on branch "ifc" https://github.com/CamFlow/camflow-dev/tree/ifc.
- Fix "sleeping function called from invalid context" when d_find_alias was
 called in provenance_inode_permission.
- Identify containers via "cid" (current_cid() << (current->nsproxy->cgroup_ns->ns.inum)).
- Use the correct relation type for relationships between packets and sockets.
- Update to kernel version 4.9.5.
```

### v0.1.11

```
- Separate named relation for entities and activities.
- Add RL_MMAP relation used to connect inodes to private mmap nodes.
- Separate exec relation into inode -> process (RL_EXEC), and process -> process (RL_EXEC_PROCESS)
- Add inode_post_sexattr, inode_getxattr, inode_listxattr, and inode_removexattr hooks.
- Add readlink hook.
- Add inode_setattr and inode_getattr hooks.
- Add inode_rename hook.
- If IP filter is already present update operation rather than duplicating the entry.
- Can now delete IP filter entry.
- Fix more orphaned edge cases.
- Update to kernel version 4.4.36.
```

### v0.1.10

```
- Fix bug when recording version.
- Fix issue with private MMAP and opaque process.
- Add API to track socket on bind and connect.
- Fix type of socket bind.
- Fix direction of socket accept.
- Add pseudo file interface to read/write provenance tracking option from PID.
- ifc_from_pid -> ifc_from_vpid and prov_from_pid -> prov_from_vpid (name change for clarity).
- Reworked relation and node types: 64 bits, W3C type + CamFlow subtype.
- Fixed issue when activating both IFC and Provenance.
- Change module load priority.
- Update to kernel version 4.4.31.
```

### v0.1.9

```
- Record whole-provenance at boot if option set in kernel config (off by default).
- Fix a deadlock bug.
- Record pid and vpid for task.
- Update to kernel version 4.4.28.
```

### v0.1.8

```
- Properly deal with MMAP_SHARED and MMAP_PRIVATE.
- Refine relation types in inode permission hooks.
- Deal with concurrency issues.
- Recording offset information.
- Record jiffies for every events (nodes, relationships).
- Update to kernel version 4.4.25.
```

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

### 0.2.X

* generalise access denial recording.
* look at some form of automated testing.
* support for Raspberry Pi / ARM.
* refactor userspace API.

### 0.3.X

* Switch to 4.9 once confirmed it is LTS.
* Setting tracking via pid is "racy" (i.e. pid may be reassigned while parameter are being set).
* Clean-up code.
* IFC tags and provenance data persistence across reboot.
* Look at [keystore](https://lwn.net/Articles/210502/) to store tag related metadata (e.g. associated certificate for MW)
* Look at [NetLabel](https://www.kernel.org/doc/Documentation/netlabel/introduction.txt), [XFRM](http://man7.org/linux/man-pages/man8/ip-xfrm.8.html) and [IPSEC](http://kernelspec.blogspot.co.uk/2014/10/ipsec-implementation-in-linux-kernel.html) for labelled packet (may or may not do what we want).
* Look at [Coccinelle](http://coccinelle.lip6.fr/) for patching /security/security.c and .h files.
