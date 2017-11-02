## Version

| CamFlow version | Kernel version | Date       |
| --------------- |----------------| ---------- |
| 0.3.8           | 4.13.10        | N/A        |
| 0.3.7           | 4.13.4         | 04/10/2017 |
| 0.3.6           | 4.13.4         | 28/09/2017 |
| 0.3.5           | 4.12.9         | 27/08/2017 |
| 0.3.4           | 4.12.4         | 02/08/2017 |
| 0.3.3           | 4.11.6         | 23/06/2017 |
| 0.3.2           | 4.11.3         | 31/05/2017 |
| 0.3.1           | 4.11.2         | 22/05/2017 |
| 0.3.0           | 4.10.10        | 15/04/2017 |
| 0.2.3           | 4.9.13         | 09/03/2017 |
| 0.2.2           | 4.9.9          | 14/02/2017 |
| 0.2.1           | 4.9.5          | 03/02/2017	|
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

### v0.3.8
```
- Rework recording and filtering internal logic.
- Process node more detailed (pid, vpid, ppid, tgid).
- Add support for multiple relay channel.
- Expose version number via pseudofile.
- Update to kernel version 4.13.10.
```

### v0.3.7
```
- Change the syntax of the version number to make debian happy.
```

### v0.3.6
```
- Fix bug related to file path recording.
- Made node compression (introduced in v0.2.2) configurable from userspace.
- Removed unused relation types.  
- Update to kernel version 4.13.4.
```

### v0.3.5
```
- Capture performance information (CPU, memory usage etc.) for processes.
- Ensure that uname -r and packages name match.
- provenance_unix_may_send uses RL_SND_UNIX instead of RL_UNKNOWN.
- Ensure correct direction of perm_xxx relations.
- Fix issue with link relation type.
- Fix issue with shm alloc relations.
- Fix issue with unix_stream_connect not being recorded.
- Fix issue with xattr related relation types.
- Fix issue with accept relation type.
- Fix the direction of arg and envp relationship.
- Update to kernel version 4.12.9.
```

### v0.3.4
```
- Non-datagram unix socket generates connected graph.
- Properly record arguments and environment variables.
- Implement UID and GID filtering.
- Handle properly inode changing type (in practice we observe file -> link).
- Fix sleep in provenance_inode_permission.
- Update to kernel version 4.12.4.
```

### v0.3.3
```
- Improve LSM support for Information Flow see https://github.com/CamFlow/camflow-dev/issues/41.
- Use netfilter per net registration.
- Update to kernel version 4.11.6.
```

### v0.3.2
```
- Fix issue created by reading pidns.
- Update to kernel version 4.11.3.
```

### v0.3.1
```
- Expose hash of currently loaded capture polciy to user space.
- Update filters to support namespaces based selection.
- Load netfilter on subsys_initcall.
- Load propagate "query" much earlier.
- Record all available namespace id.
- Update to kernel version 4.11.2.
```

### v0.3.0
```
- Make persistence of inode provenance information a build option.
- Add a closed relationship when an inode is freed.
- Add a terminate relationship when a cred is freed.
- Boot id is set from userspace.
- union prov_msg -> union prov_elt
- Implemented run-time query system.
- Debug output legibility improved.
- Update to kernel version 4.10.10.
```

### v0.2.3
```
- A variety of minor issues fixed through code analysis.
- Add support for travis (see https://travis-ci.org/) testing.
- Put back Unix socket recording.
- Persist provenance information across reboot.
- Anticipate upcoming changes: read only after initialisation of security hooks.
- Handle provenance through extended attributes.
- Update to kernel version 4.9.13.
```

### v0.2.2

```
- Fixed some rare deadlock issue.
- Change anti-cycle logic to significantly reduce node numbers (edge number
  remain constant)
- Change how certain target are applied internally.
- Application can be integrated to provenance by writing to a pseudo file.
- Update to kernel version 4.9.9.
```

### v0.2.1

```
- Performance improvement.
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
- Support for IFC on a temporary hold (manpower and priority reason).
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
