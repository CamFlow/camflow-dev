# Releases

| CamFlow version | Kernel version | Date       |
| --------------- |----------------| ---------- |
| 0.7.3           | 5.11.2         | N/A				|
| 0.7.2           | 5.11.2         | 27/04/2021	|
| 0.7.1           | 5.9.11         | 05/12/2020 |
| 0.7.0           | 5.7.7	         | 09/07/2020	|
| 0.6.7           | 5.6.15         | 31/05/2020 |
| 0.6.6           | 5.6.7          | 30/04/2020 |
| 0.6.5           | 5.5.11         | 23/03/2020	|
| 0.6.4           | 5.4.15         | 30/01/2020	|
| 0.6.3           | 5.2.9          | 23/08/2019	|
| 0.6.2           | 5.1.9          | 17/06/2019	|
| 0.6.1           | 5.1.9          | 14/06/2019	|
| 0.6.0           | 5.0.10         | 29/04/2019 |
| 0.5.3           | 4.20.13        | 04/03/2019	|
| 0.5.2           | 4.20.11        | 21/02/2019 |
| 0.5.1           | 4.20.7         | 11/02/2019 |
| 0.5.0           | 4.20.5         | 30/01/2019	|
| 0.4.6           | 4.20           | 05/01/2019 |
| 0.4.5           | 4.18.16        | 24/10/2018 |
| 0.4.4           | 4.17.17        | 19/08/2018 |
| 0.4.3           | 4.17.4         | 06/07/2018 |
| 0.4.2           | 4.16.13        | 05/06/2018 |
| 0.4.1           | 4.16.12        | 28/05/2018 |
| 0.4.0           | 4.16.12        | 26/05/2018 |
| 0.3.11          | 4.14.18        | 09/02/2018 |
| 0.3.10          | 4.14.15        | 27/01/2018 |
| 0.3.9           | 4.14.9         | 27/12/2017 |
| 0.3.8           | 4.14.5         | 12/12/2017 |
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

## v0.7.3
```
- Epoch starts from zero instead of one (0 before daemon, 1 after daemon start).
- Consider node version for edge compression.
- Namespaces associated to tasks instead of process state (align with kernel).
- Update to kernel version 5.11.2.
```

## v0.7.2
```
- Fix ingress/egress network filter.
- Reverse 0.7.1 (expect for what appear bellow).
-- Made git dependencies explicit.
-- Change to how taints are handled.
-- Remove dependencies related to READING_FIRMWARE_PREALLOC_BUFFER (which was removed from mainline).
- Update to kernel version 5.11.2.
```

## v0.7.1
```
- Record packet length properly.
- Remove dependencies related to READING_FIRMWARE_PREALLOC_BUFFER (which was removed from mainline).
- Made git dependencies explicit.
- Rename build (SECURITY_PROVENANCE_WHOLE_SYSTEM -> SECURITY_PROVENANCE_BOOT).
- Track copy up (overlayfs) operations.
- Change the way setgid is handled.
- Read/Write self applies to tasks (aka threads).
- Change to how taints are handled.
- Clean up UAPI header files.
- Update to kernel version 5.9.11.
```

## v0.7.0
```
- Change build directory structure.
- Update to kernel version 5.7.7.
```

## v0.6.7
```
- Changes the way patches are generated and handled.
- Update to kernel version 5.6.15.
```

## v0.6.6
```
- Modified CircleCI workflow to test build with clang.
- Fix issue where policy hash will change once provenance is written.
- Fix issue where file reference counter was not properly released.
- Update to kernel version 5.6.7.
```

## v0.6.5
```
- Fix issue to build on Fedora 31 (new gcc version etc.).
- Update to kernel version 5.5.11.
```

## v0.6.4
```
- Use kernel linked list to build boot buffer.
- Refactoring of layering interface (accommodate changes to libprovenance).
- Add ptrace support.
- Update to kernel version 5.4.15.
```

## v0.6.3
```
- Resource accounting metrics associated with task instead of process.
- Fix potential memory leak when reading policy hash.
- Fix potential memory leak when creating new relay channel.
- Update to kernel version 5.2.9.
```

## v0.6.2
```
- Ensure that the propagate query is on from the start
- Fix interaction with process self-provenance.
- Hotfix: fix issue when load order changes.
```

## v0.6.1
```
- Remove extra pr_info in record address (left from debugging).
- Update to kernel version 5.1.9.
```

## v0.6.0
```
- Remove RL_NAMED_PROCESS as it was not used.
- Add RL_ADDRESSED relation.
- Add RL_RENAME relation.
- Add RL_CONNECT_UNIX_STREAM relation.
- Add RL_LOAD_UNDEFINED relation.
- Ensure inode_alloc_security does not generate provenance.
- Ensure sk_alloc_security does not generate provenance.
- Ensure inode_setxattr does not generate provenance.
- Ensure inode_getsecurity does not generate provenance.
- Associate task_id with relations.
- Simplified boot buffer implementation.
- Internal refactoring.
- Split uapi/linux/provenance.h between uapi/linux/provenance.h, uapi/linux/provenance_fs.h, uapi/linux/provenance_utils.h
- Update to kernel version 5.O.10.
```

## v0.5.3
```
- Hot Fix: fix issue with latest gcc release.
- Update to kernel version 4.20.13.
```

## v0.5.2
```
- Dump boot buffer in async mode.
- Reworked on the "link" family is represented.
- Fix issue where kernel loading (module, firmware etc.) was ignoring all option.
- Track more data loaded to kernel (firmware, policy, certificates and modules, previously only modules).
- Update to kernel version 4.20.11.
```

## v0.5.1
```
- Properly associate epoch with relation.
- Return error if machine or boot ID are set to 0.
- Update to kernel version 4.20.7.
```

## v0.5.0
```
- Reworking mmap handling logic (was last modified in 0.4.0).
- Take into account propagate node policy.
- Fix memory deadlock issue on boot for some configurations.
- Reworked boot buffer.
- Represent kernel more explicitly in the provenance graph.
- Provide API to get commit ID to help with issue tracking.
- Update to kernel version 4.20.5.
```

## v0.4.6
```
- Hotfix: fix  tracking issue.
- Update to kernel version 4.20.
```

## v0.4.5
```
- Record graph in full once epoch changes.
- Fix issue with receive_unix connecting to process memory instead of peer socket.
- Add suport for socket_socketpair hook.
- Update to kernel version 4.18.16.
```

## v0.4.4
```
- Fix file splice_pipe_to_pipe so the thread initiating splice appears.
- Fix file_unmmap so the thread initiating the unmmap appears.
- Fix file_mmap so the thread initiating the mmap appears.
- Generate through code analysis provenance model for LSM hooks and system calls.
- Add epoch support.
- Update to kernel version 4.17.17.
```

## v0.4.3
```
- Added support for IO signal.
- Added support for file_lock.
- Perform code analysis as part of CI to assess LSM hooks coverage.
- Update to kernel version 4.17.4.
```

## v0.4.2
```
- Fix issue where thread were not made opaque.
- Automated documentation.
- Node name changes: file_name -> path and fifo -> pipe, process -> process_memory.
- Node macro renamed accordingly.
- Links rework.
- Delete relation RL_LINK_INODE.
- Added support for symlink operation (RL_SYMLINK).
- Added support for unlink operation (RL_UNLINK).
- Reintroduce packet content recording (optional).
- Update to kernel version 4.16.13.
```

See _note_ in release v0.4.0.

## v0.4.1
```
- Hotfix (revert some changes introduced in v0.4.0 as they were introducing a bug).
```

See _note_ in release v0.4.0.

## v0.4.0
```
- Support node duplication on/off.
- Reworking mmap handling logic.
- Added hook and relation type to capture open file descriptor sent over ipc.
- RL_CHANGE becomes RL_SETUID and RL_SETGID.
- Added new relation type: RL_PERM_APPEND.
- Added new relation type: RL_STR_SH_CREATE_READ and RL_STR_SH_CREATE_WRITE.
- Added new relation type: RL_STR_SH_ATTACH_READ and RL_STR_SH_ATTACH_WRITE.
- Added new relation type: RL_WRITE_IOCTL and RL_READ_IOCTL.
- Added new relation type: RL_SND_MSG_Q and RL_RCV_MSG_Q.
- Added new relation type: RL_SND_MSG and RL_RCV_MSG.
- Added new relation type: RL_CLONE_MEM.
- Split RL_CREATE into RL_SOCKET_CREATE, RL_MSG_CREATE and RL_INODE_CREATE.
- Re-introduce RL_SND_UNIX and RL_RCV_UNIX now that we have space.
- Added new relation type: RL_PROC_WRITE and RL_PROC_READ.
- Increased the maximum number of relation type supported.
- Protect (ro) a number of pointers after init.
- Handle signal.
- Revert single source of ID change.
- Update to kernel version 4.16.12.
```

_NOTE_ changes reverted in `v0.4.1` and re-introduced in `v0.4.2`:
```
- Changes in the following functions:
	- filter_update_node in security/provenance/include/provenance_filter.h: filter relation_type RL_NAMED_PROCESS.
	- update_inode_type in security/provenance/include/provenance_filter.h: remove filter_update_node function call in the function body because type variable is never a relation.
	- provenance_add_hooks in security/provenance/hooks.c: add code to check if allocating memory in provenance_cache and long_provenance_cache failed.
	- record_terminate in security/provenance/include/provenance_record.h: clear outgoing edge count of a terminate node.
	- __write_node in security/provenance/include/provenance_relay.h: remove setting boot_id.
	- record_task_name in security/provenance/include/provenance_task.h: return error code -ENOMEM when allocating buffer failed.
	- update_proc_perf in security/provenance/inclue/provenance_task.h: get mm from task instead of current when calling get_task_mm function.
	- record_read_xattr in security/provenance/include/provenance_inode.h: return error code -ENOMEM when allocating a new long provenance entry failed.
	- provenance_mmap_file in security/provenance/hooks.c: add a map type MAP_SHARED_VALIDATE.
	- provenance_mmap_file in security/provenance/hooks.c: return rc instead of hard-coded 0.
	- current_update_shst in security/provenance/include/provenance_task.h: return rc instead of hard-coded 0.
	- provenance_shm_alloc_security in security/provenance/hooks.c: RL_SH_CREATE_WRITE relation changes from uses to generates.
	- provenance_shm_shmat in security/provenance/hooks.c: RL_SH_ATTACH_WRITE relation changes from uses to generates.
	- socket_inode_provenance in security/provenance/include/provenance_net.h: change SOCK_INODE(sock) to simply inode.
	- provenance_socket_post_create in security/provenance/hooks.c: return -ENOMEM if socket inode provenance does not exist.
	- provenance_socket_bind in security/provenance/hooks.c: return rc instead of hard-coded 0 when provenance is opaque.
	- record_task_name in security/provenance/include/provenance_task.h: remove cred declaraction, then remove obtaining credential (and releasing it later) and checking its existence.
	- provenance_socket_sock_rcv_skb in security/provenance/hooks.c: return -ENOMEM if sk inode provenance does not exist.
	- prov_record_args in security/provenance/include/provenance_task.h: return rc instead of hard-coded 0 at the end (rc should be 0 at the end.)
- Change in the following defintions:
	- vm_read_exec_mayshare(flags) in security/provenance/include/provenance_task.h: vm_write(flags) is changed to vm_read(flags).
```

## v0.3.11
```
- RL_SND_UNIX and RL_RCV_UNIX replace by simply RL_SND and RL_RCV.
- Fix issue with user buffer in fs interface (only affected certain configuration).
- Update to kernel version 4.14.18.
```

## v0.3.10
```
- Add support for shmdt.
- Add support for pipe to pipe slice.
- Update to kernel version 4.14.15.
```

## v0.3.9
```
- Fix bug with machine ID not always being properly associated with nodes.
- Log machine and boot ID when set.
- Single source of ID.
- Generate git patch for linuxkit.
- Update to kernel version 4.14.9.
```

## v0.3.8
```
- Record munmap events.
- Capture flags value on relations.
- No more flags on xattr (value is now part of relation).
- Rework recording and filtering internal logic.
- Process node more detailed (pid, vpid, ppid, tgid).
- Add support for multiple relay channel.
- Expose version number via pseudofile.
- Update to kernel version 4.14.5.
```

## v0.3.7
```
- Change the syntax of the version number to make debian happy.
```

## v0.3.6
```
- Fix bug related to file path recording.
- Made node compression (introduced in v0.2.2) configurable from userspace.
- Removed unused relation types.  
- Update to kernel version 4.13.4.
```

## v0.3.5
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

## v0.3.4
```
- Non-datagram unix socket generates connected graph.
- Properly record arguments and environment variables.
- Implement UID and GID filtering.
- Handle properly inode changing type (in practice we observe file -> link).
- Fix sleep in provenance_inode_permission.
- Update to kernel version 4.12.4.
```

## v0.3.3
```
- Improve LSM support for Information Flow see https://github.com/CamFlow/camflow-dev/issues/41.
- Use netfilter per net registration.
- Update to kernel version 4.11.6.
```

## v0.3.2
```
- Fix issue created by reading pidns.
- Update to kernel version 4.11.3.
```

## v0.3.1
```
- Expose hash of currently loaded capture polciy to user space.
- Update filters to support namespaces based selection.
- Load netfilter on subsys_initcall.
- Load propagate "query" much earlier.
- Record all available namespace id.
- Update to kernel version 4.11.2.
```

## v0.3.0
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

## v0.2.3
```
- A variety of minor issues fixed through code analysis.
- Add support for travis (see https://travis-ci.org/) testing.
- Put back Unix socket recording.
- Persist provenance information across reboot.
- Anticipate upcoming changes: read only after initialisation of security hooks.
- Handle provenance through extended attributes.
- Update to kernel version 4.9.13.
```

## v0.2.2

```
- Fixed some rare deadlock issue.
- Change anti-cycle logic to significantly reduce node numbers (edge number
  remain constant)
- Change how certain target are applied internally.
- Application can be integrated to provenance by writing to a pseudo file.
- Update to kernel version 4.9.9.
```

## v0.2.1

```
- Performance improvement.
```

## v0.2.0

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

## v0.1.11

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

## v0.1.10

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

## v0.1.9

```
- Record whole-provenance at boot if option set in kernel config (off by default).
- Fix a deadlock bug.
- Record pid and vpid for task.
- Update to kernel version 4.4.28.
```

## v0.1.8

```
- Properly deal with MMAP_SHARED and MMAP_PRIVATE.
- Refine relation types in inode permission hooks.
- Deal with concurrency issues.
- Recording offset information.
- Record jiffies for every events (nodes, relationships).
- Update to kernel version 4.4.25.
```

## v0.1.7

```
- Config change: by default IFC is not set.
- Recording IPv4 incoming and outgoing packets.
- More sensible settings for relay buffer.
- Update to kernel version 4.4.23.
```

## v0.1.6

```
- Add API to mark files as trusted (IFC).
- Merge several pseudo files interface into a single one.
- Added taint tracking support.
- Replace byte sized flag, by bit sized one.
- Update to kernel version 4.4.21.
```

## v0.1.5

```
- Nodes updated only when relations are recorded.
- Rework provenance tracking propagation.
- More detailed mmap provenance recording.
- Task inherit property from the file they execute (tracking and opaque).
- Fix issues with tracking exec.
- Update to kernel version 4.4.19.
```


## v0.1.4

```
- Add pseudofile to manipulate file provenance settings.
- Add pseudofile to flush relay buffer.
- Edge renamed relation to align with W3C PROV model.
- Update to kernel version 4.4.16.
```

## v0.1.3

```
- Provide facility to filter nodes and edges in kernel.
- Added a string to the disclosed provenance node data structure.
- Provided provenance tracking depth setting (how far tracked flag is propagated).
- Add pseudo file for a process to request to be provenance-tracked.
- Modified provenance internal data structure and working to align with W3C Prov model.
- IFC and Provenance LSM are now part of the default configuration.
```

## v0.1.2

```
- Machine ID provided by kernel module.
- Added pseudo file to set the machine ID.
- Modified provenance data structure.
- Added dependency to userspace configuration service (loaded at boot time).
- Prevent duplications in the list of allowed bridges.
- Build and install configuration service.
```

## v0.1.1

```
- Reduce number of file name and address recorded, limit to tracked entities.
- Obfuscate tag value, to avoid side channel through created tags.
- Correct a bug that allowed the same tag to be added several times on files.
- Name of files should now be properly recorded.
- Security context recorded in audit.
- Update kernel from version 4.2.8 to version 4.4.6.
```

## v0.1.0

```
- Initial release.
```
