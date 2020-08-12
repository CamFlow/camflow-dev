# Relations supported by CamFlow

Automatically generated do not edit!

As defined in #include<linux/provenance_types.h>|string in configuration file and CLI|Description|
------------------------------------------------|------------------------------------|-----------|
RL_UNKNOWN|unknown|unknown relation should not happen|
RL_READ|read|read to inode|
RL_READ_IOCTL|read_ioctl|ioctl read|
RL_WRITE|write|write to inode|
RL_WRITE_IOCTL|write_ioctl|ioctl write|
RL_CLONE_MEM|clone_mem|memory copy on clone|
RL_MSG_CREATE|msg_create|create msg |
RL_SOCKET_CREATE|socket_create|create socket|
RL_SOCKET_PAIR_CREATE|socket_pair_create|create socket pair|
RL_INODE_CREATE|inode_create|create inode|
RL_SETUID|setuid|setuid|
RL_SETGID|setpgid|setpgid|
RL_GETGID|getpgid|getpgid|
RL_SH_WRITE|sh_write|writing to shared state|
RL_PROC_WRITE|memory_write|writing to process memory |
RL_BIND|bind|socket bind operation|
RL_CONNECT|connect|socket connection operation|
RL_CONNECT_UNIX_STREAM|connect_unix_stream|unix stream socket connection operation|
RL_LISTEN|listen|socket listen operation|
RL_ACCEPT|accept|socket accept operation|
RL_OPEN|open|file open operation|
RL_FILE_RCV|file_rcv|open file descriptor recevied through IPC|
RL_FILE_LOCK|file_lock|represent file lock operation|
RL_FILE_SIGIO|file_sigio|represent IO signal|
RL_VERSION|version_entity|connect version of entity object|
RL_MUNMAP|munmap|munmap operation|
RL_SHMDT|shmdt|shmdt operation|
RL_LINK|link|create a link|
RL_RENAME|rename|rename inode|
RL_UNLINK|unlink|delete a link|
RL_SYMLINK|symlink|create a symlink|
RL_SPLICE_IN|splice_in|pipe splice operation from in file|
RL_SPLICE_OUT|splice_out|pipe splice operation to out file|
RL_SETATTR|setattr|setattr operation |
RL_SETATTR_INODE|setattr_inode|setattr operation |
RL_ACCEPT_SOCKET|accept_socket|accept operation |
RL_SETXATTR|setxattr|setxattr operation |
RL_SETXATTR_INODE|setxattr_inode|setxattr operation |
RL_RMVXATTR|removexattr|remove xattr operation |
RL_RMVXATTR_INODE|removexattr_inode|remove xattr operation |
RL_NAMED|named|connect path to inode|
RL_ADDRESSED|addressed|connect address to inode|
RL_EXEC|exec|exec operation|
RL_EXEC_TASK|exec_task|exec operation|
RL_PCK_CNT|packet_content|connect netwrok packet to its content|
RL_CLONE|clone|clone operation|
RL_VERSION_TASK|version_activity|connection two versions of an activity|
RL_SEARCH|search|search operation on directory|
RL_GETATTR|getattr|getattr operation|
RL_GETXATTR|getxattr|getxattr operation |
RL_GETXATTR_INODE|getxattr_inode|getxattr operation |
RL_LSTXATTR|listxattr|listxattr operation|
RL_READ_LINK|read_link|readlink operation|
RL_MMAP_READ|mmap_read|mmap mounting with read perm|
RL_MMAP_EXEC|mmap_exec|mmap mounting with exec perm|
RL_MMAP_WRITE|mmap_write|mmap mounting with write perm|
RL_MMAP_READ_PRIVATE|mmap_read_private|mmap private mounting with read perm|
RL_MMAP_EXEC_PRIVATE|mmap_exec_private|mmap private mounting with exec perm|
RL_MMAP_WRITE_PRIVATE|mmap_write_private|mmap private  mounting with write perm|
RL_SH_READ|sh_read|sh_read operation|
RL_PROC_READ|memory_read|read from process memory|
RL_SND|send|send over socket|
RL_SND_PACKET|send_packet|connect socket to packet on send operation|
RL_SND_UNIX|send_unix|send over unix socket|
RL_SND_MSG|send_msg|send message|
RL_SND_MSG_Q|send_msg_queue|send message to queue|
RL_RCV|receive|receive socket operation|
RL_RCV_PACKET|receive_packet|connect packet to socket on receive operation|
RL_RCV_UNIX|receive_unix|receive on unix socket|
RL_RCV_MSG|receive_msg|receive message|
RL_RCV_MSG_Q|receive_msg_queue|receive message from queue|
RL_PERM_READ|perm_read|check read permission|
RL_PERM_WRITE|perm_write|check write permission|
RL_PERM_EXEC|perm_exec|check exec permission|
RL_PERM_APPEND|perm_append|check append permission|
RL_TERMINATE_TASK|terminate_task|created when task data structure is freed|
RL_TERMINATE_PROC|terminate_proc|created when cred data structure is freed|
RL_FREED|free|created when an inode is freed|
RL_ARG|arg|connect arg value to process|
RL_ENV|env|connect env value to process|
RL_LOG|log|connect string to task|
RL_SH_ATTACH_READ|sh_attach_read|attach sh with read perm|
RL_SH_ATTACH_WRITE|sh_attach_write|attach sh with write perm|
RL_SH_CREATE_READ|sh_create_read|sh create with read perm|
RL_SH_CREATE_WRITE|sh_create_write|sh create with write perm|
RL_LOAD_FILE|load_file|load file into kernel|
RL_RAN_ON|ran_on|task run on this machine|
RL_LOAD_UNKNOWN|load_unknown|load file into kernel|
RL_LOAD_FIRMWARE|load_firmware|load file into kernel|
RL_LOAD_FIRMWARE_PREALLOC_BUFFER|load_firmware_prealloc_buffer|load file into kernel|
RL_LOAD_MODULE|load_module|load file into kernel|
RL_LOAD_KEXEC_IMAGE|load_kexec_image|load file into kernel|
RL_LOAD_KEXEC_INITRAMFS|load_kexec_initramfs|load file into kernel|
RL_LOAD_POLICY|load_policy|load file into kernel|
RL_LOAD_CERTIFICATE|load_certificate|load file into kernel|
RL_LOAD_UNDEFINED|load_undefined|load file into kernel|
RL_COPY_UP_NEW_CRED|copy_up_new_cred|overlayfs copy up create temporary cred|
RL_COPY_UP_INODE|copy_up_inode|overlayfs action on inode|
RL_PTRACE_ATTACH|ptrace_attach|ptrace attach effect on memory|
RL_PTRACE_READ|ptrace_read|ptrace read from mem|
RL_PTRACE_ATTACH_TASK|ptrace_attach_task|write info via ptrace effect on task|
RL_PTRACE_READ_TASK|ptrace_read_task|read info via ptrace effect on task|
RL_PTRACE_TRACEME|ptrace_traceme|track ptrace_traceme|
RL_DERIVED_DISC|derived_disc|disclosed type|
RL_GENERATED_DISC|generated_disc|disclosed type|
RL_USED_DISC|used_disc|disclosed type|
RL_INFORMED_DISC|informed_disc|disclosed type|
RL_INFLUENCED_DISC|influenced_disc|disclosed type|
RL_ASSOCIATED_DISC|associated_disc|disclosed type|
