# LSM statistics
This file is generated automatically. DO NOT EDIT.

Total number of system calls that trigger no LSM hooks: 158

Those system calls are:

	__x64_sys_execveat

	__x64_sys_sysfs

	__x64_sys_flock

	__x64_sys_lchown16

	__x64_sys_chown16

	__x64_sys_fchown16

	__x64_sys_copy_file_range

	__x64_sys_delete_module

	__x64_sys_init_module

	__x64_sys_finit_module

	__x64_sys_getresuid

	__x64_sys_getresgid

	__x64_sys_getpid

	__x64_sys_gettid

	__x64_sys_getppid

	__x64_sys_getuid

	__x64_sys_geteuid

	__x64_sys_getgid

	__x64_sys_getegid

	__x64_sys_umask

	__x64_sys_getcpu

	__x64_sys_mprotect

	__x64_sys_pkey_mprotect

	__x64_sys_pkey_alloc

	__x64_sys_pkey_free

	__x64_sys_remap_file_pages

	__x64_sys_msgsnd

	__x64_sys_msgrcv

	__x64_sys_msgget

	__x64_sys_msgctl

	__x64_sys_process_vm_readv

	__x64_sys_process_vm_writev

	__x64_sys_shmget

	__x64_sys_shmctl

	__x64_sys_shmat

	__x64_sys_shmdt

	__x64_sys_time

	__x64_sys_getgroups

	__x64_sys_getgroups16

	__x64_sys_setgroups

	__x64_sys_setgroups16

	__x64_sys_acct

	__x64_sys_personality

	__x64_sys_timer_getoverrun

	__x64_sys_sched_get_priority_max

	__x64_sys_sched_get_priority_min

	__x64_sys_restart_syscall

	__x64_sys_kexec_load

	__x64_sys_kexec_file_load

	__x64_sys_set_tid_address

	__x64_sys_futex

	__x64_sys_init_module

	__x64_sys_delete_module

	__x64_sys_sgetmask

	__x64_sys_bdflush

	__x64_sys_mremap

	__x64_sys_msync

	__x64_sys_fadvise64

	__x64_sys_fadvise64_64

	__x64_sys_mlock

	__x64_sys_munlock

	__x64_sys_mlockall

	__x64_sys_munlockall

	__x64_sys_madvise

	__x64_sys_mincore

	__x64_sys_io_setup

	__x64_sys_io_destroy

	__x64_sys_io_getevents

	__x64_sys_io_submit

	__x64_sys_io_cancel

	__x64_sys_setregid16

	__x64_sys_setgid16

	__x64_sys_setreuid16

	__x64_sys_setuid16

	__x64_sys_setresuid16

	__x64_sys_getresuid16

	__x64_sys_setresgid16

	__x64_sys_getresgid16

	__x64_sys_setfsuid16

	__x64_sys_setfsgid16

	__x64_sys_getgroups16

	__x64_sys_setgroups16

	__x64_sys_getuid16

	__x64_sys_geteuid16

	__x64_sys_getgid16

	__x64_sys_getegid16

	__x64_sys_lookup_dcookie

	__x64_sys_quotactl

	__x64_sys_epoll_create

	__x64_sys_epoll_create1

	__x64_sys_epoll_ctl

	__x64_sys_epoll_wait

	__x64_sys_epoll_pwait

	__x64_sys_semget

	__x64_sys_semop

	__x64_sys_semctl

	__x64_sys_semtimedop

	__x64_sys_mq_open

	__x64_sys_mq_unlink

	__x64_sys_mq_timedsend

	__x64_sys_mq_timedreceive

	__x64_sys_mq_notify

	__x64_sys_mq_getsetattr

	__x64_sys_swapon

	__x64_sys_swapoff

	__x64_sys_sysfs

	__x64_sys_add_key

	__x64_sys_request_key

	__x64_sys_keyctl

	__x64_sys_ioprio_set

	__x64_sys_ioprio_get

	__x64_sys_set_mempolicy

	__x64_sys_migrate_pages

	__x64_sys_move_pages

	__x64_sys_mbind

	__x64_sys_get_mempolicy

	__x64_sys_inotify_init

	__x64_sys_inotify_init1

	__x64_sys_inotify_add_watch

	__x64_sys_inotify_rm_watch

	__x64_sys_get_robust_list

	__x64_sys_set_robust_list

	__x64_sys_signalfd

	__x64_sys_signalfd4

	__x64_sys_timerfd_create

	__x64_sys_timerfd_settime

	__x64_sys_timerfd_gettime

	__x64_sys_eventfd

	__x64_sys_eventfd2

	__x64_sys_memfd_create

	__x64_sys_userfaultfd

	__x64_sys_fanotify_init

	__x64_sys_fanotify_mark

	__x64_sys_name_to_handle_at

	__x64_sys_open_by_handle_at

	__x64_sys_seccomp

	__x64_sys_mlock2

	__x64_sys_shutdown

	__x64_sys_setsockopt

	__x64_sys_getsockopt

	__x64_sys_bind

	__x64_sys_connect

	__x64_sys_accept

	__x64_sys_accept4

	__x64_sys_getsockname

	__x64_sys_getpeername

	__x64_sys_send

	__x64_sys_sendto

	__x64_sys_sendmsg

	__x64_sys_sendmmsg

	__x64_sys_recv

	__x64_sys_recvfrom

	__x64_sys_recvmsg

	__x64_sys_recvmmsg

	__x64_sys_socket

	__x64_sys_socketpair

	__x64_sys_socketcall

	__x64_sys_listen

## Statistics of System Calls That Trigger LSM Hooks
SYSTEM CALL NAME | NUMBER OF HOOKS CALLED |
-----------------|------------------------|
__x64_sys_writev|7|
__x64_sys_sync|7|
__x64_sys_sigsuspend|5|
__x64_sys_execve|38|
__x64_sys_fallocate|7|
__x64_sys_fchdir|8|
__x64_sys_clone|27|
__x64_sys_preadv2|7|
__x64_sys_stat|16|
__x64_sys_llistxattr|17|
__x64_sys_times|5|
__x64_sys_tee|6|
__x64_sys_sched_getattr|6|
__x64_sys_ioctl|10|
__x64_sys_sigpending|5|
__x64_sys_statfs64|16|
__x64_sys_syncfs|6|
__x64_sys_sched_setparam|6|
__x64_sys_sigaltstack|5|
__x64_sys_fsync|6|
__x64_sys_rt_sigsuspend|5|
__x64_sys_read|7|
__x64_sys_setgid|9|
__x64_sys_sched_getscheduler|1|
__x64_sys_lsetxattr|18|
__x64_sys_bpf|27|
__x64_sys_creat|29|
__x64_sys_newlstat|16|
__x64_sys_capget|6|
__x64_sys_flistxattr|8|
__x64_sys_setdomainname|5|
__x64_sys_clock_gettime|5|
__x64_sys_pwritev2|7|
__x64_sys_rt_sigaction|5|
__x64_sys_timer_gettime|5|
__x64_sys_fremovexattr|9|
__x64_sys_sysinfo|5|
__x64_sys_clock_nanosleep|5|
__x64_sys_fgetxattr|9|
__x64_sys_getxattr|17|
__x64_sys_readlink|16|
__x64_sys_sendfile64|7|
__x64_sys_utimes|18|
__x64_sys_setregid|9|
__x64_sys_newstat|16|
__x64_sys_timer_settime|5|
__x64_sys_old_getrlimit|5|
__x64_sys_link|17|
__x64_sys_renameat2|12|
__x64_sys_ioperm|6|
__x64_sys_getsid|1|
__x64_sys_fstatfs64|6|
__x64_sys_utimensat|18|
__x64_sys_wait4|9|
__x64_sys_membarrier|5|
__x64_sys_readahead|5|
__x64_sys_getrandom|5|
__x64_sys_mknodat|15|
__x64_sys_fchown|14|
__x64_sys_write|7|
__x64_sys_getpgid|1|
__x64_sys_mmap_pgoff|28|
__x64_sys_select|5|
__x64_sys_sched_getparam|6|
__x64_sys_fdatasync|6|
__x64_sys_fchmod|14|
__x64_sys_setresgid|9|
__x64_sys_old_readdir|7|
__x64_sys_setitimer|5|
__x64_sys_sched_setaffinity|6|
__x64_sys_prctl|15|
__x64_sys_unlinkat|14|
__x64_sys_lstat|16|
__x64_sys_oldumount|18|
__x64_sys_sched_getaffinity|6|
__x64_sys_newuname|5|
__x64_sys_faccessat|16|
__x64_sys_sethostname|5|
__x64_sys_rt_sigprocmask|5|
__x64_sys_fstatfs|6|
__x64_sys_preadv|7|
__x64_sys_clock_getres|5|
__x64_sys_ppoll|5|
__x64_sys_lremovexattr|16|
__x64_sys_gettimeofday|5|
__x64_sys_unlink|12|
__x64_sys_lchown|19|
__x64_sys_newfstatat|16|
__x64_sys_lgetxattr|17|
__x64_sys_getrusage|8|
__x64_sys_ftruncate|14|
__x64_sys_prlimit64|7|
__x64_sys_iopl|6|
__x64_sys_uname|5|
__x64_sys_alarm|5|
__x64_sys_nice|6|
__x64_sys_vmsplice|8|
__x64_sys_pivot_root|16|
__x64_sys_chown|19|
__x64_sys_timer_delete|5|
__x64_sys_chmod|19|
__x64_sys_getpriority|5|
__x64_sys_mmap|28|
__x64_sys_sysctl|5|
__x64_sys_pwrite64|7|
__x64_sys_pselect6|5|
__x64_sys_setfsgid|9|
__x64_sys_ptrace|16|
__x64_sys_clock_adjtime|5|
__x64_sys_pipe2|11|
__x64_sys_linkat|17|
__x64_sys_removexattr|16|
__x64_sys_fstat|6|
__x64_sys_timer_create|5|
__x64_sys_renameat|12|
__x64_sys_setfsuid|10|
__x64_sys_lseek|5|
__x64_sys_fork|27|
__x64_sys_sync_file_range|5|
__x64_sys_pread64|7|
__x64_sys_getdents|7|
__x64_sys_perf_event_open|12|
__x64_sys_statfs|16|
__x64_sys_getcwd|5|
__x64_sys_setxattr|18|
__x64_sys_getpgrp|1|
__x64_sys_fchownat|19|
__x64_sys_chdir|15|
__x64_sys_open|29|
__x64_sys_getitimer|5|
__x64_sys_symlink|12|
__x64_sys_access|16|
__x64_sys_llseek|5|
__x64_sys_mount|22|
__x64_sys_fchmodat|19|
__x64_sys_vfork|27|
__x64_sys_kill|7|
__x64_sys_umount|18|
__x64_sys_pause|5|
__x64_sys_rmdir|12|
__x64_sys_tgkill|7|
__x64_sys_rt_tgsigqueueinfo|7|
__x64_sys_sched_setscheduler|6|
__x64_sys_setsid|8|
__x64_sys_mknod|15|
__x64_sys_dup2|6|
__x64_sys_dup3|6|
__x64_sys_chroot|16|
__x64_sys_rt_sigtimedwait|5|
__x64_sys_rename|12|
__x64_sys_unshare|16|
__x64_sys_symlinkat|12|
__x64_sys_splice|8|
__x64_sys_fcntl|10|
__x64_sys_readv|7|
__x64_sys_exit|20|
__x64_sys_reboot|24|
__x64_sys_sendfile|7|
__x64_sys_rt_sigpending|5|
__x64_sys_sched_yield|5|
__x64_sys_setreuid|10|
__x64_sys_ssetmask|5|
__x64_sys_setuid|10|
__x64_sys_stime|9|
__x64_sys_syslog|6|
__x64_sys_adjtimex|8|
__x64_sys_setpriority|6|
__x64_sys_fsetxattr|11|
__x64_sys_capset|10|
__x64_sys_gethostname|5|
__x64_sys_sched_rr_get_interval|6|
__x64_sys_mkdirat|12|
__x64_sys_settimeofday|9|
__x64_sys_nanosleep|5|
__x64_sys_waitpid|9|
__x64_sys_getrlimit|6|
__x64_sys_olduname|5|
__x64_sys_pwritev|7|
__x64_sys_sigprocmask|5|
__x64_sys_setpgid|6|
__x64_sys_clock_settime|5|
__x64_sys_readlinkat|16|
__x64_sys_sync_file_range2|5|
__x64_sys_listxattr|17|
__x64_sys_rt_sigqueueinfo|7|
__x64_sys_brk|9|
__x64_sys_munmap|8|
__x64_sys_close|6|
__x64_sys_dup|5|
__x64_sys_mkdir|12|
__x64_sys_poll|5|
__x64_sys_exit_group|20|
__x64_sys_setrlimit|6|
__x64_sys_statx|16|
__x64_sys_newfstat|6|
__x64_sys_futimesat|18|
__x64_sys_setns|15|
__x64_sys_tkill|7|
__x64_sys_waitid|9|
__x64_sys_signal|5|
__x64_sys_ustat|7|
__x64_sys_utime|18|
__x64_sys_sched_setattr|6|
__x64_sys_truncate|19|
__x64_sys_pipe|11|
__x64_sys_setresuid|10|
__x64_sys_openat|29|
__x64_sys_getdents64|7|


## Statistics of Number of LSM Hooks Triggered by System Calls
NUMBER OF HOOKS CALLED | NUMBER OF SYSTEM CALLS |
-----------------------|------------------------|
1|4|
5|53|
6|28|
7|24|
8|8|
9|13|
10|7|
11|3|
12|10|
14|4|
15|5|
16|19|
17|6|
18|8|
19|6|
20|2|
22|1|
24|1|
27|4|
28|2|
29|3|
38|1|


## Statistics of System Calls Arranged by Weighted API Importance
WEIGHTED API CALL (MOST TO LEAST IMPORTANT) | NUMBER OF HOOKS CALLED |
--------------------------------------------|------------------------|
mmap|28|
vfork|27|
exit|20|
exit_group|20|
write|7|
read|7|
open|29|
gettid|N/A|
madvise|N/A|
munmap|8|
futex|N/A|
rt_sigprocmask|5|
fcntl|10|
close|6|
getuid|N/A|
mprotect|N/A|
getgid|N/A|
sched_yield|5|
getpid|N/A|
stat|16|
fstat|6|
lstat|16|
lseek|5|
tgkill|7|
getdents|7|
writev|7|
getcwd|5|
clock_getres|5|
getrlimit|6|
newfstatat|16|
openat|29|
dup2|6|
clone|27|
execve|38|
kill|7|
setresuid|10|
setresgid|9|
setpgid|6|
sched_setscheduler|6|
sched_setparam|6|
mremap|N/A|
ioctl|10|
access|16|
socket|N/A|
connect|N/A|
poll|5|
sendto|N/A|
recvmsg|N/A|
dup|5|
unlink|12|
uname|5|
nanosleep|5|
wait4|9|
readv|7|
geteuid|N/A|
readlink|16|
bind|N/A|
pipe|11|
getsockname|N/A|
mkdir|12|
select|5|
rename|12|
chdir|15|
getegid|N/A|
chmod|19|
setsockopt|N/A|
fchmod|14|
statfs|16|
recvfrom|N/A|
sendmsg|N/A|
fsync|6|
sched_get_priority_max|N/A|
sched_get_priority_min|N/A|
ftruncate|14|
umask|N/A|
rmdir|12|
pipe2|11|
getsockopt|N/A|
chown|19|
link|17|
fchown|14|
sigaltstack|5|
shutdown|N/A|
getppid|N/A|
setuid|10|
getresuid|N/A|
getresgid|N/A|
symlink|12|
fstatfs|6|
getpeername|N/A|
utimes|18|
socketpair|N/A|
alarm|5|
setsid|8|
getxattr|17|
lchown|19|
fallocate|7|
pread64|7|
eventfd2|N/A|
inotify_add_watch|N/A|
fgetxattr|9|
getgroups|N/A|
shmctl|N/A|
pwrite64|7|
inotify_init|N/A|
lgetxattr|17|
setxattr|18|
shmat|N/A|
prctl|15|
inotify_rm_watch|N/A|
listen|N/A|
inotify_init1|N/A|
setgid|9|
accept|N/A|
shmdt|N/A|
fadvise64|N/A|
shmget|N/A|
llistxattr|17|
listxattr|17|
flistxattr|8|
splice|8|
setrlimit|6|
setgroups|N/A|
epoll_ctl|N/A|
utime|18|
epoll_wait|N/A|
epoll_create1|N/A|
setpriority|6|
dup3|6|
sched_getparam|6|
mknod|15|
sched_getscheduler|1|
chroot|16|
sync|7|
fchdir|8|
creat|29|
mlock|N/A|
getpgrp|1|
utimensat|18|
getpriority|5|
setitimer|5|
times|5|
pselect6|5|
getrusage|8|
faccessat|16|
setreuid|10|
flock|N/A|
semget|N/A|
semctl|N/A|
ppoll|5|
msync|N/A|
capget|6|
sendmmsg|N/A|
fdatasync|6|
sched_getaffinity|6|
unlinkat|14|
readlinkat|16|
setregid|9|
rt_sigsuspend|5|
mount|22|
brk|9|
clock_gettime|5|
name_to_handle_at|N/A|
semop|N/A|
lsetxattr|18|
futimesat|18|
pause|5|
getpgid|1|
getsid|1|
fsetxattr|11|
sysinfo|5|
munlock|N/A|
settimeofday|9|
umount2|N/A|
rt_sigtimedwait|5|
timerfd_create|N/A|
timerfd_settime|N/A|
ptrace|16|
ioprio_set|N/A|
fchmodat|19|
fchownat|19|
accept4|N/A|
linkat|17|
mlockall|N/A|
sync_file_range|5|
mincore|N/A|
sethostname|5|
removexattr|16|
capset|10|
personality|N/A|
iopl|6|
sched_setaffinity|6|
reboot|24|
clock_settime|5|
unshare|16|
symlinkat|12|
getitimer|5|
ioperm|6|
renameat|12|
tkill|7|
mkdirat|12|
lremovexattr|16|
syslog|6|
rt_sigreturn|N/A|
msgctl|N/A|
msgget|N/A|
swapoff|N/A|
pivot_root|16|
swapon|N/A|
signalfd4|N/A|
setns|15|
ioprio_get|N/A|
timer_delete|5|
timer_create|5|
timer_settime|5|
mknodat|15|
setdomainname|5|
prlimit64|7|
vhangup|N/A|
epoll_create|N/A|
munlockall|N/A|
truncate|19|
init_module|N/A|
finit_module|N/A|
adjtimex|8|
waitid|9|
perf_event_open|12|
process_vm_readv|N/A|
sendfile|7|
readahead|5|
rt_sigaction|5|
arch_prctl|N/A|
gettimeofday|5|
time|N/A|
quotactl|N/A|
_sysctl|N/A|
msgsnd|N/A|
msgrcv|N/A|
clock_nanosleep|5|
get_mempolicy|N/A|
rt_sigpending|5|
mbind|N/A|
setfsuid|10|
fremovexattr|9|
setfsgid|9|
add_key|N/A|
keyctl|N/A|
set_tid_address|N/A|
set_robust_list|N/A|
getdents64|7|
fork|27|
delete_module|N/A|
request_key|N/A|
pwritev|7|
preadv|7|
ustat|7|
nfsservctl|N/A|
tee|6|
sched_rr_get_interval|6|
set_mempolicy|N/A|
io_submit|N/A|
io_setup|N/A|
mq_unlink|N/A|
mq_open|N/A|
io_destroy|N/A|
io_cancel|N/A|
signalfd|N/A|
migrate_pages|N/A|
kcmp|N/A|
renameat2|12|
clock_adjtime|5|
recvmmsg|N/A|
modify_ldt|N/A|
getcpu|N/A|
epoll_pwait|N/A|
rt_sigqueueinfo|7|
open_by_handle_at|N/A|
fanotify_mark|N/A|
fanotify_init|N/A|
acct|N/A|
mq_timedreceive|N/A|
timer_getoverrun|N/A|
semtimedop|N/A|
eventfd|N/A|
timerfd_gettime|N/A|
timer_gettime|5|
vmsplice|8|
mq_getsetattr|N/A|
mq_timedsend|N/A|
kexec_load|N/A|
afs_syscall|N/A|
uselib|N/A|
io_getevents|N/A|
syncfs|6|
vserver|N/A|
process_vm_writev|N/A|
security|N/A|
seccomp|N/A|
sched_setattr|6|
sched_getattr|6|
rt_tgsigqueueinfo|7|
getpmsg|N/A|
create_module|N/A|
get_thread_area|N/A|
sysfs|N/A|
putpmsg|N/A|
lookup_dcookie|N/A|
epoll_ctl_old|N/A|
epoll_wait_old|N/A|
get_robust_list|N/A|
set_thread_area|N/A|
remap_file_pages|N/A|
mq_notify|N/A|
tuxcall|N/A|
restart_syscall|N/A|
move_pages|N/A|
query_module|N/A|
get_kernel_syms|N/A|


## Statistics of System Calls Arranged by Unweighted API Importance
UNWEIGHTED API CALL (MOST TO LEAST IMPORTANT) | NUMBER OF HOOKS CALLED |
----------------------------------------------|------------------------|
exit|20|
mmap|28|
write|7|
exit_group|20|
open|29|
read|7|
madvise|N/A|
gettid|N/A|
futex|N/A|
munmap|8|
rt_sigprocmask|5|
clone|27|
close|6|
sched_yield|5|
mprotect|N/A|
getuid|N/A|
fcntl|10|
getgid|N/A|
lseek|5|
getcwd|5|
lstat|16|
getdents|7|
tgkill|7|
getpid|N/A|
stat|16|
writev|7|
clock_getres|5|
fstat|6|
getrlimit|6|
newfstatat|16|
openat|29|
execve|38|
dup2|6|
kill|7|
setpgid|6|
sched_setscheduler|6|
vfork|27|
setresgid|9|
setresuid|10|
sched_setparam|6|
ioctl|10|
mremap|N/A|
access|16|
socket|N/A|
connect|N/A|
sendto|N/A|
poll|5|
recvmsg|N/A|
dup|5|
uname|5|
unlink|12|
nanosleep|5|
rt_sigreturn|N/A|
rt_sigaction|5|
set_tid_address|N/A|
set_robust_list|N/A|
readv|7|
select|5|
wait4|9|
bind|N/A|
setsockopt|N/A|
sched_get_priority_max|N/A|
getsockname|N/A|
sched_get_priority_min|N/A|
geteuid|N/A|
recvfrom|N/A|
mkdir|12|
pipe|11|
getegid|N/A|
readlink|16|
shutdown|N/A|
chdir|15|
rename|12|
sendmsg|N/A|
pipe2|11|
chmod|19|
ftruncate|14|
statfs|16|
getsockopt|N/A|
rmdir|12|
getresuid|N/A|
getresgid|N/A|
getpeername|N/A|
shmdt|N/A|
fchmod|14|
shmctl|N/A|
shmat|N/A|
sigaltstack|5|
fsync|6|
listen|N/A|
eventfd2|N/A|
accept|N/A|
link|17|
fstatfs|6|
pread64|7|
fchown|14|
getppid|N/A|
pwrite64|7|
umask|N/A|
chown|19|
inotify_init|N/A|
inotify_add_watch|N/A|
inotify_rm_watch|N/A|
shmget|N/A|
inotify_init1|N/A|
fadvise64|N/A|
symlink|12|
socketpair|N/A|
setsid|8|
fallocate|7|
sched_getscheduler|1|
sched_getparam|6|
prctl|15|
times|5|
utimes|18|
lchown|19|
getxattr|17|
lgetxattr|17|
setxattr|18|
llistxattr|17|
fgetxattr|9|
splice|8|
listxattr|17|
flistxattr|8|
setuid|10|
alarm|5|
setgid|9|
setrlimit|6|
getrusage|8|
getgroups|N/A|
semget|N/A|
dup3|6|
semctl|N/A|
utime|18|
epoll_ctl|N/A|
epoll_wait|N/A|
clock_gettime|5|
semop|N/A|
sched_getaffinity|6|
getpgrp|1|
setgroups|N/A|
setpriority|6|
sync|7|
mknod|15|
setitimer|5|
msync|N/A|
epoll_create1|N/A|
sendmmsg|N/A|
mlock|N/A|
epoll_create|N/A|
getpriority|5|
fdatasync|6|
pselect6|5|
brk|9|
ppoll|5|
rt_sigsuspend|5|
chroot|16|
rt_sigtimedwait|5|
munlock|N/A|
creat|29|
pause|5|
flock|N/A|
mlockall|N/A|
truncate|19|
fchdir|8|
mbind|N/A|
sched_setaffinity|6|
timerfd_create|N/A|
rt_sigpending|5|
timerfd_settime|N/A|
setreuid|10|
getitimer|5|
getpgid|1|
mincore|N/A|
utimensat|18|
timer_delete|5|
sendfile|7|
getsid|1|
setregid|9|
timer_settime|5|
timer_create|5|
munlockall|N/A|
mount|22|
capget|6|
sysinfo|5|
accept4|N/A|
name_to_handle_at|N/A|
get_mempolicy|N/A|
set_mempolicy|N/A|
migrate_pages|N/A|
lsetxattr|18|
arch_prctl|N/A|
signalfd4|N/A|
ioprio_set|N/A|
faccessat|16|
fsetxattr|11|
ptrace|16|
tkill|7|
unlinkat|14|
readlinkat|16|
iopl|6|
rt_sigqueueinfo|7|
settimeofday|9|
personality|N/A|
umount2|N/A|
msgget|N/A|
ioperm|6|
symlinkat|12|
mkdirat|12|
removexattr|16|
msgctl|N/A|
msgsnd|N/A|
lremovexattr|16|
clock_nanosleep|5|
perf_event_open|12|
io_submit|N/A|
capset|10|
renameat|12|
io_setup|N/A|
linkat|17|
unshare|16|
reboot|24|
mknodat|15|
msgrcv|N/A|
time|N/A|
waitid|9|
fchownat|19|
gettimeofday|5|
fremovexattr|9|
sync_file_range|5|
tee|6|
ioprio_get|N/A|
adjtimex|8|
sethostname|5|
clock_settime|5|
futimesat|18|
quotactl|N/A|
setns|15|
pivot_root|16|
pwritev|7|
preadv|7|
io_cancel|N/A|
setfsuid|10|
io_destroy|N/A|
timer_gettime|5|
setfsgid|9|
timerfd_gettime|N/A|
readahead|5|
fchmodat|19|
swapoff|N/A|
syslog|6|
_sysctl|N/A|
recvmmsg|N/A|
timer_getoverrun|N/A|
signalfd|N/A|
swapon|N/A|
mq_open|N/A|
vhangup|N/A|
mq_unlink|N/A|
setdomainname|5|
getdents64|7|
add_key|N/A|
prlimit64|7|
acct|N/A|
fork|27|
semtimedop|N/A|
open_by_handle_at|N/A|
epoll_pwait|N/A|
delete_module|N/A|
afs_syscall|N/A|
mq_timedreceive|N/A|
process_vm_readv|N/A|
vmsplice|8|
init_module|N/A|
kcmp|N/A|
fanotify_init|N/A|
finit_module|N/A|
sched_rr_get_interval|6|
process_vm_writev|N/A|
fanotify_mark|N/A|
request_key|N/A|
syncfs|6|
keyctl|N/A|
modify_ldt|N/A|
eventfd|N/A|
io_getevents|N/A|
renameat2|12|
mq_timedsend|N/A|
getcpu|N/A|
security|N/A|
mq_getsetattr|N/A|
ustat|7|
uselib|N/A|
clock_adjtime|5|
sched_setattr|6|
nfsservctl|N/A|
seccomp|N/A|
vserver|N/A|
sched_getattr|6|
kexec_load|N/A|
epoll_ctl_old|N/A|
query_module|N/A|
sysfs|N/A|
get_kernel_syms|N/A|
rt_tgsigqueueinfo|7|
get_robust_list|N/A|
get_thread_area|N/A|
putpmsg|N/A|
getpmsg|N/A|
epoll_wait_old|N/A|
move_pages|N/A|
tuxcall|N/A|
mq_notify|N/A|
remap_file_pages|N/A|
set_thread_area|N/A|
restart_syscall|N/A|
create_module|N/A|
lookup_dcookie|N/A|
