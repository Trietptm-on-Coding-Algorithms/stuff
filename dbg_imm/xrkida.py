"""
http://hellojavaer.iteye.com/blog/1087823
#define SOCKOP_socket       1
#define SOCKOP_bind     2
#define SOCKOP_connect      3
#define SOCKOP_listen       4
#define SOCKOP_accept       5
#define SOCKOP_getsockname  6
#define SOCKOP_getpeername  7
#define SOCKOP_socketpair   8
#define SOCKOP_send     9
#define SOCKOP_recv     10
#define SOCKOP_sendto       11
#define SOCKOP_recvfrom     12
#define SOCKOP_shutdown     13
#define SOCKOP_setsockopt   14
#define SOCKOP_getsockopt   15
#define SOCKOP_sendmsg      16
#define SOCKOP_recvmsg      17
"""

# unistd.h
linux_sys_call_id_to_name = {0: "restart",
                             1: "exit",
                             2: "fork",
                             3: "read",
                             4: "write",
                             5: "open",
                             6: "close",
                             7: "waitpid",
                             8: "creat",
                             9: "link",
                             10: "unlink",
                             11: "execve",
                             12: "chdir",
                             13: "time",
                             14: "mknod",
                             15: "chmod",
                             16: "chown",
                             17: "break",
                             18: "oldstat",
                             19: "lseek",
                             20: "getpid",
                             21: "mount",
                             22: "umount",
                             23: "setuid",
                             24: "getuid",
                             25: "stime",
                             26: "ptrace",
                             27: "alarm",
                             28: "oldfstat",
                             29: "pause",
                             30: "utime",
                             31: "stty",
                             32: "gtty",
                             33: "access",
                             34: "nice",
                             35: "ftime",
                             36: "sync",
                             37: "kill",
                             38: "rename",
                             39: "mkdir",
                             40: "rmdir",
                             41: "dup",
                             42: "pipe",
                             43: "times",
                             44: "prof",
                             45: "brk",
                             46: "setgid",
                             47: "getgid",
                             48: "signal",
                             49: "geteuid",
                             50: "getegid",
                             51: "acct",
                             52: "umount2",
                             53: "lock",
                             54: "ioctl",
                             55: "fcntl",
                             56: "mpx",
                             57: "setpgid",
                             58: "ulimit",
                             59: "oldolduname",
                             60: "umask",
                             61: "chroot",
                             62: "ustat",
                             63: "dup2",
                             64: "getppid",
                             65: "getpgrp",
                             66: "setsid",
                             67: "sigaction",
                             68: "sgetmask",
                             69: "ssetmask",
                             70: "setreuid",
                             71: "setregid",
                             72: "sigsuspend",
                             73: "sigpending",
                             74: "sethostname",
                             75: "setrlimit",
                             76: "getrlimit",
                             77: "getrusage",
                             78: "gettimeofday",
                             79: "settimeofday",
                             80: "getgroups",
                             81: "setgroups",
                             82: "select",
                             83: "symlink",
                             84: "oldlstat",
                             85: "readlink",
                             86: "uselib",
                             87: "swapon",
                             88: "reboot",
                             89: "readdir",
                             90: "mmap",
                             91: "munmap",
                             92: "truncate",
                             93: "ftruncate",
                             94: "fchmod",
                             95: "fchown",
                             96: "getpriority",
                             97: "setpriority",
                             98: "profil",
                             99: "statfs",
                             100: "fstatfs",
                             101: "ioperm",
                             102: "socketcall",
                             103: "syslog",
                             104: "setitimer",
                             105: "getitimer",
                             106: "stat",
                             107: "lstat",
                             108: "fstat",
                             109: "olduname",
                             110: "iopl",
                             111: "vhangup",
                             112: "idle",
                             113: "vm86old",
                             114: "wait4",
                             115: "swapoff",
                             116: "sysinfo",
                             117: "ipc",
                             118: "fsync",
                             119: "sigreturn",
                             120: "clone",
                             121: "setdomainname",
                             122: "uname",
                             123: "modify_ldt",
                             124: "adjtimex",
                             125: "mprotect",
                             126: "sigprocmask",
                             127: "create_module",
                             128: "init_module",
                             129: "delete_module",
                             130: "get_kernel_syms",
                             131: "quotactl",
                             132: "getpgid",
                             133: "fchdir",
                             134: "bdflush",
                             135: "sysfs",
                             136: "personality",
                             137: "afs_syscall",
                             138: "setfsuid",
                             139: "setfsgid",
                             140: "llseek",
                             141: "getdents",
                             142: "newselect",
                             143: "flock",
                             144: "msync",
                             145: "readv",
                             146: "writev",
                             147: "getsid",
                             148: "fdatasync",
                             149: "sysctl",
                             150: "mlock",
                             151: "munlock",
                             152: "mlockall",
                             153: "munlockall",
                             154: "sched_setparam",
                             155: "sched_getparam",
                             156: "sched_setscheduler",
                             157: "sched_getscheduler",
                             158: "sched_yield",
                             159: "sched_get_priority_max",
                             160: "sched_get_priority_min",
                             161: "sched_rr_get_interval",
                             162: "nanosleep",
                             163: "mremap",
                             164: "setresuid",
                             165: "getresuid",
                             166: "vm86",
                             167: "query_module",
                             168: "poll",
                             169: "nfsservctl",
                             170: "setresgid",
                             171: "getresgid",
                             172: "prctl",
                             173: "rt_sigreturn",
                             174: "rt_sigaction",
                             175: "rt_sigprocmask",
                             176: "rt_sigpending",
                             177: "rt_sigtimedwait",
                             178: "rt_sigqueueinfo",
                             179: "rt_sigsuspend",
                             180: "pread",
                             181: "pwrite",
                             182: "lchown",
                             183: "getcwd",
                             184: "capget",
                             185: "capset",
                             186: "sigaltstack",
                             187: "sendfile",
                             188: "getpmsg",
                             189: "putpmsg",
                             190: "vfork",
                             191: "getrlimit",
                             192: "mmap2",
                             193: "truncate64",
                             194: "ftruncate64",
                             195: "stat64",
                             196: "lstat64",
                             197: "fstat64",
                             198: "chown32",
                             199: "getuid32",
                             200: "getgid32",
                             201: "geteuid32",
                             202: "getegid32",
                             203: "setreuid32",
                             204: "setregid32",
                             205: "getgroups32",
                             206: "setgroups32",
                             207: "fchown32",
                             208: "setresuid32",
                             209: "getresuid32",
                             210: "setresgid32",
                             211: "getresgid32",
                             212: "lchown32",
                             213: "setuid32",
                             214: "setgid32",
                             215: "setfsuid32",
                             216: "setfsgid32",
                             217: "pivot_root",
                             218: "mincore",
                             219: "madvise",
                             220: "getdents64",
                             221: "fcntl64",
                             222: "reversed",
                             223: "reversed",
                             224: "gettid",
                             225: "readahead",
                             226: "setxattr",
                             227: "lsetxattr",
                             228: "fsetxattr",
                             229: "getxattr",
                             230: "lgetxattr",
                             231: "fgetxattr",
                             232: "listxattr",
                             233: "llistxattr",
                             234: "flistxattr",
                             235: "removexattr",
                             236: "lremovexattr",
                             237: "fremovexattr",
                             238: "tkill",
                             239: "sendfile64",
                             240: "futex",
                             241: "sched_setaffinity",
                             242: "sched_getaffinity",
                             243: "set_thread_area",
                             244: "get_thread_area",
                             245: "io_setup",
                             246: "io_destroy",
                             247: "io_getevents",
                             248: "io_submit",
                             249: "io_cancel",
                             250: "alloc_hugepages",
                             251: "free_hugepages",
                             252: "exit_group",
                             253: "lookup_dcookie",
                             254: "bfin_spinlock",
                             255: "epoll_create",
                             256: "epoll_ctl",
                             257: "epoll_wait",
                             258: "remap_file_pages",
                             259: "set_tid_address",
                             260: "timer_create",
                             261: "timer_settime",
                             262: "timer_gettime",
                             263: "timer_getoverrun",
                             264: "timer_delete",
                             265: "clock_settime",
                             266: "clock_gettime",
                             267: "clock_getres",
                             268: "clock_nanosleep",
                             269: "statfs64",
                             270: "fstatfs64",
                             271: "tgkill",
                             272: "utimes",
                             273: "fadvise64_64",
                             274: "vserver",
                             275: "mbind",
                             276: "get_mempolicy",
                             277: "set_mempolicy",
                             278: "mq_open",
                             279: "mq_unlink",
                             280: "mq_timedsend",
                             281: "mq_timedreceive",
                             282: "mq_notify",
                             283: "mq_getsetattr",
                             284: "kexec_load",
                             285: "waitid",
                             286: "add_key",
                             287: "request_key",
                             288: "keyctl",
                             289: "ioprio_set",
                             290: "ioprio_get",
                             291: "inotify_init",
                             292: "inotify_add_watch",
                             293: "inotify_rm_watch",
                             294: "migrate_pages",
                             295: "openat",
                             296: "mkdirat",
                             297: "mknodat",
                             298: "fchownat",
                             299: "futimesat",
                             300: "fstatat64",
                             301: "unlinkat",
                             302: "renameat",
                             303: "linkat",
                             304: "symlinkat",
                             305: "readlinkat",
                             306: "fchmodat",
                             307: "faccessat",
                             308: "pselect6",
                             309: "ppoll",
                             310: "unshare",
                             311: "sram_alloc",
                             312: "sram_free",
                             313: "dma_memcpy",
                             314: "accept",
                             315: "bind",
                             316: "connect",
                             317: "getpeername",
                             318: "getsockname",
                             319: "getsockopt",
                             320: "listen",
                             321: "recv",
                             322: "recvfrom",
                             323: "recvmsg",
                             324: "send",
                             325: "sendmsg",
                             326: "sendto",
                             327: "setsockopt",
                             328: "shutdown",
                             329: "socket",
                             330: "socketpair",
                             331: "semctl",
                             332: "semget   ",
                             333: "semop",
                             334: "msgctl",
                             335: "msgget",
                             336: "msgrcv",
                             337: "msgsnd",
                             338: "shmat",
                             339: "shmctl",
                             340: "shmdt",
                             341: "shmget",
                             342: "splice",
                             343: "sync_file_range",
                             344: "tee",
                             345: "vmsplice",
                             346: "epoll_pwait",
                             347: "utimensat",
                             348: "signalfd",
                             349: "timerfd_create",
                             350: "eventfd",
                             351: "pread64",
                             352: "pwrite64",
                             353: "fadvise64",
                             354: "set_robust_list",
                             355: "get_robust_list",
                             356: "fallocate",
                             357: "semtimedop",
                             358: "timerfd_settime",
                             359: "timerfd_gettime",
                             360: "signalfd4",
                             361: "eventfd2",
                             362: "epoll_create1",
                             363: "dup3",
                             364: "pipe2",
                             365: "inotify_init1",
                             366: "preadv",
                             367: "pwritev",
                             368: "rt_tgsigqueueinfo",
                             369: "perf_event_open",
                             370: "recvmmsg",
                             371: "fanotify_init",
                             372: "fanotify_mark",
                             373: "prlimit64",
                             374: "cacheflush",
                             375: "name_to_handle_at",
                             376: "open_by_handle_at",
                             377: "clock_adjtime",
                             378: "syncfs",
                             379: "setns",
                             380: "sendmmsg",
                             381: "process_vm_readv",
                             382: "process_vm_writev",
                             383: "kcmp",
                             384: "finit_module",
                             385: "sched_setattr",
                             386: "sched_getattr",
                             387: "renameat2",
                             388: "seccomp",
                             389: "getrandom",
                             390: "memfd_create",
                             391: "bpf",
                             392: "execveat",
                             393: "syscall"}
