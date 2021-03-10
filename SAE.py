import os
import multiprocessing

class StatusMessage:
    def __init__(self, a=None, b=None, c=None, d=None):
        '''
            $MSG = text to be send
            $TYPE = ['ok', 'warn', 'fail', 'notice']
            $STYLE = ['1: display color/bold on [TAG]', '2: display color/bold on all']
            $ICON = [y, n]
        '''
        self.msg = a
        self.type = b
        self.style = c
        self.icon = d

    def meow(self):
        print('meow!')

    def p_msg(self, msg, type, style, icon):
        # Set colors to be called
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        CYAN = '\033[36m'
        BOLD = '\033[1m'
        RESET = '\033[0m'

        if type == 'ok':
            if icon == 'y':
                icon = '☑ '
            else:
                icon = ""
            if style == '1':
                print(GREEN + BOLD + f'{icon}[PURR]' + RESET + f' {msg}')
            if style == '2':
                print(GREEN + BOLD + f'{icon}[PURR] {msg}' + RESET)

        if type == 'warn':
            if icon == 'y':
                icon = '⚠ '
            else:
                icon = ""
            if style == '1':
                print(YELLOW + BOLD + f'{icon}[RAWR]' + RESET + f' {msg}')
            if style == '2':
                print(YELLOW + BOLD + f'{icon}[RAWR] {msg}' + RESET)

        if type == 'fail':
            if icon == 'y':
                icon = '☒ '
            else:
                icon = ""
            if style == '1':
                print(RED + BOLD + f'{icon}[HISS]' + RESET + f' {msg}')
            if style == '2':
                print(RED + BOLD + f'{icon}[HISS] {msg}' + RESET)

        if type == 'notice':
            if icon == 'y':
                icon = '😺 '
            else:
                icon = ""
            if style == '1':
                print(CYAN + BOLD + f'{icon}[MEOW]' + RESET + f' {msg}')
            if style == '2':
                print(CYAN + BOLD + f'{icon}[MEOW] {msg}' + RESET)

sm = StatusMessage()

#
# set global variables
#

# https://github.com/torvalds/linux/blob/v4.17/arch/x86/entry/syscalls/syscall_64.tbl#L11
SysCall64List = ['read','write','open','close','stat','fstat','lstat','poll','lseek','mmap','mprotect','munmap','brk','rt_sigaction','rt_sigprocmask','rt_sigreturn','ioctl','pread','pwrite','readv','writev','access','pipe','select','sched_yield','mremap','msync','mincore','madvise','shmget','shmat','shmctl','dup','dup2','pause','nanosleep','getitimer','alarm','setitimer','getpid','sendfile','socket','connect','accept','sendto','recvfrom','sendmsg','recvmsg','shutdown','bind','listen','getsockname','getpeername','socketpair','setsockopt','getsockopt','clone','fork','vfork','execve','exit','wait4','kill','uname','semget','semop','semctl','shmdt','msgget','msgsnd','msgrcv','msgctl','fcntl','flock','fsync','fdatasync','truncate','ftruncate','getdents','getcwd','chdir','fchdir','rename','mkdir','rmdir','creat','link','unlink','symlink','readlink','chmod','fchmod','chown','fchown','lchown','umask','gettimeofday','getrlimit','getrusage','sysinfo','times','ptrace','getuid','syslog','getgid','setuid','setgid','geteuid','getegid','setpgid','getppid','getpgrp','setsid','setreuid','setregid','getgroups','setgroups','setresuid','getresuid','setresgid','getresgid','getpgid','setfsuid','setfsgid','getsid','capget','capset','rt_sigpending','rt_sigtimedwait','rt_sigqueueinfo','rt_sigsuspend','sigaltstack','utime','mknod','uselib','personality','ustat','statfs','fstatfs','sysfs','getpriority','setpriority','sched_setparam','sched_getparam','sched_setscheduler','sched_getscheduler','sched_get_priority_max','sched_get_priority_min','sched_rr_get_interval','mlock','munlock','mlockall','munlockall','vhangup','modify_ldt','pivot_root','_sysctl','prctl','arch_prctl','adjtimex','setrlimit','chroot','sync','acct','settimeofday','mount','umount2','swapon','swapoff','reboot','sethostname','setdomainname','iopl','ioperm','create_module','init_module','delete_module','get_kernel_syms','query_module','quotactl','nfsservctl','getpmsg','putpmsg','afs_syscall','tuxcall','security','gettid','readahead','setxattr','lsetxattr','fsetxattr','getxattr','lgetxattr','fgetxattr','listxattr','llistxattr','flistxattr','removexattr','lremovexattr','fremovexattr','tkill','time','futex','sched_setaffinity','sched_getaffinity','set_thread_area','io_setup','io_destroy','io_getevents','io_submit','io_cancel','get_thread_area','lookup_dcookie','epoll_create','epoll_ctl_old','epoll_wait_old','remap_file_pages','getdents64','set_tid_address','restart_syscall','semtimedop','fadvise64','timer_create','timer_settime','timer_gettime','timer_getoverrun','timer_delete','clock_settime','clock_gettime','clock_getres','clock_nanosleep','exit_group','epoll_wait','epoll_ctl','tgkill','utimes','vserver','mbind','set_mempolicy','get_mempolicy','mq_open','mq_unlink','mq_timedsend','mq_timedreceive','mq_notify','mq_getsetattr','kexec_load','waitid','add_key','request_key','keyctl','ioprio_set','ioprio_get','inotify_init','inotify_add_watch','inotify_rm_watch','migrate_pages','openat','mkdirat','mknodat','fchownat','futimesat','newfstatat','unlinkat','renameat','linkat','symlinkat','readlinkat','fchmodat','faccessat','pselect6','ppoll','unshare','set_robust_list','get_robust_list','splice','tee','sync_file_range','vmsplice','move_pages','utimensat','epoll_pwait','signalfd','timerfd_create','eventfd','fallocate','timerfd_settime','timerfd_gettime','accept4','signalfd4','eventfd2','epoll_create1','dup3','pipe2','inotify_init1','preadv','pwritev','rt_tgsigqueueinfo','perf_event_open','recvmmsg','fanotify_init','fanotify_mark','prlimit64','name_to_handle_at','open_by_handle_at','clock_adjtime','syncfs','sendmmsg','setns','getcpu','process_vm_readv','process_vm_writev','kcmp','finit_module','sched_setattr','sched_getattr','renameat2','seccomp','getrandom','memfd_create','kexec_file_load','bpf','execveat','userfaultfd','membarrier','mlock2','copy_file_range','preadv2','pwritev2','pkey_mprotect','pkey_alloc','pkey_free','statx','io_pgetevents','rseq']
FoundInList = []
FilePath = '/root/test'
suffix = '.LOG'
Threads = 4

def common_elements(list1, list2):
    result = []
    for element in list1:
        if element in list2:
            result.append(element)
    return result

#
# dump syscalls to log files from loaded files
#
def syscall_finder(filename: str):
    sm.p_msg('Loading File: ' + filename, 'notice', '1', 'y')
    os.system("strace "+filename+" 2>&1 >/dev/null | grep -P -o '^[a-z]*(?=\()' | sort | uniq > "+filename+".LOG")
    sm.p_msg('File Scanned for SysCalls: ' + filename, 'ok', '1', 'y')

#
# pull syscalls from the extracted files
#
def syscall_extractor():
    sm.p_msg('=== STARTING SYSCALL EXTRACTOR ===', 'notice', '2', 'y')
    files = os.listdir(FilePath)
    sm.p_msg('File Path: ' + FilePath, 'notice', '1', 'y')
    sm.p_msg('===', 'notice', '1', 'y')
    print("\r")
    # LOAD list to our list to remove SysCalls as not found to build a common list
    FoundInList = SysCall64List
    for file in files:
        if file.endswith(".LOG"):
            SysCallsInFile = [] # set
            with open(os.path.join(FilePath, file), 'r') as CURRENTLoadedFile:
                sm.p_msg('Pulling SysCalls from: ' + file.rsplit(".", 1)[0], 'notice', '1', 'y')
                ReadFile = CURRENTLoadedFile.read()
                # Build a LIST of common SysCalls used by all the exploits.
                # IF SysCall from FILE is NOT found in the current list, do not add it.
                for SysCall in SysCall64List:
                    if SysCall in ReadFile:
                        SysCallsInFile.append(SysCall)
            # if syscall in current list is not found in file remove
            FoundInList = common_elements(SysCallsInFile, FoundInList)
            sm.p_msg('SysCalls Used In ' + file.rsplit(".", 1)[0] + ' : ' + ' , '.join(map(str, SysCallsInFile)), 'ok', '1', 'y')
            CURRENTLoadedFile.close()
            sm.p_msg('Remove File: ' + file, 'notice', '1', 'y')
            os.remove(FilePath+"/"+file)
            print("\r")
    print("\r")
    sm.p_msg('SysCalls in Common [Linux 64 Bit]:  ' + ' , '.join(map(str, FoundInList)), 'ok', '2', 'y')

#
# run the application steps
#
if __name__ == "__main__":
    sm.p_msg('=== STARTING SYSCALL FINDER ===', 'notice', '2', 'y')
    sm.p_msg('File Path: ' + FilePath, 'notice', '1', 'y')
    sm.p_msg('===', 'notice', '1', 'y')
    with multiprocessing.Pool(Threads) as p:
        p.map(syscall_finder,[os.path.join(FilePath, file) for file in os.listdir(FilePath)])
    print("\r")
    syscall_extractor()
