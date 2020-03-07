//
// Created by Kaihang Ji on 3/7/2020.
//

#ifndef PEEKABOO_SYSCALL_H
#define PEEKABOO_SYSCALL_H

#ifdef UNIX
#    ifdef LINUX
#        include <syscall.h>
#        define SYSNUM_SIGPROCMASK SYS_rt_sigprocmask
#    else
#        include <sys/syscall.h>
#        define SYSNUM_SIGPROCMASK SYS_sigprocmask
#    endif
#    include <errno.h>
#endif

const char* get_syscall_name(int sysnum);

#endif //PEEKABOO_SYSCALL_H
