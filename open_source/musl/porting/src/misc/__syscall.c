#include "syscall.h"
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>

#include "vsyscall/futex.h"

// syscall.h define __syscall as a macro, but __syscall below should not be expanded by the macro
// so undef __syscall
#undef __syscall
#define VIRTUAL_SYSCALL_NUM 500

/* Since we are mimic linux syscalls, we set the return type to int */
typedef int (*hm_vsyscall_t)(va_list);

/* Our faked syscall provides mainly futex_vsyscall and set_roubust_list_vsyscall
 * for the purpose of supporting libc. */
long __syscall(long syscall_num, ...)
{
    va_list al;
    va_start(al, syscall_num);
    hm_vsyscall_t sysfunc = NULL;

    if (syscall_num < 0 || syscall_num >= VIRTUAL_SYSCALL_NUM) {
        va_end(al);
        return -ENOSYS;
    }

    switch (syscall_num) {
#ifndef USE_IN_SYSMGR
    case SYS_futex:
        sysfunc = futex_vsyscall;
        break;
    case SYS_set_robust_list:
        sysfunc = set_robust_list_vsyscall;
        break;
#endif
    default:
        /* this situation will be deal with in next step */
        break;
    }

    if (!sysfunc) {
        va_end(al);
        printf("[VSYSCALL ERROR:] syscall [%ld] not implemented\n", syscall_num);
        return -ENOSYS;
    }
    int ret = sysfunc(al);
    va_end(al);
    return ret;
}
