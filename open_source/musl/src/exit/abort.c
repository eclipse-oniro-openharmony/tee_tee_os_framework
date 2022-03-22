#include <errno.h>
#include <procmgr.h>
#include <sys/usrsyscall.h>

void __attribute__((noreturn)) abort(void);

void __attribute__((noreturn)) abort(void)
{
	__builtin_trap();
	__builtin_unreachable();
}
