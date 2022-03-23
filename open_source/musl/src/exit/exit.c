#include <procmgr.h>
#include <sys/kuapi.h>
#include "libc.h"

_Noreturn void exit(int code)
{
	__funcs_on_exit();
	_fini();
	hm_exit(code);
}
