// By default, linker will put the __init_array_start to the begin of ".init_array"
// and __init_array_end to the end of ".init_array" section. So does the ".fini_array"
// You can check it by 'ld -verbose' command.
//
// The ".init_array" section stores the following init functions:
// 1. Global C++ object constructor.
// 2. The functions which marked as "constructor" like
//    __attribute__((constructor(200))) void setup_xx()
//
// We need to call this init functions before main function.
#include <stdlib.h>
#include "dynlink.h"

typedef void (*func_ptr)(void);
extern func_ptr __init_array_start[0], __init_array_end[0];
extern func_ptr __fini_array_start[0], __fini_array_end[0];

void _init(void)
{
	__libc_start_init();
}

void _fini(void)
{
	__libc_exit_fini();
}
