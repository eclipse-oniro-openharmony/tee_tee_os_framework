#ifndef __SLICE_BALONG_H__
#define __SLICE_BALONG_H__
#include <sre_typedef.h>

u32 bsp_get_slice_value(void);
void bsp_slice_getcurtime(u64 *pcurtime);
#define get_timer_slice_delta(begin,end) ((end>=begin)?(end-begin):(0xFFFFFFFF-begin+end))

#endif

