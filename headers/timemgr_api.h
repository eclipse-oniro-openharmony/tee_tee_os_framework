#ifndef LIB_TIMEMGR_API_H
#define LIB_TIMEMGR_API_H

#include <stdint.h>

typedef uint64_t cref_t;

cref_t create_timer(void);

void delete_timer(cref_t timer_cref);

int32_t timer_start(cref_t timer_cref, uint32_t millis);

int32_t timer_stop(cref_t timer_cref);

int32_t timer_get_offset(int32_t *seconds, int32_t *millis);

#endif
