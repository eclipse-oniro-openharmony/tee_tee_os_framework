#ifndef __SELF_ADAPT_SUPPLIER_
#define __SELF_ADAPT_SUPPLIER_

#include "securec.h"

#define struct_supplier(key)    \
static thp_afe_api thp_afe_api_##key =      \
{                                           \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    thp_afe_open_##key,                     \
    thp_afe_open_project_##key,             \
    thp_afe_close_##key,                    \
    thp_afe_start_##key,                    \
    thp_afe_stop_##key,                     \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    thp_afe_get_hw_cap_##key,               \
    thp_afe_get_frame_##key,                \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
    NULL,                                   \
}                                           \

//#define THP_DEBUG_LOG   // control whether create the logfile of tsa raw data

extern int g_row_num;
extern int g_column_num;

#endif /* __TEE_LOG_H */

