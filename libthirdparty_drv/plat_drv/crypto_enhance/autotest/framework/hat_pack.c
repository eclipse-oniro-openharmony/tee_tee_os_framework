/****************************************************************************//**
 * @file   : hieps_pack.c
 * @brief  :
 * @par    : Copyright(c) 2018-2034, HUAWEI Technology Co., Ltd.
 * @date   : 2018/08/20
 * @author : l00265041
 * @note   :
********************************************************************************/
#include <pal_libc.h>


/*===============================================================================
 *                                 types/macros                                *
===============================================================================*/
/**< array size */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)       (sizeof(x) / sizeof(x[0]))
#endif /* ARRAY_SIZE */

typedef struct hat_object_stru {
	u32 addr;
	const char *name;
} hat_object_s;


/*===============================================================================
 *                                global objects                               *
===============================================================================*/
hat_object_s g_hat_sym_map[] = { }; /* 此行为替换模板，不允许做任何改动 */

/*===============================================================================
 *                                  functions                                  *
===============================================================================*/
/****************************************************************************//**
 * @brief      : hat_get_func_addr
 * @param[in]  : name 函数名称
 * @param[in]  : len 函数对应buffer大小
 * @return     : ::u32 函数地址
 * @note       :
********************************************************************************/
u32 hat_get_func_addr(const s8 *name, u32 len)
{
	u32 idx;

	if ((NULL == name) || (0 == len)) {
		return 0;
	}

	for (idx = 0; idx < ARRAY_SIZE(g_hat_sym_map); idx++) {
		if (0 == pal_strncmp(g_hat_sym_map[idx].name, (const char *)name, len)) {
			return g_hat_sym_map[idx].addr;
		}
	}
	return 0;
}
