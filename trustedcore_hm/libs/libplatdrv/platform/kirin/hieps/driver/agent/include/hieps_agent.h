/****************************************************************************//**
 * @file   : hieps_agent.h
 * @brief  : define hieps agent
 * @par    : Copyright(c) 2018-2034, HUAWEI Technology Co., Ltd.
 * @date   : 2018/12/19
 * @author : m00172947
 * @note   :
********************************************************************************/
#ifndef __HIEPS_AGENT_H__
#define __HIEPS_AGENT_H__
#include <pal_memory.h>
#include "hieps_run_func.h"


/*===============================================================================
 *                               types/macros                                  *
===============================================================================*/
#define HIEPS_AGENT_TIMEOUT_DEFAULT (3 * 1000 * 1000) /* us */
#define HIEPS_AGENT_TIMEOUT_RSA_GENKEY (120 * 1000 * 1000) /* us */


/*===============================================================================
 *                                 functions                                   *
===============================================================================*/
/****************************************************************************//**
 * @brief      : initialize hieps agent included memory and so on
 * @return     : ::err_bsp_t
 * @note       :
********************************************************************************/
err_bsp_t hieps_agent_init();

/****************************************************************************//**
 * @brief      : switch tee memory addr to hieps memory addr
 * @param[in]  : tee_p  tee pointer
 * @return     : void *
 * @note       :
********************************************************************************/
void *hieps_mem_convert2hieps(const void *tee_p);

/****************************************************************************//**
 * @brief      : switch hieps memory addr to tee memory addr
 * @param[in]  : hieps_p hieps pointer
 * @return     : void *
 * @note       :
********************************************************************************/
void *hieps_mem_convert2tee(const void *hieps_p);

/****************************************************************************//**
 * @brief      : hieps share memory alloc
 * @param[in]  : obj  cloned memory object, if NULL, then only alloc share memory
 * @param[in]  : size size of obj
 * @return     : void * memory address pointer
 * @note       :
********************************************************************************/
void *hieps_mem_new(const void *obj, u32 size);

/****************************************************************************//**
 * @brief      : release share memory
 * @param[in]  : obj buffer pointer
 * @return     : NA
 * @note       :
********************************************************************************/
void hieps_mem_delete(const void* obj);

/****************************************************************************//**
 * @brief      : hieps_run_func
 * @param[in]  : timeout_us timeout if -1, no timeout
 * @param[in]  : func_id     funciton identifier
 * @param[in]  : params_num  funciton parameter number
 * @return     : ::err_bsp_t
 * @note       :
********************************************************************************/
err_bsp_t hieps_run_func(int timeout_us, u32 func_id, u32 params_num, ...);


/*===============================================================================
 *                                 functions                                   *
===============================================================================*/
#ifdef FEATURE_ALLOC_TRACE_ENABLE
static inline void __hieps_mem_delete(const void *obj, const char *func, u32 line)
{
	pal_heap_trace(-1, obj, func, line);
	hieps_mem_delete(obj);
}
#define hieps_mem_delete(obj) __hieps_mem_delete(obj, __FUNCTION__, __LINE__)

static inline void *__hieps_mem_new(const void *obj, u32 size, const char *func, u32 line)
{
	void *p = hieps_mem_new(obj, size);
	pal_heap_trace(1, p, func, line);
	return p;
}
#define hieps_mem_new(obj, size) __hieps_mem_new(obj, size, __FUNCTION__, __LINE__)
#endif /* FEATURE_ALLOC_TRACE_ENABLE */

#endif /*__HIEPS_AGENT_H__*/
