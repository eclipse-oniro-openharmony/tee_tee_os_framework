/****************************************************************************//**
 * @file   : pal_hieps_memory.c
 * @brief  : hieps share memory
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2018/12/19
 * @author : m00475438
 * @note   :
********************************************************************************/
#include <eps_ddr_layout_define.h>
#include <soc_baseaddr_interface.h>
#include <common_utils.h>
#include <pal_memory.h>
#include <securec.h>


/*===============================================================================
 *                               types/macros                                  *
===============================================================================*/
/* set the module to which the file belongs
   each .C file needs to be configured
*/
#define BSP_THIS_MODULE BSP_MODULE_SYS

#define HIEPS_SHARE_MEM_POOL            (u8 *)(EPS_SHARE_DDR_ENG_GENERIC_DATA_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))
#define HIEPS_SHARE_MEM_SIZE            HIEPS_SHARE_DDR_ENG_GENERIC_DATA_SIZE
#define HIEPS_SHARE_HEAP_INIT()         pal_heap_init(HIEPS_SHARE_MEM_POOL, HIEPS_SHARE_MEM_SIZE)
#define HIEPS_SHAER_HEAP_ALLOC(len)     pal_heap_alloc(HIEPS_SHARE_MEM_POOL, HIEPS_SHARE_MEM_SIZE, len)
#define HIEPS_SHARE_HEAP_FREE(mem)      pal_heap_free(HIEPS_SHARE_MEM_POOL, HIEPS_SHARE_MEM_SIZE, (void *)mem)


#define HIEPS_ADDR_DDR_WIN_MASK       (0x1FFFFFFF)
#define HIEPS_ADDR_TEE2HIEPS(addr)    \
	(u8 *)((((uintptr_t)(addr)) & HIEPS_ADDR_DDR_WIN_MASK) | SOC_DDR_BASE_ADDR)
#define HIEPS_ADDR_HIEPS2TEE(addr)    \
	(u8 *)(uintptr_t)((((uintptr_t)(addr)) & HIEPS_ADDR_DDR_WIN_MASK) | ((u32)HIEPS_SHARE_MEM_POOL & (~HIEPS_ADDR_DDR_WIN_MASK)))


/*===============================================================================
 *                                 functions                                   *
===============================================================================*/
/****************************************************************************//**
 * @brief      : switch tee memory addr to hieps memory addr
 * @param[in]  : tee_p  tee pointer
 * @return     : void *
 * @note       :
********************************************************************************/
void *hieps_mem_convert2hieps(const void *tee_p)
{
	if ((HIEPS_SHARE_MEM_POOL > (u8 *)tee_p) || ((u8 *)tee_p > HIEPS_SHARE_MEM_POOL + HIEPS_SHARE_MEM_SIZE))
	{
		PAL_ERROR("err p = "PAL_FMT_PTR"\n", (uintptr_t)tee_p);
		return NULL;
	}
	return HIEPS_ADDR_TEE2HIEPS(tee_p);
}

/****************************************************************************//**
 * @brief      : switch hieps memory addr to tee memory addr
 * @param[in]  : hieps_p hieps pointer
 * @return     : void *
 * @note       :
********************************************************************************/
void *hieps_mem_convert2tee(const void *hieps_p)
{
	if ((HIEPS_ADDR_TEE2HIEPS(HIEPS_SHARE_MEM_POOL) > (u8 *)hieps_p) ||
		((u8 *)hieps_p > HIEPS_ADDR_TEE2HIEPS(HIEPS_SHARE_MEM_POOL + HIEPS_SHARE_MEM_SIZE)))
	{
		PAL_ERROR("err p = "PAL_FMT_PTR"\n", (uintptr_t)hieps_p);
		return NULL;
	}
	return HIEPS_ADDR_HIEPS2TEE(hieps_p);
}

/****************************************************************************//**
 * @brief      : initialize hieps agent included memory and so on
 * @return     : ::err_bsp_t
 * @note       :
********************************************************************************/
err_bsp_t hieps_agent_init()
{
    /**< initialize heap memory */
    return HIEPS_SHARE_HEAP_INIT();
}

/****************************************************************************//**
 * @brief      : release share memory
 * @param[in]  : obj buffer pointer
 * @return     : NA
 * @note       :
********************************************************************************/
void hieps_mem_delete(const void* obj)
{
    err_bsp_t ret;
    if (NULL == obj) {
        return;
    }

    ret = HIEPS_SHARE_HEAP_FREE(obj);
    if (ret != BSP_RET_OK) {
        PAL_ERROR("ret = "PAL_FMT_PTR"\n", ret);
    }
}

/****************************************************************************//**
 * @brief      : share memory alloc and clear to zero
 * @param[in]  : obj  cloned memory object, if NULL, then only alloc share memory
 * @param[in]  : size size of obj
 * @return     : void * memory address pointer
 * @note       :
********************************************************************************/
void *hieps_mem_new(const void *obj, u32 size)
{
    errno_t libc_ret;
    void *p = NULL;

    if (size <= 0)
    {
        return NULL;
    }

    /* alloc */
    p = HIEPS_SHAER_HEAP_ALLOC((u32)size);

    /* init */
    if (NULL == p) {
        PAL_ERROR("malloc %d failed! NO Memory!\n", size);
    } else {
        if (NULL != obj) {
            libc_ret = memcpy_s(p, size, obj, size);
            if (EOK != libc_ret) {
                hieps_mem_delete(p);
                return NULL;
            }
        }
    }

    return p;
}

