/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: drivers of drv_osal_sys
 * Author: cipher team
 * Create: 2019-06-18
 */

#include "drv_osal_lib.h"
#include "libhwsecurec/securec.h"
#include "hi_tee_drv_mem.h"

/*************************** Internal Structure Definition ********************/
/** \addtogroup      base type */
/** @{ */ /** <!-- [base] */

/* under TEE, we only can malloc secure mmz at system steup,
 * then map the mmz to Smmu, but the smmu can't map to cpu address,
 * so we must save the cpu address in a static table when malloc and map mmz.
 * when call crypto_mem_map, we try to query the table to get cpu address firstly,
 * if can't get cpu address from the table, then call system api to map it.
 */
#define CRYPTO_MEM_MAP_TABLE_DEPTH 32

/* try to create memory */
#define PHY_MEM_CREATE_TRY_TIME 10

typedef struct {
    hi_u32 valid;
    compat_addr dma;
    compat_addr mmz;
    hi_void *via;
} crypto_mem_map_table;

static crypto_mem_map_table g_local_map_table[CRYPTO_MEM_MAP_TABLE_DEPTH];

/** @} */ /** <!-- ==== Structure Definition end ==== */

/******************************* API Code *****************************/
/** \addtogroup      base */
/** @{ */ /** <!--[base] */

/*****************************************************************
 *                       mmz/mmu api                             *
 *****************************************************************/
/* Implementation that should never be optimized out by the compiler */
hi_void crypto_zeroize(hi_void *buf, hi_u32 len)
{
    volatile unsigned char *p = (unsigned char *)buf;

    if (buf == HI_NULL) {
        return;
    }

    while (len--) {
        *p++ = 0;
    }
}

/* brief allocate and map a mmz or smmu memory
* we can't allocate smmu directly during TEE boot period.
* in addition, the buffer of cipher node list must be mmz.
* so here we have to allocate a mmz memory then map to smmu if necessary.
 */
static hi_s32 crypto_mem_alloc_remap(crypto_mem *mem, hi_u32 type, const char *name, hi_u32 size)
{
    hi_u32 i;
    hi_u32 ret;
    hi_tee_mmz_buf mmz_buf;

    ret = memset_s(mem, sizeof(crypto_mem), 0, sizeof(crypto_mem));
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(memset_s, ret);
        return ret;
    }

    hi_log_debug("mem_alloc_remap()- name %s, size 0x%x\n", name, size);

    /* allocate mmz, only support 32-bit ddr */
    mmz_buf.size = size;
    ret = hi_tee_drv_mmz_alloc(name, size, type, &mmz_buf);
    if (ret != HI_SUCCESS) {
        return HI_ERR_CIPHER_FAILED_MEM;
    }

    /* map mmz to cpu */
    ret = hi_tee_drv_mmz_map_cpu(&mmz_buf, HI_FALSE);
    if (ret != HI_SUCCESS) {
        (hi_void)hi_tee_drv_mmz_free(&mmz_buf);
        return HI_ERR_CIPHER_FAILED_MEM;
    }
    mem->dma_virt = mmz_buf.virt;
    ADDR_L32(mem->dma_addr) = mmz_buf.phys_addr;
    ADDR_L32(mem->mmz_addr) = mmz_buf.phys_addr;
    mem->dma_size = size;

#ifdef CRYPTO_SMMU_SUPPORT
    {
        hi_tee_smmu_buf smmu_buf;

        /* mmz map to smmu */
        ret = hi_tee_drv_mmz_map_secsmmu(&mmz_buf, &smmu_buf);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(hi_tee_drv_mmz_map_secsmmu, ret);
            (hi_void)hi_tee_drv_mmz_unmap_cpu(&mmz_buf);
            (hi_void)hi_tee_drv_mmz_free(&mmz_buf);
            crypto_zeroize(mem->dma_virt, mem->dma_size);
            return HI_ERR_CIPHER_FAILED_MEM;
        }
        ret = hi_tee_drv_smmu_set_tag(&smmu_buf, BUFFER_TAG_INTERNAL_BUF_MCIPHER);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(hi_tee_drv_smmu_attach, ret);
            (hi_void)hi_tee_drv_mmz_unmap_secsmmu(&smmu_buf, ADDR_L32(mem->mmz_addr));
            (hi_void)hi_tee_drv_mmz_unmap_cpu(&mmz_buf);
            (hi_void)hi_tee_drv_mmz_free(&mmz_buf);
            crypto_zeroize(mem->dma_virt, mem->dma_size);
            return HI_ERR_CIPHER_FAILED_MEM;
        }

        /* only support 32-bit ddr */
        ADDR_L32(mem->dma_addr) = smmu_buf.smmu_addr;
    }
#endif

    hi_log_debug("MMZ/MMU malloc, MMZ 0x%x, MMZ/MMU 0x%x, VIA %p, SIZE 0x%x\n",
                 ADDR_L32(mem->mmz_addr), ADDR_L32(mem->dma_addr), mem->dma_virt, size);

    mem->user_buf = HI_NULL;

    /* save the map info */
    for (i = 0; i < CRYPTO_MEM_MAP_TABLE_DEPTH; i++) {
        if (g_local_map_table[i].valid == HI_FALSE) {
            ADDR_L32(g_local_map_table[i].dma) = ADDR_L32(mem->dma_addr);
            ADDR_L32(g_local_map_table[i].mmz) = ADDR_L32(mem->mmz_addr);
            g_local_map_table[i].via = mem->dma_virt;
            g_local_map_table[i].valid = HI_TRUE;
            hi_log_debug("map local map %d, dma 0x%x, via %p\n",
                         i, ADDR_L32(mem->dma_addr), mem->dma_virt);
            break;
        }
    }
    crypto_zeroize(mem->dma_virt, mem->dma_size);

    return HI_SUCCESS;
}

/* brief release and unmap a mmz or smmu memory */
static hi_s32 crypto_mem_release_unmap(crypto_mem *mem)
{
    hi_s32 ret;
    hi_tee_mmz_buf mmz_buf;
    hi_u32 i;

    hi_log_debug("mem_release_unmap()- dma 0x%x, via 0x%p, size 0x%x\n",
                 ADDR_L32(mem->dma_addr), mem->dma_virt, mem->dma_size);

#ifdef CRYPTO_SMMU_SUPPORT
    {
        hi_tee_smmu_buf smmu_buf;

        /* umap mmz from smmu */
        smmu_buf.virt = mem->dma_virt;
        smmu_buf.smmu_addr = ADDR_L32(mem->dma_addr);
        smmu_buf.size = mem->dma_size;
        ret = hi_tee_drv_mmz_unmap_secsmmu(&smmu_buf, ADDR_L32(mem->mmz_addr));
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(hi_tee_drv_mmz_unmap_secsmmu, ret);
            return ret;
        }
    }
#endif
    /* umap and free mmz */
    mmz_buf.phys_addr = ADDR_L32(mem->mmz_addr);
    mmz_buf.virt = mem->dma_virt;
    mmz_buf.size = mem->dma_size;
    ret = hi_tee_drv_mmz_unmap_cpu(&mmz_buf);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(hi_tee_drv_mmz_unmap_cpu, ret);
        return ret;
    }
    ret = hi_tee_drv_mmz_free(&mmz_buf);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(hi_tee_drv_mmz_free, ret);
        return ret;
    }

    /* remove the map info */
    for (i = 0; i < CRYPTO_MEM_MAP_TABLE_DEPTH; i++) {
        if (g_local_map_table[i].valid &&
            ADDR_L32(g_local_map_table[i].dma) == ADDR_L32(mem->dma_addr)) {
            ADDR_L32(g_local_map_table[i].dma) = 0x00;
            ADDR_L32(g_local_map_table[i].mmz) = 0x00;
            g_local_map_table[i].via = HI_NULL;
            g_local_map_table[i].valid = HI_FALSE;
            hi_log_debug("unmap local map %d, dma 0x%x, via 0x%p\n",
                         i, ADDR_L32(mem->dma_addr), mem->dma_virt);
            break;
        }
    }
    ret = memset_s(mem, sizeof(crypto_mem), 0, sizeof(crypto_mem));
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(memset_s, ret);
        return ret;
    }

    return HI_SUCCESS;
}

/* brief map a mmz or smmu memory */
static hi_s32 crypto_mem_map(crypto_mem *mem)
{
    hi_u32 i;

    hi_log_debug("crypto_mem_map()- dma 0x%x, size 0x%x\n",
                 ADDR_L32(mem->dma_addr), mem->dma_size);

    /* try to query the table to get cpu address firstly,
     * if can't get cpu address from the table, then call system api to map it.
     */
    for (i = 0; i < CRYPTO_MEM_MAP_TABLE_DEPTH; i++) {
        if (g_local_map_table[i].valid &&
            ADDR_L32(g_local_map_table[i].dma) == ADDR_L32(mem->dma_addr)) {
            mem->dma_virt = g_local_map_table[i].via;
            hi_log_debug("local map %d, dma 0x%x, via 0x%p\n",
                         i, ADDR_L32(mem->dma_addr), mem->dma_virt);
            return HI_SUCCESS;
        }
    }

#if defined(CRYPTO_SMMU_SUPPORT)
    hi_s32 ret;
    hi_tee_smmu_buf smmu_buf;

    /* map mmu to cpu */
    smmu_buf.smmu_addr = ADDR_L32(mem->dma_addr);
    smmu_buf.size = mem->dma_size;
    ret = hi_tee_drv_smmu_map_cpu(&smmu_buf, 0);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(hi_tee_drv_smmu_map_cpu, ret);
        return ret;
    }

    mem->dma_virt = smmu_buf.virt;
    hi_log_debug("mem_map()- smmu 0x%x, vai %p\n", ADDR_L32(mem->dma_addr), mem->dma_virt);
#else /* MMZ */
    hi_s32 ret;
    hi_tee_mmz_buf mmz_buf;

    /* map mmz to cpu */
    mmz_buf.phys_addr = ADDR_L32(mem->dma_addr);
    mmz_buf.size = mem->dma_size;
    ret = hi_tee_drv_mmz_map_cpu(&mmz_buf, 0);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(hi_tee_drv_mmz_map_cpu, ret);
        return ret;
    }

    mem->dma_virt = mmz_buf.virt;
#endif

    if (mem->dma_virt == HI_NULL) {
        hi_log_print_err_code(HI_ERR_CIPHER_FAILED_MEM);
        return HI_ERR_CIPHER_FAILED_MEM;
    }

    hi_log_info("crypto_mem_map()- via 0x%p\n", mem->dma_virt);

    return HI_SUCCESS;
}

/* brief unmap a mmz or smmu memory */
static hi_s32 crypto_mem_unmap(crypto_mem *mem)
{
    hi_u32 i;

    hi_log_debug("crypto_mem_unmap()- dma 0x%x, size 0x%x\n",
                 ADDR_L32(mem->dma_addr), mem->dma_size);

    /* try to query the table to ummap cpu address firstly,
     * if can't get cpu address from the table, then call system api to unmap it.
     */
    for (i = 0; i < CRYPTO_MEM_MAP_TABLE_DEPTH; i++) {
        if (g_local_map_table[i].valid &&
            ADDR_L32(g_local_map_table[i].dma) == ADDR_L32(mem->dma_addr)) {
            /* this api can't unmap the dma within the map table */
            hi_log_debug("local unmap %d, dma 0x%x, via 0x%p\n",
                         i, ADDR_L32(mem->dma_addr), mem->dma_virt);
            return HI_SUCCESS;
        }
    }

#if defined(CRYPTO_SMMU_SUPPORT)
    {
        hi_tee_smmu_buf smmu_buf;

        /* umap smmu */
        smmu_buf.smmu_addr = ADDR_L32(mem->dma_addr);
        smmu_buf.virt = mem->dma_virt;
        smmu_buf.size = mem->dma_size;
        mem->dma_virt = HI_NULL;
        return hi_tee_drv_smmu_unmap_cpu(&smmu_buf);
    }
#else /* MMZ */
    {
        hi_tee_mmz_buf mmz_buf;

        /* umap mmz */
        mmz_buf.phys_addr = ADDR_L32(mem->dma_addr);
        mmz_buf.virt = mem->dma_virt;
        mmz_buf.size = mem->dma_size;
        mem->dma_virt = HI_NULL;
        return hi_tee_drv_mmz_unmap_cpu(&mmz_buf);
    }
#endif

    return HI_SUCCESS;
}

hi_void crypto_mem_init(void)
{
    (void)memset_s(&g_local_map_table, sizeof(g_local_map_table), 0, sizeof(g_local_map_table));
}

hi_void crypto_mem_deinit(void)
{
}

hi_s32 crypto_mem_create(crypto_mem *mem, hi_u32 type, const char *name, hi_u32 size)
{
    crypto_assert(mem != HI_NULL);

    return crypto_mem_alloc_remap(mem, type, name, size);
}

hi_s32 crypto_mem_destory(crypto_mem *mem)
{
    crypto_assert(mem != HI_NULL);

    return crypto_mem_release_unmap(mem);
}

hi_s32 crypto_mem_open(crypto_mem *mem, compat_addr dma_addr, hi_u32 dma_size)
{
    hi_s32 ret;

    crypto_assert(mem != HI_NULL);

    mem->dma_addr = dma_addr;
    mem->dma_size = dma_size;

    if (mem->dma_size == 0) {
        return HI_SUCCESS;
    }

    ret = crypto_mem_map(mem);

    return ret;
}

hi_s32 crypto_mem_close(crypto_mem *mem)
{
    crypto_assert(mem != HI_NULL);

    if (mem->dma_size == 0) {
        return HI_SUCCESS;
    }

    return crypto_mem_unmap(mem);
}

hi_s32 crypto_mem_attach(crypto_mem *mem, hi_void *buffer)
{
    crypto_assert(mem != HI_NULL);

    mem->user_buf = buffer;

    return HI_SUCCESS;
}

hi_s32 crypto_mem_flush(crypto_mem *mem, hi_u32 dma2user, hi_u32 offset, hi_u32 data_size)
{
    crypto_assert(mem != HI_NULL);
    crypto_assert(mem->dma_virt != HI_NULL);
    crypto_assert(mem->user_buf != HI_NULL);
    crypto_assert(data_size <= mem->dma_size);

    if (dma2user) {
        return memcpy_s((hi_u8 *)mem->user_buf + offset, data_size,
                        (hi_u8 *)mem->dma_virt + offset, data_size);
    } else {
        return memcpy_s((hi_u8 *)mem->dma_virt + offset, data_size,
                        (hi_u8 *)mem->user_buf + offset, data_size);
    }
}

hi_s32 crypto_mem_phys(crypto_mem *mem, compat_addr *dma_addr)
{
    crypto_assert(mem != HI_NULL);

    dma_addr->phy = ADDR_U64(mem->dma_addr);

    return HI_SUCCESS;
}

hi_void *crypto_mem_virt(crypto_mem *mem)
{
    if (mem == HI_NULL) {
        return HI_NULL;
    }

    return mem->dma_virt;
}

hi_void crypto_mem_map_info(void)
{
    hi_u32 i;

    for (i = 0; i < CRYPTO_MEM_MAP_TABLE_DEPTH; i++) {
        if (g_local_map_table[i].valid) {
            HI_PRINT("local map %d: dma 0x%x, mmz 0x%x, via 0x%p\n",
                     i, ADDR_L32(g_local_map_table[i].dma),
                     ADDR_L32(g_local_map_table[i].mmz), g_local_map_table[i].via);
        }
    }
    return;
}

hi_u32 crypto_is_sec_cpu(void)
{
    return HI_TRUE;
}

hi_s32 crypto_copy_from_user(hi_void *to, unsigned long to_len, const hi_void *from, unsigned long from_len)
{
    hi_s32 ret;
    hi_void *user = HI_NULL;

    if (from_len == 0) {
        return HI_SUCCESS;
    }

    hi_log_check_param(to == HI_NULL);
    hi_log_check_param(from == HI_NULL);
    hi_log_check_param(to_len < from_len);

    ret = hi_tee_drv_hal_read_right_check((void *)from, from_len);
    if (ret != HI_TRUE) {
        hi_log_print_func_err(hi_tee_drv_hal_read_right_check, ret);
        return ret;
    }

    user = from;
    ret = hi_tee_drv_hal_user_mmap(&user, from_len);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(hi_tee_drv_hal_user_mmap, ret);
        return ret;
    }

    asm_memmove(to, user, from_len);

    ret = hi_tee_drv_hal_user_munmap(user, from_len);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(hi_tee_drv_hal_user_munmap, ret);
        return ret;
    }

    return HI_SUCCESS;
}

hi_s32 crypto_copy_to_user(hi_void *to, unsigned long to_len, const hi_void *from, unsigned long from_len)
{
    hi_s32 ret;
    hi_void *user = HI_NULL;

    if (from_len == 0) {
        return HI_SUCCESS;
    }

    hi_log_check_param(to == HI_NULL);
    hi_log_check_param(from == HI_NULL);
    hi_log_check_param(to_len < from_len);

    ret = hi_tee_drv_hal_write_right_check((void *)to, to_len);
    if (ret != HI_TRUE) {
        hi_log_print_func_err(hi_tee_drv_hal_write_right_check, ret);
        return ret;
    }

    user = to;
    ret = hi_tee_drv_hal_user_mmap(&user, to_len);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(hi_tee_drv_hal_user_mmap, ret);
        return ret;
    }

    asm_memmove(user, from, from_len);

    ret = hi_tee_drv_hal_user_munmap(user, to_len);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(hi_tee_drv_hal_user_munmap, ret);
        return ret;
    }

    return HI_SUCCESS;
}

hi_void smmu_get_table_addr(hi_u64 *rdaddr, hi_u64 *wraddr, hi_u64 *table)
{
    hi_s32 ret;
    hi_u64 smmu_e_raddr = 0;
    hi_u64 smmu_e_waddr = 0;
    hi_u64 mmu_pgtbl = 0;

    ret = hi_tee_drv_smmu_get_pgtinfo(&smmu_e_raddr, &smmu_e_waddr, &mmu_pgtbl);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(hi_tee_drv_smmu_get_pgtinfo, ret);
        return;
    }

    *rdaddr = smmu_e_raddr;
    *wraddr = smmu_e_waddr;
    *table = mmu_pgtbl;

    return;
}

hi_s32 crypto_mem_try_create_max(const char *name, hi_u32 type, hi_u32 max, crypto_mem *mem)
{
    hi_s32 ret = HI_FAILURE;
    hi_u32 i = 0;

    hi_log_func_enter();

    /* Try to alloc memory, halve the length if failed */
    for (i = 0; i < PHY_MEM_CREATE_TRY_TIME; i++) {
        ret = crypto_mem_create(mem, type, name, max);
        if (ret == HI_SUCCESS) {
            return HI_SUCCESS;
        } else {
            /* halve the length */
            max /= 0x02;
        }
    }

    hi_log_func_exit();
    return HI_FAILURE;
}

hi_s32 crypto_judge_sec_mem(const hi_cipher_data_dir data_dir, hi_bool *in_is_sec, hi_bool *out_is_sec)
{
    switch (data_dir) {
        case HI_CIPHER_DATA_DIR_REE2REE:
            *in_is_sec = HI_FALSE;
            *out_is_sec = HI_FALSE;
            break;
        case HI_CIPHER_DATA_DIR_REE2TEE:
            *in_is_sec = HI_FALSE;
            *out_is_sec = HI_TRUE;
            break;
        case HI_CIPHER_DATA_DIR_TEE2REE:
            *in_is_sec = HI_TRUE;
            *out_is_sec = HI_FALSE;
            break;
        case HI_CIPHER_DATA_DIR_TEE2TEE:
            *in_is_sec = HI_TRUE;
            *out_is_sec = HI_TRUE;
            break;
        default:
            hi_log_error("Unsupport memory direction\n");
            return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_s32 crypto_bufhandle_to_phys(hi_u64 *bufphys, const hi_mem_handle bufhandle, const hi_bool is_sec_mem)
{
    hi_s32 ret;
    hi_tee_smmu_buf smmubuf;

    if (bufhandle.mem_handle == 0) {
        *bufphys = 0x00;
        return HI_SUCCESS;
    }

    ret = memset_s(&smmubuf, sizeof(hi_tee_smmu_buf), 0, sizeof(hi_tee_smmu_buf));
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(memset_s, ret);
        return ret;
    }

    if (is_sec_mem == HI_TRUE) {
        ret = hi_tee_drv_mem_get_secsmmu_by_handle_id(&smmubuf, bufhandle.mem_handle);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(hi_tee_drv_mem_get_secsmmu_by_handle_id, ret);
            return ret;
        }
    } else {
        ret = hi_tee_drv_mem_get_nssmmu_by_handle_id(&smmubuf, bufhandle.mem_handle);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(hi_tee_drv_mem_get_nssmmu_by_handle_id, ret);
            return ret;
        }
    }

    *bufphys = smmubuf.smmu_addr + bufhandle.addr_offset;
    return HI_SUCCESS;
}

/** @} */ /** <!-- ==== API Code end ==== */
