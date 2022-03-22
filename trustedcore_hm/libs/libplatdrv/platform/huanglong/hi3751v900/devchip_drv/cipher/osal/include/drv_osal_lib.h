/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: drivers of drv_osal_init
 * Author: cipher team
 * Create: 2019-06-18
 */
#ifndef __DRV_OSAL_LIB_H__
#define __DRV_OSAL_LIB_H__

#include <string.h>
#include <semaphore.h>
#include "hi_tee_module_id.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_mem_layout.h"
#include "hi_tee_drv_cipher.h"
#include "securec.h"
#include "drv_cipher_kapi.h"
#include "drv_osal_chip.h"
#include "hi_tee_errcode.h"

#define HI_LOG_D_MODULE_ID          HI_ID_CIPHER
#include "hi_log.h"

#ifndef HI_PRINT
#define HI_PRINT             hi_log_err
#endif

#define HASH_HANDLE_CLOSED_STATUS 0xFFFFFFFF

#define CRYPTO_UNUSED(x)    ((x) = (x))

#ifndef cipher_max
#define cipher_max(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef cipher_min
#define cipher_min(a, b) ((a) < (b) ? (a) : (b))
#endif

/*! \serure mmz or not, not used */
#define SEC_MMZ                         0x00

/* smmu tag id that used for mcipher, defined in drv/ssm/tee_drv_ssm_policy_table.h */
#define BUFFER_TAG_INTERNAL_BUF_MCIPHER   3

/*! \big coding transform to litte coding */
#define cipher_cpu_to_be16(v) (((v)<< 8) | ((v)>>8))
#define cipher_cpu_to_be32(v) ((((hi_u32)(v))>>24) | ((((hi_u32)(v))>>8)&0xff00) \
                     | ((((hi_u32)(v))<<8)&0xff0000) | (((hi_u32)(v))<<24))

#define cipher_cpu_to_be64(x) ((hi_u64)(                         \
    (((hi_u64)(x) & (hi_u64)0x00000000000000ffULL) << 56) |   \
    (((hi_u64)(x) & (hi_u64)0x000000000000ff00ULL) << 40) |   \
    (((hi_u64)(x) & (hi_u64)0x0000000000ff0000ULL) << 24) |   \
    (((hi_u64)(x) & (hi_u64)0x00000000ff000000ULL) <<  8) |   \
    (((hi_u64)(x) & (hi_u64)0x000000ff00000000ULL) >>  8) |   \
    (((hi_u64)(x) & (hi_u64)0x0000ff0000000000ULL) >> 24) |   \
    (((hi_u64)(x) & (hi_u64)0x00ff000000000000ULL) >> 40) |   \
    (((hi_u64)(x) & (hi_u64)0xff00000000000000ULL) >> 56)))

/*! \return uuid */
#define check_owner(local) \
    do { \
        crypto_owner owner; (void)memset_s(&owner, sizeof(owner), 0, sizeof(owner)); \
        if (HI_SUCCESS == crypto_get_owner(&owner)) {\
            if (0 != memcmp(&owner, local, sizeof(owner))) { \
                hi_log_err("check user uuid failed\n"); hi_err_print_err_code(HI_ERR_CIPHER_ILLEGAL_UUID); \
                return HI_ERR_CIPHER_ILLEGAL_UUID; \
            } \
        }\
    } while (0)

/*! \max length module name */
#define CRYPTO_MODULE_NAME_LEN          16

/* the max cipher hard channel count */
#define CRYPTO_HARD_CHANNEL_MAX         0x10

/*! \enumeration module_id */
typedef enum {
    CRYPTO_MODULE_ID_SYMC,        /*!<  Symmetric Cipher */
    CRYPTO_MODULE_ID_SYMC_KEY,    /*!<  Symmetric Cipher key */
    CRYPTO_MODULE_ID_HASH,        /*!<  Message Digest */
    CRYPTO_MODULE_ID_IFEP_RSA,    /*!<  Asymmetric developed by IFEP */
    CRYPTO_MODULE_ID_SIC_RSA,     /*!<  Asymmetric developed by SIC */
    CRYPTO_MODULE_ID_TRNG,        /*!<  Random Data Generation */
    CRYPTO_MODULE_ID_PKE,         /*!<  Public Key Cryptographic Algorithm Based on Elliptic Curves */
    CRYPTO_MODULE_ID_SM4,         /*!<  SM4 */
    CRYPTO_MODULE_ID_SMMU,        /*!<  SMMU */
    CRYPTO_MODULE_ID_CNT,         /*!<  Count of module id */
} module_id;

/*! \struct channel
 * the context of hardware channel.
*/
typedef struct {
    /* the state of instance, open or closed. */
    u32 open;

    /* the context of channel, which is defined by specific module */
    void *ctx;
}channel_context;

/*! \struct of crypto_mem */
typedef struct {
    compat_addr dma_addr;    /*!<  dam addr, may be mmz or smmu */
    compat_addr mmz_addr;    /*!<  mmz addr, sometimes the smmu must maped from mmz */
    hi_void *dma_virt;         /*!<  cpu virtual addr maped from dam addr */
    hi_u32 dma_size;           /*!<  dma memory size */
    hi_void *user_buf;         /*!<  buffer of user */
} crypto_mem;

#define HI_LOG_CHECK_LENGTH(_check_length_val)                  \
    do {                                                        \
        if (_check_length_val) {                                                       \
            hi_err_print_err_code(HI_ERR_CIPHER_INVALID_LENGTH);  \
            return HI_ERR_CIPHER_INVALID_LENGTH;                \
        }                                                       \
    } while (0)

/** @} */  /** <!-- ==== Structure Definition end ==== */

/*! \****************************** API Declaration *****************************/
/*! \addtogroup    osal lib */
/** @{ */  /** <!--[osal] */

/**
\brief  init dma memory.
*/
hi_void crypto_mem_init(hi_void);

/**
\brief  deinit dma memory.
*/
hi_void crypto_mem_deinit(hi_void);

/**
\brief  allocate and map a dma memory.
\param[in] mem  The struct of crypto_mem.
\param[in] size The size of mem.
\param[in] name The name of mem.
\return         HI_SUCCESS if successful, or HI_BASE_ERR_MALLOC_FAILED.
*/
hi_s32 crypto_mem_create(crypto_mem *mem, hi_u32 type, const char *name, hi_u32 size);

/**
\brief  try to create max dma memory.
\param[in] name The name of crypto_mem.
\param[in] type The type of crypto_mem.
\param[in] max The max size of crypto_mem.
\param[out] mem The struct of crypto_mem.
\return         HI_SUCCESS if successful, or HI_FAILURE.
*/
hi_s32 crypto_mem_try_create_max(const char *name, hi_u32 type, hi_u32 max, crypto_mem *mem);

/**
\brief  destory and unmap a dma memory.
\param[in] mem  The struct of crypto_mem.
\return         0 if successful, or HI_BASE_ERR_UNMAP_FAILED.
*/
hi_s32 crypto_mem_destory(crypto_mem *mem);

/**
\brief  map a dma memory.
\param[in] mem  The struct of crypto_mem.
\param[in] dma_ddr The address of dma mem.
\param[in] dma_size The size of dma mem.
\return         HI_SUCCESS if successful, or HI_BASE_ERR_MAP_FAILED.
*/
hi_s32 crypto_mem_open(crypto_mem *mem, compat_addr dma_ddr, hi_u32 dma_size);

/**
\brief  unmap a dma memory.
\param[in] mem  The struct of crypto_mem.
\param[in] dma_ddr The address of dma mem.
\return         HI_SUCCESS if successful, or HI_BASE_ERR_UNMAP_FAILED.
*/
hi_s32 crypto_mem_close(crypto_mem *mem);

/**
\brief  attach a cpu buffer with dma memory.
\param[in] mem  The struct of crypto_mem.
\param[in] buffer The user's buffer.
\return         HI_SUCCESS if successful, or HI_FAILURE.
*/
hi_s32 crypto_mem_attach(crypto_mem *mem, hi_void *buffer);

/**
\brief  flush dma memory,
\param[in] mem The struct of crypto_mem.
\param[in] dma2user 1-data from dma to user, 0-data from user to dma.
\param[in] offset The offset of data to be flush.
\param[in] data_size The size of data to be flush.
\return         HI_SUCCESS if successful, or HI_FAILURE.
*/
hi_s32 crypto_mem_flush(crypto_mem *mem, hi_u32 dma2user, hi_u32 offset, hi_u32 data_size);

/**
\brief  get dma memory physical address
\param[in] mem The struct of crypto_mem.
\return         HI_SUCCESS if successful, or HI_FAILURE.
*/
hi_s32 crypto_mem_phys(crypto_mem *mem, compat_addr *dma_addr);

/**
\brief  get dma memory virtual address
\param[in] mem The struct of crypto_mem.
\return         dma_addr if successful, or zero.
*/
hi_void *crypto_mem_virt(crypto_mem *mem);

/**
\brief  print the map info of local dma
\param[in] mem The struct of crypto_mem.
\return         dma_addr if successful, or zero.
*/
hi_void crypto_mem_map_info(hi_void);

/**
\brief  check whether cpu is secure or not.
\retval secure cpu, true is returned otherwise false is returned.
*/
hi_u32 crypto_is_sec_cpu(hi_void);

/**
\brief  check smmu's uuid whether sample with ower.
\retval secure cpu, true is returned otherwise false is returned.
*/
hi_s32 crypto_smmu_check_uuid(hi_u32 ddr, hi_u32 size);

/**
\brief  map the physics addr to cpu within the base table, contains the base addr and crg addr.
\retval    on success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned. */
hi_s32 module_addr_map(hi_void);

/**
\brief  unmap the physics addr to cpu within the base table, contains the base addr and crg addr.
\retval    on success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned. */
hi_s32 module_addr_unmap(hi_void);

/**
\brief  enable a module, open clock  and remove reset signal.
\param[in]  id The module id.
\retval    NA */
hi_void module_enable(module_id id);

/**
\brief  disable a module, close clock and set reset signal.
\param[in] id The module id.
\retval    NA */
hi_void module_disable(module_id id);

/**
\brief  get attribute of module.
\param[in]  id The module id.
\param[out] int_valid enable interrupt or not.
\param[out] int_num interrupt number of module.
\param[out] name name of module.
\retval    NA. */
hi_void module_get_attr(module_id id, hi_u32 *int_valid, hi_u32 *int_num, const char **name);

/**
\brief  read a register.
\param[in]  id The module id.
\param[in]  offset The module id.
\retval    the value of register */
hi_u32 module_reg_read(module_id id, hi_u32 offset);

/**
\brief  hex to string.
\param[in]  buf The string buffer.
\param[in]  val The value of hex.
\retval    NA */
hi_void hex2str(char *buf, hi_u8 val);

/**
\brief  write a register.
\param[in]  id The module id.
\retval    NA */
hi_void module_reg_write(module_id id, hi_u32 offset, hi_u32 val);

/* cipher module read and write a register */
#define symc_read(offset)         module_reg_read(CRYPTO_MODULE_ID_SYMC, offset)
#define symc_write(offset, val)   module_reg_write(CRYPTO_MODULE_ID_SYMC, offset, val)

/* hash module read and write a register */
#define hash_read(offset)         module_reg_read(CRYPTO_MODULE_ID_HASH, offset)
#define hash_write(offset, val)   module_reg_write(CRYPTO_MODULE_ID_HASH, offset, val)

/* rsa module read and write a register */
#define ifep_rsa_read(offset)       module_reg_read(CRYPTO_MODULE_ID_IFEP_RSA, offset)
#define ifep_rsa_write(offset, val) module_reg_write(CRYPTO_MODULE_ID_IFEP_RSA, offset, val)

/* trng module read and write a register */
#define trng_read(offset)         module_reg_read(CRYPTO_MODULE_ID_TRNG, offset)
#define trng_write(offset, val)   module_reg_write(CRYPTO_MODULE_ID_TRNG, offset, val)

/* sm2 module read and write a register */
#define pke_read(offset)         module_reg_read(CRYPTO_MODULE_ID_PKE, offset)
#define pke_write(offset, val)   module_reg_write(CRYPTO_MODULE_ID_PKE, offset, val)

/* smmu module read and write a register */
#define smmu_read(offset)         module_reg_read(CRYPTO_MODULE_ID_SMMU, offset)
#define smmu_write(offset, val)   module_reg_write(CRYPTO_MODULE_ID_SMMU, offset, val)

/**
\brief  Initialize the channel list.
\param[in]  ctx The context of channel.
\param[in]  num The channel numbers, max is 32.
\param[in]  ctx_size The size of context.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 crypto_channel_init(channel_context *ctx, hi_u32 num, hi_u32 ctx_size);

/**
\brief  Deinitialize the channel list.
\param[in]  ctx The context of channel.
\param[in]  num The channel numbers, max is 32.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 crypto_channel_deinit(channel_context *ctx, hi_u32 num);

/**
\brief  allocate a channel.
\param[in]  ctx The context of channel.
\param[in]  num The channel numbers, max is 32.
\param[in]  mask Mask whick channel allowed be alloc, max is 32.
\param[out] id The id of channel.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 crypto_channel_alloc(channel_context *ctx, hi_u32 num, hi_u32 mask, hi_u32 *id);

/**
\brief  free a channel.
\param[in]  ctx The context of channel.
\param[in]  num The channel numbers, max is 32.
\param[in] id The id of channel.
\retval    on success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_void crypto_channel_free(channel_context *ctx, hi_u32 num, hi_u32 id);

/**
\brief  get the private data of hard channel.
\param[in] ctx The context of channel.
\param[in] num The channel numbers, max is 32.
\param[in] id The id of channel.
\retval    on success, the address of context is returned.  On error, NULL is returned..
*/
hi_void *crypto_channel_get_context(channel_context *ctx, hi_u32 num, hi_u32 id);

/**
\brief  get the rang.
\retval    random number.
*/
hi_s32 crypto_copy_from_user(void *to, unsigned long to_len, const void *from, unsigned long from_len);
hi_s32 crypto_copy_to_user(void  *to, unsigned long to_len, const void *from, unsigned long from_len);
hi_u32 get_rand(hi_void);

/* Instruction Synchronization Barrier flushes the pipeline in the processor,
 * so that all instructions following the ISB are fetched from
 * cache or memory, after the instruction has been completed.
 * It ensures that the effects of context altering operations, such as
 * changing the ASID, or completed TLB maintenance operations,
 * or branch predictor maintenance operations, as well as all changes
 * to the CP15 registers, executed before the ISB instruction are visible
 * to the instructions fetched after the ISB.
*/
#define isb() __asm__ __volatile__ ("isb" : : : "memory")

/* Data Synchronization Barrier acts as a special kind of memory barrier.
*  No instruction in program order after this instruction executes until this instruction completes.
*  This instruction completes when: All explicit memory accesses before this instruction complete.
*  All Cache, Branch predictor and TLB maintenance operations before this instruction complete.
*/
#define dsb() __asm__ __volatile__ ("dsb" : : : "memory")

/* Data Memory Barrier acts as a memory barrier.
 * It ensures that all explicit memory accesses that appear in program order
 * before the DMB instruction are observed before any
 * explicit memory accesses that appear in program order after the DMB instruction.
 * It does not affect the ordering of any other instructions executing on the processor.
*/
#define dmb() __asm__ __volatile__ ("dmb" : : : "memory")

/* ARM Memory barrier */
#define ARM_MEMORY_BARRIER()  do { dsb(); isb(); dmb();} while (0)

#define crypto_ioremap_nocache(addr, size)  (void*)addr
#define crypto_iounmap(addr, size)

#define crypto_read(addr)         \
    (*(volatile unsigned int *)(hi_tee_drv_hal_phys_to_virt(((long unsigned int)(addr)))))
#define crypto_write(addr, val)   \
    (*(volatile unsigned int *)(hi_tee_drv_hal_phys_to_virt(((long unsigned int)(addr)))) = (val))

#define crypto_msleep(msec)          hi_tee_drv_hal_udelay(msec * 1000)
#define crypto_udelay(msec)          hi_tee_drv_hal_udelay(msec)

/* Clear key information */
void crypto_zeroize(void *buf, u32 len);

void *crypto_calloc(u32 n, u32 size);
#define crypto_malloc(x)            (0 < (x) ? hi_tee_drv_hal_malloc(x) : HI_NULL)
#define crypto_free(x)              {if (HI_NULL != (x))  hi_tee_drv_hal_free(x);}

#define crypto_request_irq(irq, func, name)  hi_tee_drv_hal_request_irq(irq + 32, (void *)func, 0, (void*)name)
#define crypto_free_irq(irq, name)           hi_tee_drv_hal_unregister_irq(irq + 32)

#define crypto_mutex                              struct hi_tee_hal_mutex
#define crypto_mutex_init(x)                      hi_tee_drv_hal_mutex_init("crypto", x)
#define crypto_mutex_lock(x)                      (hi_tee_drv_hal_mutex_lock(x), 0)
#define crypto_mutex_unlock(x)                    hi_tee_drv_hal_mutex_unlock(x)
#define crypto_mutex_destroy(x)                   hi_tee_drv_hal_mutex_destroy(x)
#define DEFINE_SEMAPHORE(x)                       static struct hi_tee_hal_mutex x

#define irqreturn_t  hi_u32

#define crypto_queue_head                          sem_t
#define crypto_queue_init(x)                       sem_init(&x, 0, 0)
#define crypto_queue_wake_up(x)                    sem_post(&x)
#define crypto_queue_wait_timeout(head, con, time) sem_wait(&head)
#define crypto_queue_destroy(x)                    sem_destroy(&x)

extern void v7_flush_kern_cache_all(void);
#define dcache_flush(va, len)                      hi_tee_drv_hal_dcache_flush(va, len)

#define crypto_owner                               TEE_UUID
#define crypto_get_owner(x)                        hi_tee_drv_hal_current_uuid(x)

void smmu_get_table_addr(hi_u64 *rdaddr, hi_u64 *wraddr, hi_u64 *table);

#define IRQ_HANDLED                               0
#define IRQ_NONE                                  1

#define LOG_D_MODULE_ID             0
#define LOG_D_FUNCTRACE             0
#define LOG_D_UNFTRACE              0

/**< allow modules to define internel error code, from 0x1000*/
#define log_err_code_def(errid)      (hi_u32)(((LOG_D_MODULE_ID) << 16)  | (errid))

/**< General Error Code, All modules can extend according to the rule */
#define HI_LOG_ERR_MEM              log_err_code_def(0x0001)      /**< Memory Operation Error */
#define HI_LOG_ERR_SEM              log_err_code_def(0x0002)      /**< Semaphore Operation Error */
#define HI_LOG_ERR_FILE             log_err_code_def(0x0003)      /**< File Operation Error */
#define HI_LOG_ERR_LOCK             log_err_code_def(0x0004)      /**< Lock Operation Error */
#define HI_LOG_ERR_PARAM            log_err_code_def(0x0005)      /**< Invalid Parameter */
#define HI_LOG_ERR_TIMER            log_err_code_def(0x0006)      /**< Timer error */
#define HI_LOG_ERR_THREAD           log_err_code_def(0x0007)      /**< Thread Operation Error */
#define HI_LOG_ERR_TIMEOUT          log_err_code_def(0x0008)      /**< Time Out Error */
#define HI_LOG_ERR_DEVICE           log_err_code_def(0x0009)      /**< Device Operation Error */
#define HI_LOG_ERR_STATUS           log_err_code_def(0x0010)      /**< Status Error */
#define HI_LOG_ERR_IOCTRL           log_err_code_def(0x0011)      /**< IO Operation Error */
#define HI_LOG_ERR_INUSE            log_err_code_def(0x0012)      /**< In use */
#define HI_LOG_ERR_EXIST            log_err_code_def(0x0013)      /**< Have exist */
#define HI_LOG_ERR_NOEXIST          log_err_code_def(0x0014)      /**< no exist */
#define HI_LOG_ERR_UNSUPPORTED      log_err_code_def(0x0015)      /**< Unsupported */
#define HI_LOG_ERR_UNAVAILABLE      log_err_code_def(0x0016)      /**< Unavailable */
#define HI_LOG_ERR_UNINITED         log_err_code_def(0x0017)      /**< Uninited */
#define HI_LOG_ERR_DATABASE         log_err_code_def(0x0018)      /**< Database Operation Error */
#define HI_LOG_ERR_OVERFLOW         log_err_code_def(0x0019)      /**< Overflow */
#define HI_LOG_ERR_EXTERNAL         log_err_code_def(0x0020)      /**< External Error */
#define HI_LOG_ERR_UNKNOWNED        log_err_code_def(0x0021)      /**< Unknow Error */
#define HI_LOG_ERR_FLASH            log_err_code_def(0x0022)      /**< Flash Operation Error*/
#define HI_LOG_ERR_ILLEGAL_IMAGE    log_err_code_def(0x0023)      /**< Illegal Image */
#define HI_LOG_ERR_ILLEGAL_UUID     log_err_code_def(0x0023)      /**< Illegal UUID */
#define HI_LOG_ERR_NOPERMISSION     log_err_code_def(0x0023)      /**< No Permission */

    /* Function trace log, strictly prohibited to expand */
#define hi_log_print_func_war(Func, ErrCode)   hi_warn_print_call_fun_err(Func, ErrCode)
#define hi_log_print_func_err(Func, ErrCode)   hi_err_print_call_fun_err(Func, ErrCode)
#define hi_log_print_err_code(ErrCode)         hi_err_print_err_code(ErrCode)

    /* Used for displaying more detailed error information */
#define hi_log_print_s32(val)                     hi_info_print_s32(val)
#define hi_log_print_u32(val)                     hi_info_print_u32(val)
#define hi_log_print_s64(val)                     hi_info_print_s64(val)
#define hi_log_print_u64(val)                     hi_info_print_u64(val)
#define hi_log_print_h32(val)                     hi_info_print_h32(val)
#define hi_log_print_h64(val)                     hi_info_print_h64(val)
#define hi_log_print_str(val)                     hi_info_print_str(val)
#define hi_log_print_void(val)                    hi_info_print_void(val)
#define hi_log_print_float(val)                   hi_info_print_float(val)
#define hi_log_print_info(val)                    hi_info_print_info(val)

#define hi_log_func_enter()                       hi_dbg_func_enter()
#define hi_log_func_exit()                        hi_dbg_func_exit()

#define hi_log_check_param(val)                            \
    do                                                      \
    {                                                       \
        if (val)                                           \
        {                                                   \
            hi_log_print_err_code(HI_LOG_ERR_PARAM);          \
            return HI_LOG_ERR_PARAM;                        \
        }                                                   \
    } while (0)


#define hi_log_check_inited(init_count)                     \
    do                                                      \
    {                                                       \
        if (init_count == 0)                                \
        {                                                   \
            hi_log_print_err_code(HI_LOG_ERR_UNINITED);       \
            return HI_LOG_ERR_UNINITED;                     \
        }                                                   \
    } while (0)

#define hi_log_check_length(_check_length_val)                  \
    do                                                          \
    {                                                           \
        if (_check_length_val)                                  \
        {                                                       \
            hi_log_print_err_code(HI_ERR_CIPHER_INVALID_LENGTH);  \
            return HI_ERR_CIPHER_INVALID_LENGTH;                \
        }                                                       \
    } while (0)

/*! \assert */
#define crypto_assert(expr) \
    do { \
        if (!(expr)) { \
            /* hi_log_error("assertion '%s' failed\n", #expr); */ \
            /* hi_log_error("at %s:%d (func '%s')\n", __FILE__, __LINE__, __func__); */ \
            return HI_ERR_CIPHER_INVALID_PARA; \
        } \
    } while (0)

#define check_exit(expr) \
    do { \
        if ((ret = expr != HI_SUCCESS)) { \
            hi_log_print_func_err(expr, ret); \
            goto exit__; \
        } \
    } while (0)

#ifdef HI_CIPHER_TEST
#define hi_print_hex(name, str, len) \
    do { \
        hi_u32 _i = 0; hi_u8 *_str = (hi_u8*)str; \
        HI_PRINT("[%s]:\n", name);\
        for (_i = 0 ; _i < (len); _i++) {\
            if((_i % 16 == 0) && (_i != 0)) HI_PRINT("\n");\
            HI_PRINT("\\x%02x", *((_str)+_i));\
        }\
        HI_PRINT("\n");\
    } while (0)

#undef hi_log_fatal
#undef hi_log_error
#undef hi_log_warn
#undef hi_log_info
#undef hi_log_debug

#define hi_log_fatal(fmt...)
#define hi_log_error(fmt...)       hi_log_err(fmt)
#define hi_log_warn(fmt...)
#define hi_log_info(fmt...)
#define hi_log_debug(fmt...)
#else
#define hi_print_hex(name, str, len)
#define hi_log_fatal(fmt...)
#define hi_log_error(fmt...)        hi_log_err(fmt)
#define hi_log_warn(fmt...)
#define hi_log_info(fmt...)
#define hi_log_debug(fmt...)

#endif

#endif

