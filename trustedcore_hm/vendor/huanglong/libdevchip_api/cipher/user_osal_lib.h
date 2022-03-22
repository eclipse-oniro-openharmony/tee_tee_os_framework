/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee cipher user osal head file
 * Author: cipher group
 * Create: 2019-12-11
 */

#ifndef __USER_OSAL_LIB_H__
#define __USER_OSAL_LIB_H__

#include "hmdrv.h"
#include "hm_msg_type.h"
#include "securec.h"
#include "hi_tee_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_cipher.h"
#include "hi_tee_drv_cipher.h"
#include "tee_drv_cipher_ioctl.h"
#include "hi_mpi_cipher.h"
#include "hi_tee_errcode.h"

#define HI_LOG_D_MODULE_ID     HI_ID_CIPHER
#define HI_LOG_D_FUNCTRACE     0
#define HI_LOG_D_UNFTRACE      0
#include "hi_log.h"

#define hi_log_check_param(val)                            \
    do                                                      \
    {                                                       \
        if (val)                                           \
        {                                                   \
            hi_err_print_err_code(HI_ERR_CIPHER_INVALID_PARA);          \
            return HI_ERR_CIPHER_INVALID_PARA;                        \
        }                                                   \
    } while (0)

#define HI_LOG_CHECK_PARAM     hi_log_check_param

/** @} */  /** <!-- ==== Structure Definition end ==== */

/*! \****************************** API Declaration *****************************/
/*! \addtogroup    osal lib */
/** @{ */  /** <!--[osal] */

void print_string(const char *name, hi_u8 *string, hi_u32 size);

#ifndef HI_PRINT
#define HI_PRINT(fmt...)                            hi_tee_printf(fmt)
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define crypto_malloc(x)                    (0 < (x) ? TEE_Malloc(x, 0) : HI_NULL)
#define crypto_free(x)                      {if (HI_NULL != (x)) TEE_Free(x);}
void *crypto_calloc(hi_u32 element_num, hi_u32 element_size);

#define crypto_mutex                pthread_mutex_t
#define crypto_mutex_init(x)        (void)pthread_mutex_init(x, NULL)
#define crypto_mutex_lock(x)        (void)pthread_mutex_lock(x)
#define crypto_mutex_unlock(x)      (void)pthread_mutex_unlock(x)
#define crypto_mutex_destroy(x)     pthread_mutex_destroy(x)

#define QUEUE_POOL_MAX_DEPTH     0x20
#define QUEUE_POOL_MAX_MSG_SIZE  0x100

typedef struct hiqueue_pool {
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    hi_u32 msg_size;
    hi_u8 *msg_data;
    hi_u32 count;
    hi_u32 depth;
    hi_u32 head;
    hi_u32 tail;
}queue_pool;

hi_s32 queue_pool_create(queue_pool *queue, hi_u32 msg_size, hi_u32 depth);
hi_s32 queue_pool_destroy(queue_pool *queue);
hi_s32 queue_pool_read(queue_pool *queue, hi_void *msg, hi_u32 msg_size);
hi_s32 queue_pool_write(queue_pool *queue, const hi_void *msg, hi_u32 msg_size);

#define HI_LOG_CHECK_LENGTH(_check_length_val) do {             \
        if (_check_length_val) {                                \
            hi_err_print_err_code(HI_ERR_CIPHER_INVALID_LENGTH);  \
            return HI_ERR_CIPHER_INVALID_LENGTH;                \
        }                                                       \
    } while (0)

#define crypto_open(a, b, c)                (CRYPTO_IOCTL(CRYPTO_CMD_INIT, NULL), 1)
#define crypto_close(x)                     (CRYPTO_IOCTL(CRYPTO_CMD_DEINIT, NULL), 0)

hi_s32 CRYPTO_IOCTL(hi_u32 cmd, const hi_void *argp);

#endif  /* End of #ifndef __HI_DRV_CIPHER_H__ */
