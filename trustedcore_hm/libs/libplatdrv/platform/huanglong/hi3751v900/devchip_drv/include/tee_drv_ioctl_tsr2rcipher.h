/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tee tsr2rcipher ioctl defination.
 * Author: sdk
 * Create: 2019-08-02
 */

#ifndef __TEE_DRV_IOCTL_TSR2RCIPHER_H__
#define __TEE_DRV_IOCTL_TSR2RCIPHER_H__

#include "hi_type_dev.h"
#include "hi_log.h"
#include "hi_tee_errcode.h"
#include "hi_tee_module_id.h"
#include "hi_tee_drv_syscall_id.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define TSR2RCIPHER_MIN_IV_LEN        (8)
#define TSR2RCIPHER_MAX_IV_LEN        (16)
#define TSR2RCIPHER_MAX_SIZE_PRE_DESC (64 * 1024 * 188)
#define TSR2RCIPHER_TS_PACKAGE_LEN    (188)
#define TSR2RCIPHER_ADDR_ALIGN        (4)

#define TSC_CHECK_NULL_POINTER(p) do { \
    if ((p) == HI_NULL) {              \
        hi_log_err("null pointer!\n"); \
        return HI_TEE_ERR_INVALID_PTR; \
    }                                  \
} while (0)

#define _IOC_NRBITS   8
#define _IOC_TYPEBITS 8

/* Let any architecture override either of the following before including this file. */
#ifndef _IOC_SIZEBITS
#define _IOC_SIZEBITS 14
#endif

#ifndef _IOC_DIRBITS
#define _IOC_DIRBITS 2
#endif

#define _IOC_NRMASK   ((1 << _IOC_NRBITS) - 1)
#define _IOC_TYPEMASK ((1 << _IOC_TYPEBITS) - 1)
#define _IOC_SIZEMASK ((1 << _IOC_SIZEBITS) - 1)
#define _IOC_DIRMASK  ((1 << _IOC_DIRBITS) - 1)

#define _IOC_NRSHIFT   0
#define _IOC_TYPESHIFT (_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT (_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT  (_IOC_SIZESHIFT + _IOC_SIZEBITS)

/* Direction bits, which any architecture can choose to override before including this file. */
#ifndef _IOC_NONE
#define _IOC_NONE 0U
#endif

#ifndef _IOC_WRITE
#define _IOC_WRITE 1U
#endif

#ifndef _IOC_READ
#define _IOC_READ 2U
#endif

#define _ioc(dir, type, nr, size) (((dir) << _IOC_DIRSHIFT) | ((type) << _IOC_TYPESHIFT) | \
                                   ((nr)  << _IOC_NRSHIFT)  | ((size) << _IOC_SIZESHIFT))

#define _ioc_type_check(t) (sizeof(t))

/* used to create numbers */
#define _io(type, nr)             _ioc(_IOC_NONE, (type), (nr), 0)
#define _ior(type, nr, size)      _ioc(_IOC_READ, (type), (nr), (_ioc_type_check(size)))
#define _iow(type, nr, size)      _ioc(_IOC_WRITE, (type), (nr), (_ioc_type_check(size)))
#define _iowr(type, nr, size)     _ioc(_IOC_READ | _IOC_WRITE, (type), (nr), (_ioc_type_check(size)))
#define _ior_bad(type, nr, size)  _ioc(_IOC_READ, (type), (nr), sizeof(size))
#define _iow_bad(type, nr, size)  _ioc(_IOC_WRITE, (type), (nr), sizeof(size))
#define _iowr_bad(type, nr, size) _ioc(_IOC_READ | _IOC_WRITE, (type), (nr), sizeof(size))

/* used to decode ioctl numbers.. */
#define _ioc_dir(nr)  (((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _ioc_type(nr) (((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _ioc_nr(nr)   (((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _ioc_size(nr) (((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)

/* and for the drivers/sound files... */
#define IOC_IN        (_IOC_WRITE << _IOC_DIRSHIFT)
#define IOC_OUT       (_IOC_READ << _IOC_DIRSHIFT)
#define IOC_INOUT     ((_IOC_WRITE | _IOC_READ) << _IOC_DIRSHIFT)
#define IOCSIZE_MASK  (_IOC_SIZEMASK << _IOC_SIZESHIFT)
#define IOCSIZE_SHIFT (_IOC_SIZESHIFT)

typedef enum {
    TSR2RCIPHER_ALG_AES_ECB   = 0x10,
    TSR2RCIPHER_ALG_AES_CBC   = 0x13,
    TSR2RCIPHER_ALG_AES_IPTV  = 0x16,
    TSR2RCIPHER_ALG_AES_CTR   = 0x17,
    TSR2RCIPHER_ALG_SMS4_ECB  = 0x30,
    TSR2RCIPHER_ALG_SMS4_CBC  = 0x31,
    TSR2RCIPHER_ALG_SMS4_IPTV = 0x32,
    TSR2RCIPHER_ALG_MAX
} tsr2rcipher_alg;

typedef enum {
    TSR2RCIPHER_MODE_PAYLOAD = 0x0,
    TSR2RCIPHER_MODE_RAW     = 0x1,
    TSR2RCIPHER_MODE_MAX
} tsr2rcipher_mode;

typedef enum {
    TSR2RCIPHER_IV_EVEN = 0,
    TSR2RCIPHER_IV_ODD  = 1,
    TSR2RCIPHER_IV_MAX,
} tsr2rcipher_iv_type;

typedef struct {
    hi_u32 ts_chan_cnt;
} tsr2rcipher_capability;

typedef struct {
    tsr2rcipher_alg  alg;
    tsr2rcipher_mode mode;
    hi_bool          is_crc_check;
    hi_bool          is_create_ks;
    hi_bool          is_odd_key;
} tsr2rcipher_attr;

typedef struct {
    tsr2rcipher_attr tsc_attr;
    hi_handle        handle;
} tsr2rcipher_create_info;

typedef struct {
    hi_handle        handle;
    tsr2rcipher_attr tsc_attr;
} tsr2rcipher_attr_info;

typedef struct {
    hi_handle            handle;
    tsr2rcipher_iv_type  type;
    hi_u32               len;
    hi_u8                iv[TSR2RCIPHER_MAX_IV_LEN];
} tsr2rcipher_set_iv_info;

typedef struct {
    hi_handle handle;
    hi_u64 src_buf;
    hi_u64 dst_buf;
    hi_u32 data_len;
} tsr2rcipher_deal_data_info;

typedef struct {
    hi_handle tsc_handle;
    hi_handle ks_handle;
} tsr2rcipher_get_ks_handle;

typedef struct {
    hi_handle tsc_handle;
    hi_handle ks_handle;
} tsr2rcipher_associate_ks;

/* tee ioctl definitions */
#define TSR2RCIPHER_TEE_IOCTL_GET_CAP   _iowr(HI_ID_TSR2RCIPHER, 0x0, tsr2rcipher_capability)
#define TSR2RCIPHER_TEE_IOCTL_CREATE    _iowr(HI_ID_TSR2RCIPHER, 0x1, tsr2rcipher_create_info)
#define TSR2RCIPHER_TEE_IOCTL_DESTROY   _iow(HI_ID_TSR2RCIPHER, 0x2, hi_handle)
#define TSR2RCIPHER_TEE_IOCTL_GET_ATTR  _iowr(HI_ID_TSR2RCIPHER, 0x3, tsr2rcipher_attr_info)
#define TSR2RCIPHER_TEE_IOCTL_SET_ATTR  _iow(HI_ID_TSR2RCIPHER, 0x4, tsr2rcipher_attr_info)
#define TSR2RCIPHER_TEE_IOCTL_GET_KS    _iowr(HI_ID_TSR2RCIPHER, 0x5, tsr2rcipher_get_ks_handle)
#define TSR2RCIPHER_TEE_IOCTL_ATTACH_KS _iow(HI_ID_TSR2RCIPHER, 0x6, tsr2rcipher_associate_ks)
#define TSR2RCIPHER_TEE_IOCTL_DETACH_KS _iow(HI_ID_TSR2RCIPHER, 0x7, tsr2rcipher_associate_ks)
#define TSR2RCIPHER_TEE_IOCTL_SET_IV    _iow(HI_ID_TSR2RCIPHER, 0x8, tsr2rcipher_set_iv_info)
#define TSR2RCIPHER_TEE_IOCTL_ENCRYPT   _iow(HI_ID_TSR2RCIPHER, 0x9, tsr2rcipher_deal_data_info)
#define TSR2RCIPHER_TEE_IOCTL_DECRYPT   _iow(HI_ID_TSR2RCIPHER, 0xA, tsr2rcipher_deal_data_info)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* end of __TEE_DRV_IOCTL_TSR2RCIPHER_H__ */
