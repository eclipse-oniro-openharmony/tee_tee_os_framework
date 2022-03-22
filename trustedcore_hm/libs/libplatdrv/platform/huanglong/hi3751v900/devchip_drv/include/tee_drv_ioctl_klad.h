/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:KLAD ioctl defination.
 * Author: Linux SDK team
 * Create: 2019/06/22
 */
#ifndef __DRV_KLAD_IOCTL_H__
#define __DRV_KLAD_IOCTL_H__

#include "tee_drv_klad_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

#define _IOC_NRBITS     8
#define _IOC_TYPEBITS   8

/*
 * Let any architecture override either of the following before
 * including this file.
 */
#ifndef _IOC_SIZEBITS
# define _IOC_SIZEBITS  14
#endif

#ifndef _IOC_DIRBITS
# define _IOC_DIRBITS   2
#endif

#define _IOC_NRMASK     ((1 << _IOC_NRBITS) - 1)
#define _IOC_TYPEMASK   ((1 << _IOC_TYPEBITS) - 1)
#define _IOC_SIZEMASK   ((1 << _IOC_SIZEBITS) - 1)
#define _IOC_DIRMASK    ((1 << _IOC_DIRBITS) - 1)

#define _IOC_NRSHIFT    0
#define _IOC_TYPESHIFT  (_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT  (_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT   (_IOC_SIZESHIFT + _IOC_SIZEBITS)

/*
 * Direction bits, which any architecture can choose to override
 * before including this file.
 */
#ifndef _IOC_NONE
# define _IOC_NONE      0U
#endif

#ifndef _IOC_WRITE
# define _IOC_WRITE     1U
#endif

#ifndef _IOC_READ
# define _IOC_READ      2U
#endif

#define _ioc(dir, type, nr, size) \
        (((dir)  << _IOC_DIRSHIFT) | \
         ((type) << _IOC_TYPESHIFT) | \
         ((nr)   << _IOC_NRSHIFT) | \
         ((size) << _IOC_SIZESHIFT))

#define _ioc_typecheck(t) (sizeof(t))

/* used to create numbers */
#define _io(type, nr)             _ioc(_IOC_NONE, (type), (nr), 0)
#define _ior(type, nr, size)      _ioc(_IOC_READ, (type), (nr), (_ioc_typecheck(size)))
#define _iow(type, nr, size)      _ioc(_IOC_WRITE, (type), (nr), (_ioc_typecheck(size)))
#define _iowr(type, nr, size)     _ioc(_IOC_READ | _IOC_WRITE, (type), (nr), (_ioc_typecheck(size)))
#define _ior_bad(type, nr, size)  _ioc(_IOC_READ, (type), (nr), sizeof(size))
#define _iow_bad(type, nr, size)  _ioc(_IOC_WRITE, (type), (nr), sizeof(size))
#define _iowr_bad(type, nr, size) _ioc(_IOC_READ | _IOC_WRITE, (type), (nr), sizeof(size))

/* used to decode ioctl numbers.. */
#define _ioc_dir(nr)            (((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _ioc_type(nr)           (((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _ioc_nr(nr)             (((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _ioc_size(nr)           (((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)

typedef struct {
    hi_handle create_handle;  /* handle created by driver */
} hi_klad_ctl_handle;

typedef struct {
    hi_handle handle;
    hi_handle target;
} hi_klad_ctl_target;

typedef struct {
    hi_handle handle;
    hi_klad_attr attr;
} hi_klad_ctl_attr;

typedef struct {
    hi_handle handle;
    hi_rootkey_attr rk_attr;
} hi_rk_ctl_attr;

typedef struct {
    hi_handle handle;
    hi_klad_session_key session_key;
} hi_klad_ctl_session_key;

typedef struct {
    hi_handle handle;
    hi_klad_content_key content_key;
} hi_klad_ctl_content_key;

typedef struct {
    hi_handle handle;
    hi_klad_clear_key clear_key;
} hi_klad_ctl_clear_key;

typedef struct {
    hi_handle handle;
    hi_klad_nonce_key nonce_key;
} hi_klad_ctl_nonce_key;

typedef struct {
    hi_handle handle;
} hi_klad_ctl_fp_key;

typedef struct {
    hi_handle handle;
    hi_klad_gen_key gen_key;
} hi_klad_ctl_gen_key;


typedef struct {
    hi_rootkey_attr rk_attr;
    hi_klad_attr attr;
    hi_handle hw_handle;
} hi_klad_create_attr;

typedef struct {
    hi_s64 target_cnt;
    hi_handle target_handle;

    hi_s64 rk_attr_cnt;
    hi_rootkey_attr rk_attr;

    hi_s64 attr_cnt;
    hi_klad_attr attr;

    hi_s64 session_cnt[HI_KLAD_LEVEL_MAX];
    hi_klad_session_key session_key[HI_KLAD_LEVEL_MAX];

    hi_s64 content_cnt;
    hi_klad_content_key content_key;

    hi_handle hw_handle;
} hi_klad_com_entry;

typedef struct {
    hi_s64 target_cnt;
    hi_handle target_handle;

    hi_s64 attr_cnt;
    hi_klad_attr attr;

    hi_s64 session_ta_cnt;
    hi_klad_ta_key session_ta_key;

    hi_s64 trans_cnt;
    hi_klad_trans_data trans_data;

    hi_s64 content_ta_cnt;
    hi_klad_ta_key content_ta_key;

    hi_handle hw_handle;
} hi_klad_ta_entry;

typedef struct {
    hi_s64 target_cnt;
    hi_handle target_handle;

    hi_s64 attr_cnt;
    hi_klad_attr attr;

    hi_s64 session_cnt[HI_KLAD_LEVEL_MAX];
    hi_klad_session_key session_key[HI_KLAD_LEVEL_MAX];

    hi_s64 nonce_cnt;
    hi_klad_nonce_key nonce_key;

    hi_handle hw_handle;
} hi_klad_nonce_entry;

typedef struct {
    hi_s64 target_cnt;
    hi_handle target_handle;

    hi_s64 attr_cnt;
    hi_klad_attr attr;

    hi_s64 session_cnt[HI_KLAD_LEVEL_MAX];
    hi_klad_session_key session_key[HI_KLAD_LEVEL_MAX];

    hi_s64 fp_cnt;
    hi_klad_fp_key fp_key;

    hi_handle hw_handle;
} hi_klad_fp_entry;

typedef struct {
    hi_s64 target_cnt;
    hi_handle target_handle;

    hi_s64 attr_cnt;
    hi_klad_attr attr;

    hi_s64 clr_cnt;
    hi_klad_clear_key clr_key;

    hi_handle hw_handle;
} hi_klad_clr_entry;

#define CMD_KLAD_CREATE                     _iowr(HI_ID_KLAD, 0x1, hi_klad_ctl_handle)
#define CMD_KLAD_DESTROY                    _iow (HI_ID_KLAD, 0x2, hi_handle)
#define CMD_KLAD_ATTACH                     _iow (HI_ID_KLAD, 0x3, hi_klad_ctl_target)
#define CMD_KLAD_DETACH                     _iow (HI_ID_KLAD, 0x4, hi_klad_ctl_target)
#define CMD_KLAD_GET_ATTR                   _iowr(HI_ID_KLAD, 0x5, hi_klad_ctl_attr)
#define CMD_KLAD_SET_ATTR                   _iow (HI_ID_KLAD, 0x6, hi_klad_ctl_attr)
#define CMD_RK_GET_ATTR                     _iowr(HI_ID_KLAD, 0x25, hi_rk_ctl_attr)
#define CMD_RK_SET_ATTR                     _iow (HI_ID_KLAD, 0x26, hi_rk_ctl_attr)
#define CMD_KLAD_SET_SESSION_KEY            _iow (HI_ID_KLAD, 0x7, hi_klad_ctl_session_key)
#define CMD_KLAD_SET_CONTENT_KEY            _iow (HI_ID_KLAD, 0x9, hi_klad_ctl_content_key)
#define CMD_KLAD_SET_CLEAR_KEY              _iow (HI_ID_KLAD, 0xa, hi_klad_ctl_clear_key)
#define CMD_KLAD_GET_NONCE_KEY              _iowr(HI_ID_KLAD, 0xb, hi_klad_ctl_nonce_key)
#define CMD_KLAD_FP_KEY                     _iowr(HI_ID_KLAD, 0xc, hi_klad_ctl_fp_key)
#define CMD_KLAD_GENERATE_KEY               _iowr(HI_ID_KLAD, 0xd, hi_klad_ctl_gen_key)

#define CMD_KLAD_COM_CREATE                 _iowr(HI_ID_KLAD, 0x40, hi_klad_create_attr)
#define CMD_KLAD_TA_CREATE                  _iowr(HI_ID_KLAD, 0x41, hi_klad_create_attr)
#define CMD_KLAD_FP_CREATE                  _iowr(HI_ID_KLAD, 0x42, hi_klad_create_attr)
#define CMD_KLAD_NONCE_CREATE               _iowr(HI_ID_KLAD, 0x43, hi_klad_create_attr)
#define CMD_KLAD_FP_ROUTE                   _iowr(HI_ID_KLAD, 0x44, hi_klad_create_attr)

#define CMD_KLAD_COM_STARTUP                _iowr(HI_ID_KLAD, 0x20, hi_klad_com_entry)
#define CMD_KLAD_TA_STARTUP                 _iowr(HI_ID_KLAD, 0x21, hi_klad_ta_entry)
#define CMD_KLAD_FP_STARTUP                 _iowr(HI_ID_KLAD, 0x22, hi_klad_fp_entry)
#define CMD_KLAD_NONCE_STARTUP              _iowr(HI_ID_KLAD, 0x23, hi_klad_nonce_entry)
/* Need not destory seperately. clear keyladder have not RKP process. */
#define CMD_KLAD_CLR_PROCESS                _iow(HI_ID_KLAD, 0x24, hi_klad_clr_entry)
#define CMD_KLAD_FP_CRYPTO                  _iowr(HI_ID_KLAD, 0x25, hi_klad_fp_entry)

#define CMD_KLAD_COM_DESTORY                _iow(HI_ID_KLAD, 0x30, hi_handle)
#define CMD_KLAD_TA_DESTORY                 _iow(HI_ID_KLAD, 0x31, hi_handle)
#define CMD_KLAD_FP_DESTORY                 _iow(HI_ID_KLAD, 0x32, hi_handle)
#define CMD_KLAD_NONCE_DESTORY              _iow(HI_ID_KLAD, 0x33, hi_handle)

#define CMD_KLAD_MAX                        0xFFFFFFFF

#ifdef __cplusplus
}
#endif
#endif /* __DRV_KLAD_IOCTL_H__ */
