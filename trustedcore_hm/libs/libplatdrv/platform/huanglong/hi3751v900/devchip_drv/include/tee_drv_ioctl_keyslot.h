/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:KS ioctl defination.
 * Author: Linux SDK team
 * Create: 2019/06/22
 */
#ifndef __DRV_KS_IOCTL_H__
#define __DRV_KS_IOCTL_H__

#include "tee_drv_keyslot_struct.h"

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

/* structure for ioctl */
typedef struct {
    hi_handle ks_handle;
    hi_keyslot_type ks_type; /* only for command: CMD_KS_CREATE */
} ks_entry;

#define CMD_KS_CREATE                  _iowr(HI_ID_KEYSLOT,  0x1, ks_entry)
#define CMD_KS_DESTORY                 _iow(HI_ID_KEYSLOT,  0x2, ks_entry)
#define CMD_KS_MAX                     0xffffffff

#ifdef __cplusplus
}
#endif
#endif /* __DRV_KS_IOCTL_H__ */
