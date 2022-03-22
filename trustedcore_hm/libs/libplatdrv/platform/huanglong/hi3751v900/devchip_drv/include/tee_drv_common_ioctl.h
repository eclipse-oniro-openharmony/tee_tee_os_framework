/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description:
 */

#ifndef __TEE_DRV_COMMON_IOCTL_H__
#define __TEE_DRV_COMMON_IOCTL_H__

#include "hi_log.h"
#include "hi_type_dev.h"
#include "hi_tee_drv_syscall_id.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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

#define _IOC(dir, type, nr, size) (((dir) << _IOC_DIRSHIFT) | ((type) << _IOC_TYPESHIFT) | \
                                   ((nr)  << _IOC_NRSHIFT)  | ((size) << _IOC_SIZESHIFT))

#define _IOC_TYPECHECK(t) (sizeof(t))

/* used to create numbers */
#define _IO(type, nr)             _IOC(_IOC_NONE, (type), (nr), 0)
#define _IOR(type, nr, size)      _IOC(_IOC_READ, (type), (nr), (_IOC_TYPECHECK(size)))
#define _IOW(type, nr, size)      _IOC(_IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(size)))
#define _IOWR(type, nr, size)     _IOC(_IOC_READ | _IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(size)))
#define _IOR_BAD(type, nr, size)  _IOC(_IOC_READ, (type), (nr), sizeof(size))
#define _IOW_BAD(type, nr, size)  _IOC(_IOC_WRITE, (type), (nr), sizeof(size))
#define _IOWR_BAD(type, nr, size) _IOC(_IOC_READ | _IOC_WRITE, (type), (nr), sizeof(size))

/* used to decode ioctl numbers.. */
#define _IOC_DIR(nr)  (((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _IOC_TYPE(nr) (((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _IOC_NR(nr)   (((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _IOC_SIZE(nr) (((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)

/* and for the drivers/sound files... */
#define IOC_IN        (_IOC_WRITE << _IOC_DIRSHIFT)
#define IOC_OUT       (_IOC_READ << _IOC_DIRSHIFT)
#define IOC_INOUT     ((_IOC_WRITE | _IOC_READ) << _IOC_DIRSHIFT)
#define IOCSIZE_MASK  (_IOC_SIZEMASK << _IOC_SIZESHIFT)
#define IOCSIZE_SHIFT (_IOC_SIZESHIFT)

#define SECURE_OS_VERSION_LEN 96

typedef struct {
    hi_mod_id module_id;
    hi_tee_log_level log_level;
} log_tee_level_info;

typedef struct {
    hi_char version[SECURE_OS_VERSION_LEN];
    hi_u32 total_size;
} common_tee_version_info;

/* ioctl definitions */
#define LOG_TEE_IOCTL_SET_LEVEL _IOW (HI_ID_LOG, 0x1, log_tee_level_info)
#define LOG_TEE_IOCTL_GET_LEVEL _IOWR(HI_ID_LOG, 0x2, log_tee_level_info)

#define COMMON_TEE_IOCTL_GET_VERSION _IOWR(HI_ID_SYS, 0x1, common_tee_version_info)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* end of __TEE_DRV_COMMON_IOCTL_H__ */
