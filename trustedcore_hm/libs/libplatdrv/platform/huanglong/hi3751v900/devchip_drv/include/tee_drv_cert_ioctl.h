/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: cert driver ioctl related definition
 * Author: Hisilicon hisecurity team
 * Create: 2019-03-21
 */

#ifndef __DRV_CERT_IOCTL_H__
#define __DRV_CERT_IOCTL_H__

#include "hi_type_dev.h"
#include "hi_tee_module_id.h"
#include "hi_tee_drv_cert.h"
#include "hi_tee_cert.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define _IOC_NRBITS     8
#define _IOC_TYPEBITS   8

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

#ifndef _IOC_NONE
#define _IOC_NONE 0U
#endif

#ifndef _IOC_WRITE
#define _IOC_WRITE 1U
#endif

#ifndef _IOC_READ
#define _IOC_READ 2U
#endif

#ifndef _ioc
#define _ioc(dir,type,nr,size) \
        (((dir)  << _IOC_DIRSHIFT) | \
         ((type) << _IOC_TYPESHIFT) | \
         ((nr)   << _IOC_NRSHIFT) | \
         ((size) << _IOC_SIZESHIFT))
#endif

#ifndef _ioc_typecheck
#define _ioc_typecheck(t) (sizeof(t))
#endif

/* used to create numbers */
#ifndef _io
#define _io(type, nr)             _ioc(_IOC_NONE, (type), (nr), 0)
#endif

#ifndef _ior
#define _ior(type, nr, size)      _ioc(_IOC_READ, (type), (nr), (_ioc_typecheck(size)))
#endif

#ifndef _iow
#define _iow(type, nr, size)      _ioc(_IOC_WRITE, (type), (nr), (_ioc_typecheck(size)))
#endif

#ifndef _iowr
#define _iowr(type, nr, size)     _ioc(_IOC_READ | _IOC_WRITE, (type), (nr), (_ioc_typecheck(size)))
#endif
#ifndef _ior_bad
#define _ior_bad(type, nr, size)  _ioc(_IOC_READ, (type), (nr), sizeof(size))
#endif

#ifndef _iow_bad
#define _iow_bad(type, nr, size)  _ioc(_IOC_WRITE, (type), (nr), sizeof(size))
#endif

#ifndef _iowr_bad
#define _iowr_bad(type, nr, size) _ioc(_IOC_READ | _IOC_WRITE, (type), (nr), sizeof(size))
#endif

/* used to decode ioctl numbers.. */
#define _ioc_dir(nr)            (((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _ioc_type(nr)           (((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _ioc_nr(nr)             (((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _ioc_size(nr)           (((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)

typedef struct {
    hi_cert_res_handle handle;
    hi_cert_command cmd;
} cert_cmd_ctl;

/* ioctl definitions */
#define    CMD_CERT_AKLEXCHANGE         _iowr(HI_ID_CERT, 0x1, cert_cmd_ctl)
#define    CMD_CERT_AKLKEYSEND_CTL      _iow(HI_ID_CERT, 0x2, hi_cert_key_data)
#define    CMD_CERT_METADATA            _ior(HI_ID_CERT, 0x2, hi_u32)
#define    CMD_CERT_LOCK                _ior(HI_ID_CERT, 0x3, hi_cert_res_handle)
#define    CMD_CERT_UNLOCK              _iowr(HI_ID_CERT, 0x4, hi_cert_res_handle)
#define    CMD_CERT_RESET               _io(HI_ID_CERT, 0x5)
#define    CMD_CERT_MAX                 0xFFFFFFFF

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* end of #ifndef __DRV_CERT_IOCTL_H__*/
