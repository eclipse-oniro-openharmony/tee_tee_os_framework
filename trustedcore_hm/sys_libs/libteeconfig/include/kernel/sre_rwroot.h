/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: sre rwroot implementation
 * Create: 2018-05-18
 */
#ifndef __SRE_RWROOT_H
#define __SRE_RWROOT_H
#include <sre_typedef.h> /* UINT32 */

UINT32 SRE_ReadRootStatus(VOID);
UINT32 SRE_WriteRootStatus(UINT32 status);

/*
 *  mask the enabled BIT.
 *  need to change with operation_configs simultaneously.
 */
#define WRITE_MASK 0x1F87DFu

/*
 * READ_MASK don't take OEMINFO_BIT | ROOTPROCBIT in count.
 *    OEMINFO_BIT : not status on last poweron.
 *    ROOTPROCBIT : not accurate enough to take account.
 *
 *    on  :    do scan and verify
 *    off :    not support, not scan or verify
 */
#define READ_MASK 0xFFFFFEFCu

enum root_status_bit {
    ROOTSTATE_BIT = 0, /* 0    on */
    /* read from fastboot */
    OEMINFO_BIT,       /* 1     on */
    FBLOCK_YELLOW_BIT, /* 2    on */
    FBLOCK_RED_BIT,    /* 3    on */
    FBLOCK_ORANGE_BIT, /* 4    on */
                       /* 5    off */
    /* dy scan result */
    KERNELCODEBIT = 6, /* 6    on */
    SYSTEMCALLBIT,     /* 7    on */
    ROOTPROCBIT,       /* 8    on */
    SESTATUSBIT,       /* 9    on */
    SEHOOKBIT = 10,    /* 10   on */
    SEPOLICYBIT,       /* 11   off */
    PROCINTERBIT,      /* 12    off */
    FRAMINTERBIT,      /* 13    off */
    INAPPINTERBIT,     /* 14    off */
    NOOPBIT = 15,      /* 15    on */
    ITIMEOUTBIT,       /* 16    on */
    EIMABIT,           /* 17    on */
    SETIDBIT,          /* 18   on */
    CHECKFAILBIT,      /* 19   on */
    RODATABIT,         /* 20   on */
    TOTALBIT
};

#define RWROOT_RET_SUCCESS (0)
#define RWBOOT_RET_FAILURE (0xFFFFFFFF)

/* Copy from keymaster1_util.h --start */
enum lock_state {
    LSTATE_LOCKED,
    LSTATE_UNLOCKED,
    LSTATE_MAX
};

enum lock_color {
    LOCK_GREEN,
    LOCK_YELLOW,
    LOCK_ORANGE,
    LOCK_RED,
    LOCK_COLOR_MAX
};

#define COLOR_SHMEM_TOTAL_SIZE (0x1ff)
#define COLOR_LOCK_STATE_SIZE  (0xA)
#define COLOR_LOCK_COLOR_SIZE  (0xA)
#define PUBLIC_KEY_SIZE        (0x100)
#define OS_VERSION_SIZE        (0x4)

struct verify_boot_mem_struct {
    char lock_state[COLOR_LOCK_STATE_SIZE];
    char lock_color[COLOR_LOCK_COLOR_SIZE];
    char pub_key[PUBLIC_KEY_SIZE];
    UINT32 os_version_info;
};

struct verify_boot_info_struct {
    enum lock_state lstate;
    enum lock_color color;
    char pub_key[PUBLIC_KEY_SIZE];
    UINT32 os_version;
    UINT32 patch_level;
};
/* Copy from keymaster1_util.h --end */
#endif
