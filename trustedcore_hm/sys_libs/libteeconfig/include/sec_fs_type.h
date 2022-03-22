/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: add types for sec fs
 * Create: 2021-11-23
 */
#ifndef SEC_FS_TYPES_H
#define SEC_FS_TYPES_H

enum sec_fs_meta_type {
    SEC_FS_META_UNKOWN = 0,
    SEC_FS_META,
    SEC_FS_META_EX,
    SEC_FS_META_ENCRYPTO,
    SEC_FS_META_ENCRYPTO_ENHANCE,
    SEC_FS_META_ENCRYPTO_HMAC,
};

#endif
