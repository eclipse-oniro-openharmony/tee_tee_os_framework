/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Try catch macro.
 * Create: 2019-11-14
 */
#ifndef MSPC_TRY_CATCH_H
#define MSPC_TRY_CATCH_H
#include "tee_log.h"

#define mspc_tpdu_print tloge

struct mspc_mntn_info {
    uint32_t errorcode;
    uint32_t errorline;
    uint32_t logpara1;
};

#define __TRY struct mspc_mntn_info mntn_info_value = {0, 0xFFFFFFFF, 0};

/* Here write as follow, checkpatch mischeck, no use do - while loop */
#define __CATCH \
    __tabErr: \
        mspc_tpdu_print("[%s] line(%d),error(%u),para(%u)\n", __func__, mntn_info_value.errorline,\
        mntn_info_value.errorcode, mntn_info_value.logpara1);

#define set_para(para) do {\
    mntn_info_value.logpara1 = (uint32_t)(para);\
} while (0)

#define err_proc() do {\
    mntn_info_value.errorline = __LINE__;\
    goto __tabErr;\
} while (0)

#define throw(errcode) do {\
    mntn_info_value.errorcode = (errcode);\
    err_proc();\
} while (0)

#define throw_if(expr, errcode) do {\
    if (expr)\
        throw(errcode);\
} while (0)

#define throw_if_null(ptr, errcode) do {\
    if (!(ptr))\
        throw(errcode);\
} while (0)

#define throw_with_para(errcode, para) do {\
    mntn_info_value.errorcode = (errcode);\
    set_para(para);\
    err_proc();\
} while (0)

#define throw_if_with_para(expr, errcode, para) do {\
    if (expr){\
        set_para(para);\
        throw(errcode);\
    }\
} while (0)

#define ERR_CODE (mntn_info_value.errorcode)

#endif /* MSPC_TRY_CATCH_H */
