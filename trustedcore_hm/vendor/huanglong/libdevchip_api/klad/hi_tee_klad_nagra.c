/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:
 * Author: Hisilicon hisecurity team
 * Create: 2019-06-26
 */

#include "hi_unf_klad_nagra.h"
#include "tee_klad.h"
#include "tee_klad_define.h"

hi_s32 hi_tee_klad_nagra_set_fp_key(hi_handle klad, hi_tee_klad_fp_key *key)
{
    if (key == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }
    if (sizeof(hi_klad_fp_key) != sizeof(hi_tee_klad_fp_key)) {
        print_err_hex2(sizeof(hi_klad_fp_key), sizeof(hi_tee_klad_fp_key));
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    return hi_mpi_klad_set_fp_key(klad, (hi_klad_fp_key *)key);
}

