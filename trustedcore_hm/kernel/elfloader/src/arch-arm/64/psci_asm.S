/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: elfloader psci function
 * Create: 2020-12
 */
#include <machine/assembler.h>

.text

BEGIN_FUNC(psci_func)
    smc #0
    ret
END_FUNC(psci_func)
