/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: tee shared lib implementation
 * Create: 2018-05-18
 */
#define sym(x)                       \
    asm(".global _" #x "\n"          \
        ".type _" #x ", %function\n" \
        "_" #x ":\n"                 \
        "b __" #x "\n"               \
        ".size _" #x ", .-_" #x "\n")

sym(aeabi_uidivmod);
sym(aeabi_idiv);
sym(aeabi_fadd);
sym(aeabi_fmul);
sym(aeabi_fdiv);
sym(aeabi_uidiv);
sym(aeabi_ldivmod);
sym(aeabi_uldivmod);
sym(aeabi_idivmod);
sym(aeabi_ui2d);
sym(aeabi_dmul);
sym(aeabi_dadd);
sym(aeabi_d2uiz);
sym(addvsi3);
sym(negvsi2);
sym(mulvsi3);
sym(subvsi3);
