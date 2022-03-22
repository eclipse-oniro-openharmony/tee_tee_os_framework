/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: elfloader usr_put_debug_char
 * Create: 2020-12
 */
#include <config.h>
#include <stdarg.h>
#include <machine/io.h>

#ifdef CONFIG_PRINTING

void putchar(char c);

void usr_put_debug_char(char c, int __attribute__((unused)) rdr_flag)
{
    putchar(c);
}

#endif
