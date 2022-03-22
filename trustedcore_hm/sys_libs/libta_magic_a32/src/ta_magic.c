/* Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: add a magic section for ta elf to make it loaded by tarunner
 * Create: 2019-09-17
 */

__attribute__((section (".magic"), visibility("default"))) const char g_magic_string[] = { "Dynamically linked." };

