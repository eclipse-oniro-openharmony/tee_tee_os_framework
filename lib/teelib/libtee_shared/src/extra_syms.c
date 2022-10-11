/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: symbles export for use
 * Create: 2020-03-20
 */

#ifdef __aarch64__
const char *g_debug_prefix = "libtee_shared";
#else
const char *g_debug_prefix = "libtee_shared_a32";
#endif
