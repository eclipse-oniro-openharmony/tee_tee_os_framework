/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: tee version define
 * Create: 2021-05
 */
#include <tee_version.h>

#include <string.h>
#include <autoconf.h>

#ifdef DEBUG_VERSION
#define TEE_VERSION_PUBLIC                                                     \
        "TEE Version 1.0.0"                                                    \
        "\nCommit ID: "                                                        \
        TEEOS_COMMIT_ID "," HMAPPS_COMMIT_ID "\n"
#else
#define TEE_VERSION_PUBLIC                                                     \
        "TEE Version 1.0.0"                                                    \
        "\nCommit ID: "                                                        \
        TEEOS_COMMIT_ID "," HMAPPS_COMMIT_ID "\n"
#endif

bool get_tee_version(unsigned char *buf, uint32_t size)
{
    if (buf == NULL || size < sizeof(TEE_VERSION_PUBLIC))
        return false;

    if (strncpy((char *)buf, TEE_VERSION_PUBLIC, sizeof(TEE_VERSION_PUBLIC)) != 0)
        return false;

    return true;
}
