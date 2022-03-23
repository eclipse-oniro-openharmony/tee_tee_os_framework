/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: fs oper config
 * Create: 2019-12-27
 */
#ifdef TEE_FS_OPER
#include "tee_fs_oper_config.h"
#include <string.h>
#include <securec.h>
#include <product_uuid.h>
#include "product_uuid_public.h"
#include <tee_mem_mgmt_api.h>
#include <tee_log.h>
#include "tee_fs.h"

#define MAX_FILE_COUNT  60
struct ta_file_list {
    TEE_UUID uuid;
    char file_list[MAX_FILE_COUNT][HASH_NAME_BUFF_LEN];
};

#ifdef CONFIG_LIBFUZZER
#define DEFAULT_PROFILE_NAME "default.profraw"
#endif

static const struct ta_file_list g_ta_file_table[] = {
    {
        TEE_SERVICE_FINGERPRINT,
        {
            "persist/qti_fp/bg_estimation/bg_basis.dat",
            "persist/qti_fp/bg_estimation0/bg_basis.dat",
            "persist/qti_fp/bg_estimation0/bg_metadata.dat",
            "persist/qti_fp/bg_estimation1/bg_basis.dat",
            "persist/qti_fp/bg_estimation1/bg_metadata.dat",
            "persist/qti_fp/bg_estimation2/bg_basis.dat",
            "persist/qti_fp/bg_estimation2/bg_metadata.dat",
            "persist/qti_fp/bg_estimation3/bg_basis.dat",
            "persist/qti_fp/bg_estimation3/bg_metadata.dat",
            "persist/qti_fp/bg_estimation4/bg_basis.dat",
            "persist/qti_fp/bg_estimation4/bg_metadata.dat",
            "persist/qti_fp/bg_estimation5/bg_basis.dat",
            "persist/qti_fp/bg_estimation5/bg_metadata.dat",
            "persist/qti_fp/bg_estimation6/bg_basis.dat",
            "persist/qti_fp/bg_estimation6/bg_metadata.dat",
            "persist/qti_fp/bg_estimation7/bg_basis.dat",
            "persist/qti_fp/bg_estimation7/bg_metadata.dat",
            "persist/qti_fp/newBGE/bg_estimation/bg_basis.dat",
            "persist/qti_fp/newBGE/bg_estimation0/bg_basis.dat",
            "persist/qti_fp/newBGE/bg_estimation0/bg_metadata.dat",
            "persist/qti_fp/newBGE/bg_estimation1/bg_basis.dat",
            "persist/qti_fp/newBGE/bg_estimation1/bg_metadata.dat",
            "persist/qti_fp/newBGE/bg_estimation2/bg_basis.dat",
            "persist/qti_fp/newBGE/bg_estimation2/bg_metadata.dat",
            "persist/qti_fp/newBGE/bg_estimation3/bg_basis.dat",
            "persist/qti_fp/newBGE/bg_estimation3/bg_metadata.dat",
            "persist/qti_fp/newBGE/bg_estimation4/bg_basis.dat",
            "persist/qti_fp/newBGE/bg_estimation4/bg_metadata.dat",
            "persist/qti_fp/newBGE/bg_estimation5/bg_basis.dat",
            "persist/qti_fp/newBGE/bg_estimation5/bg_metadata.dat",
            "persist/qti_fp/newBGE/bg_estimation6/bg_basis.dat",
            "persist/qti_fp/newBGE/bg_estimation6/bg_metadata.dat",
            "persist/qti_fp/newBGE/bg_estimation7/bg_basis.dat",
            "persist/qti_fp/newBGE/bg_estimation7/bg_metadata.dat",
            "persist/qti_fp/newBGE/bg_estimation_temp/bg_basis.dat",
            "persist/qti_fp/newBGE/bg_estimation_temp/bg_metadata.dat",
            "persist/qti_fp/newBGE/bg_estimation_temp_bin/bg_basis.dat",
            "persist/qti_fp/newBGE/bg_estimation_temp_bin/bg_metadata.dat",
            "persist/qti_fp/newBGE/bg_estimation",
            "persist/qti_fp/newBGE/bg_estimation0",
            "persist/qti_fp/newBGE/bg_estimation1",
            "persist/qti_fp/newBGE/bg_estimation2",
            "persist/qti_fp/newBGE/bg_estimation3",
            "persist/qti_fp/newBGE/bg_estimation4",
            "persist/qti_fp/newBGE/bg_estimation5",
            "persist/qti_fp/newBGE/bg_estimation6",
            "persist/qti_fp/newBGE/bg_estimation7",
            "persist/qti_fp/newBGE/bg_estimation_temp",
            "persist/qti_fp/newBGE/bg_estimation_temp_bin",
            "persist/qti_fp/newBGE",
            "persist/qti_fp/psf/psf_calibration.dat",
            "qti_fp/sn",
            "sec_storage_data/fp/qti_fp/qfp_config.txt",
            "sec_storage_data/log/qti_fp/dm_ai/dmai_config.txt",
            "sec_storage_data/log/qti_fp/board2.ini",
            "sec_storage_data/log/qti_fp/calib_test_config.ini",
            "sec_storage_data/log/qti_fp/sgk_erie.elf",
            "sec_storage_data/log/qti_fp/database/contents.dat.tmp",
            "sec_storage_data/log/qti_fp/database/contents.dat",
            "sec_storage_data/log/qti_fp/database",
        }
    },
    {
        TEE_SERVICE_UDFINGERPRINT,
        {
            "rfg/ud_rfg.bin",
            "cal.bvs",
        }
    },
#ifdef DEF_ENG
    {
        TEE_SERVICE_UT,
        {
            "fs_test/test1",
            "sec_storage_data/fs_test/test2",
            "fs_test/test3",
            "sec_storage_data/fs_test/test4",
            "fs_test/test5",
            "sec_storage_data/fs_test/test6",
            "fs_test/new_test3",
            "sec_storage_data/fs_test/crypto_test1",
            "sec_storage_data/fs_test/normal_test1",
            "fs_test/crypto_test2",
            "fs_test/normal_test2",
            "init.rc",
            "init.abc.rc",
        }
    },
#endif
};

static const uint32_t g_ta_file_table_num = sizeof(g_ta_file_table) / sizeof(g_ta_file_table[0]);

bool check_ta_access(const TEE_UUID *uuid)
{
#ifndef CONFIG_LIBFUZZER
    uint32_t i;
    bool find_uuid = false;

    if (uuid == NULL)
        return false;

    for (i = 0; i < g_ta_file_table_num; i++) {
        if (TEE_MemCompare(uuid, &g_ta_file_table[i].uuid, sizeof(TEE_UUID)) == 0) {
            tlogd("find uuid in list %u\n", i);
            find_uuid = true;
            break;
        }
    }

    return find_uuid;
#else
    (void)uuid;
    return true;
#endif
}

static bool file_access_check(const char *file_name, const char file_list[][HASH_NAME_BUFF_LEN], uint32_t count)
{
    char temp[HASH_NAME_BUFF_LEN] = {0};
    char *pos = temp;

    if (memcpy_s(pos, HASH_NAME_BUFF_LEN, file_name, strlen(file_name)) != EOK) {
        tloge("copy failed");
        return false;
    }

    if (strncmp(pos, "/", strlen("/")) == 0)
        pos += strlen("/");
    else if (strncmp(pos, "./", strlen("./")) == 0)
        pos += strlen("./");

    if (strncmp(pos, SFS_PARTITION_PERSISTENT, strlen(SFS_PARTITION_PERSISTENT)) == 0)
        pos += strlen(SFS_PARTITION_PERSISTENT);

    for (uint32_t i = 0; i < count; i++) {
        if (strlen(pos) != strlen(file_list[i]))
            continue;

        if (TEE_MemCompare(pos, file_list[i], strlen(file_list[i])) == 0)
            return true;
    }
    return false;
}

bool check_ta_access_file_permission(const TEE_UUID *uuid, const char *file_name)
{
    if (file_name == NULL || uuid == NULL)
        return false;

    if (strnlen(file_name, HASH_NAME_BUFF_LEN) >= HASH_NAME_BUFF_LEN)
        return false;

#ifdef CONFIG_LIBFUZZER
    if (strncmp(file_name, DEFAULT_PROFILE_NAME, strlen(DEFAULT_PROFILE_NAME)) == 0)
        return true;
#endif

    for (uint32_t i = 0; i < g_ta_file_table_num; i++) {
        if (TEE_MemCompare(uuid, &g_ta_file_table[i].uuid, sizeof(*uuid)) == 0) {
            uint32_t file_list_num = sizeof(g_ta_file_table[i].file_list) / sizeof(g_ta_file_table[i].file_list[0]);
            return file_access_check(file_name, g_ta_file_table[i].file_list, file_list_num);
        }
    }

    return false;
}
#endif
