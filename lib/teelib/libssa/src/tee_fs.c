/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: tui fs implementation
 * Author: Dizhe Mao maodizhe1@huawei.com
 * Create: 2018-05-18
 */
#include "tee_defines.h"
#include "tee_fs.h"
#include "tee_log.h"
#include "securec.h"
#include "string.h"
#include "tee_ss_agent_api.h"
#include "mem_ops_ext.h"
#include "tee_inner_uuid.h"

#ifndef FILE_NAME_MAX_BUF
#define FILE_NAME_MAX_BUF 256
#endif

TEE_Result check_file_name(const char *name)
{
    if (name == NULL) {
        tloge("Input parameter is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (strnlen(name, HASH_NAME_BUFF_LEN) == HASH_NAME_BUFF_LEN) {
        tloge("File name is too long\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /*
     * If TA or storage task pass sec_storage/../data/xxx, this will write to data dir.
     * file name must not have ".." str, to against sec_storage/../data attack
     */
    if (strstr(name, FILE_NAME_INVALID_STR)) {
        tloge("Invalid file name(file name contain ..) :%s\n", name);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

#define FILE_DIR_FLAG     "/"
#define CUR_FILE_DIR_FLAG "./"
#define USERID0_DIR_FLAG  "0/"
#define MULTI_USERID      10
static TEE_Result check_name_by_storageid_for_ce(const char *obj_id, char *pos)
{
    if (pos == NULL) {
        tloge("invalid paramerers");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *ptr = NULL;

    if (strstr(pos, FILE_DIR_FLAG) == NULL) {
        tloge("For CE storage, the file name must meet the rule 'userid/xxx'");
        return TEE_ERROR_STORAGE_PATH_WRONG;
    }

    if (strncmp(pos, USERID0_DIR_FLAG, strlen(USERID0_DIR_FLAG)) != 0 || strlen(pos) <= strlen(USERID0_DIR_FLAG)) {
        (void)strtok_r(pos, FILE_DIR_FLAG, &ptr);
        if (strlen(ptr) == 0 || !(atoi(pos) >= MULTI_USERID)) {
            tloge("The file name does not match the CE storage ID, obj_id:%s", obj_id);
            return TEE_ERROR_STORAGE_PATH_WRONG;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result check_name_by_storageid(const char *obj_id, uint32_t obj_len, uint32_t storage_id)
{
    char temp[FILE_NAME_MAX_BUF] = { '\0' };
    char *pos                    = temp;
    int rc;

    if (obj_id == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    rc = memcpy_s(pos, FILE_NAME_MAX_BUF, obj_id, obj_len);
    if (rc != EOK) {
        tloge("copy failed");
        return TEE_ERROR_SECURITY;
    }

    if (strncmp(pos, FILE_DIR_FLAG, strlen(FILE_DIR_FLAG)) == 0)
        pos += strlen(FILE_DIR_FLAG);
    else if (strncmp(pos, CUR_FILE_DIR_FLAG, strlen(CUR_FILE_DIR_FLAG)) == 0)
        pos += strlen(CUR_FILE_DIR_FLAG);

    if (storage_id == TEE_OBJECT_STORAGE_PRIVATE) {
        if (pos == strstr(pos, SFS_PERSO) || pos == strstr(pos, SFS_PRIVATE) ||
            pos == strstr(pos, SFS_PARTITION_TRANSIENT_PERSO) || pos == strstr(pos, SFS_PARTITION_TRANSIENT_PRIVATE)) {
            tloge("The file name does not match the storage ID, obj_id:%s", pos);
            return TEE_ERROR_STORAGE_PATH_WRONG;
        }
    } else if (storage_id == TEE_OBJECT_STORAGE_CE) {
        return check_name_by_storageid_for_ce(obj_id, pos);
    }

    return TEE_SUCCESS;
}
