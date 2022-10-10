/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:lBRwzWIfWflpkuvEPG9oHU2mxP0IzvCfvv+i+/xvfe6PT8VRR+8jz7b5YQbqzI49/C6xSBgi
2fFxGZUs+G3nkUIkBkfRerjPcgJTCLqrXspNkFCGTLklL/GZHRhiXBwGnNKhh0MAXEOVfrQU
iukZUWJ4vidruSf/U7e9gpUyQAooCWCSaeb3aIYEst5WD1qne8GcO+5QGB0g7/S8T09ixUGT
nR+osDAHaIEfyoPHfIFAJAQLD0ohh2OwUozrcXB/#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tee operation valid implemetion
 * Author: gaobo gaobo794@huawei.com
 * Create: 2019-10-11
 */

#include "tee_operation.h"
#include <dlist.h>
#include <tee_log.h>
#include <pthread.h>
#include <errno.h>

#define LOCK_UNLOCK_OK 0
static dlist_head(g_operation_list);
static pthread_mutex_t g_operation_mutex = PTHREAD_ROBUST_MUTEX_INITIALIZER;

typedef struct {
    struct dlist_node list_node;
    TEE_OperationHandle operation;
} operation_node;

static int32_t operation_lock_ops(pthread_mutex_t *mtx)
{
    int32_t ret = pthread_mutex_lock(mtx);
    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        return pthread_mutex_consistent(mtx);

    return ret;
}

TEE_Result add_operation(TEE_OperationHandle operation)
{
    if (operation == NULL) {
        tloge("The operation is NULL\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    operation_node *valid_operation = TEE_Malloc(sizeof(*valid_operation), TEE_MALLOC_FILL_ZERO);
    if (valid_operation == NULL) {
        tloge("Malloc operation node failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    valid_operation->operation = operation;

    if (operation_lock_ops(&g_operation_mutex) != LOCK_UNLOCK_OK) {
        tloge("Lock operation mutex failed\n");
        TEE_Free(valid_operation);
        return TEE_ERROR_GENERIC;
    }
    dlist_insert_head(&(valid_operation->list_node), &g_operation_list);
    if (pthread_mutex_unlock(&g_operation_mutex) != LOCK_UNLOCK_OK) {
        tloge("Unlock operation mutex failed\n");
        dlist_delete(&(valid_operation->list_node));
        TEE_Free(valid_operation);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

void delete_operation(const TEE_OperationHandle operation)
{
    if (operation == NULL)
        return;

    operation_node *valid_operation = NULL;
    operation_node *tmp             = NULL;

    if (operation_lock_ops(&g_operation_mutex) != LOCK_UNLOCK_OK) {
        tloge("Lock operation mutex failed\n");
        return;
    }

    dlist_for_each_entry_safe(valid_operation, tmp, &g_operation_list, operation_node, list_node) {
        if (valid_operation->operation == operation) {
            dlist_delete(&(valid_operation->list_node));
            TEE_Free(valid_operation);
            valid_operation = NULL;
            break;
        }
    }
    if (pthread_mutex_unlock(&g_operation_mutex) != LOCK_UNLOCK_OK) {
        tloge("Unlock operation mutex failed\n");
        return;
    }

    return;
}

TEE_Result check_operation(const TEE_OperationHandle operation)
{
    TEE_Result ret                  = TEE_ERROR_GENERIC;
    operation_node *valid_operation = NULL;

    if (operation == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (operation_lock_ops(&g_operation_mutex) != LOCK_UNLOCK_OK) {
        tloge("Lock operation mutex failed\n");
        return TEE_ERROR_GENERIC;
    }

    dlist_for_each_entry(valid_operation, &g_operation_list, operation_node, list_node) {
        if (valid_operation->operation == operation) {
            ret = TEE_SUCCESS;
            break;
        }
    }

    if (pthread_mutex_unlock(&g_operation_mutex) != LOCK_UNLOCK_OK) {
        tloge("Unlock operation mutex failed\n");
        return TEE_ERROR_GENERIC;
    }

    return ret;
}
