/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: storage task implementation
 * Create: 2018-05-18
 */

#include "storage_task.h"
#include <securec.h>
#include <string.h>
#include <dlist.h>
#include <tee_ext_api.h>
#include <tee_log.h>
#include <tee_init.h>
#include "tee_fs.h"
#include "tee_trusted_storage_api.h"

struct session_object {
    uint32_t session_id;
    struct dlist_node sobj_list;
    struct dlist_node session_list;
};
struct object_struct {
    TEE_ObjectHandle object;
    struct dlist_node object_list;
};
static struct dlist_node g_session_object;
static bool g_is_init = false;

struct session_identity {
    uint32_t len;
    char val[1];
};

#ifdef DEF_ENG
#define UT_CLIENT_APPNAME "/system/bin/tee_test_store"
#define UT_CLIENT_UID     (0)
#endif
#define MAX_PACKAGE_NAME_LEN 255
/*
 * @ingroup  TEE_COMMON_DATA
 *
 * The Supported CMD IDs of secure serivce STORAGE
 */
enum storage_service_cmd_id {
    STORAGE_CMD_ID_INVALID = 0x10,       /* *< Storage Task Invalid ID */
    STORAGE_CMD_ID_OPEN,                 /* *< Storage Task Open File */
    STORAGE_CMD_ID_CLOSE,                /* *< Storage Task Close File */
    STORAGE_CMD_ID_CLOSEALL,             /* *< Storage Task CLose All Files */
    STORAGE_CMD_ID_READ,                 /* *< Storage Task Read File */
    STORAGE_CMD_ID_WRITE,                /* *< Storage Task Write File */
    STORAGE_CMD_ID_SEEK,                 /* *< Storage Task Get current file position */
    STORAGE_CMD_ID_TELL,                 /* *< Storage Task Reset File Position */
    STORAGE_CMD_ID_TRUNCATE,             /* *< Storage Task Change File Size */
    STORAGE_CMD_ID_REMOVE,               /* *< Storage Task Delete File */
    STORAGE_CMD_ID_FINFO,                /* *< Storage Task Return File State */
    STORAGE_CMD_ID_FSYNC,                /* *< Storage Task Sync File to Storage */
    STORAGE_CMD_ID_UNKNOWN = 0x7FFFFFFE, /* *< Storage Task Unknown ID */
    STORAGE_CMD_ID_MAX     = 0x7FFFFFFF  /* *< Storage Task Max ID */
};

/* print all fd value in session_id's sobj_list list */
static void print_fd(uint32_t session_id)
{
#ifdef LOG_ON
    tlogd("print_fd++++\n");
    struct session_object *session_node = NULL;
    struct object_struct *object_node   = NULL;

    if (g_session_object.prev == NULL && g_session_object.next == NULL)
        return;

    dlist_for_each_entry(session_node, &g_session_object, struct session_object, session_list) {
        tlogd("session node %x\n", session_node);
        if (session_node->session_id == session_id) {
            tlogd("find sessionID\n");
            dlist_for_each_entry(object_node, &session_node->sobj_list, struct object_struct, object_list) {
                tlogd("fd=%u\n", (uint32_t)object_node->object->dataPtr);
            }
        }
    }
    tlogd("print_fd----\n");
#else
    (void)session_id;
#endif
}

/* insert object to session_id's sobj_list, if session_id not exit, insert session_id to g_session_object */
static TEE_Result insert_object(uint32_t session_id, const TEE_ObjectHandle *object)
{
    if (object == NULL || (*object) == NULL) {
        tloge("bad parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 1. init  g_session_object */
    if (g_is_init == false) {
        dlist_init(&g_session_object);
        g_is_init = true;
    }

    /* 2. malloc a new object node, and init */
    struct object_struct *object_node = (struct object_struct *)NULL;
    if ((object_node = (struct object_struct *)TEE_Malloc(sizeof(struct object_struct), 0)) == NULL) {
        tloge("malloc object_node falied\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    object_node->object = *object;
    dlist_init(&object_node->object_list);

    /* 3. find session_id is exist in g_session_object or not */
    struct session_object *session_node = (struct session_object *)NULL;
    bool is_found                       = false;
    dlist_for_each_entry(session_node, &g_session_object, struct session_object, session_list) {
        if (session_node->session_id == session_id) {
            is_found = true;
            break;
        }
    }
    /* 4. if session_id not exist, create it, and insert to g_session_object */
    if (!is_found) {
        if ((session_node = (struct session_object *)TEE_Malloc(sizeof(struct session_object), 0)) == NULL) {
            tloge("malloc session_node failed\n");
            TEE_Free((void *)object_node);
            return TEE_ERROR_OUT_OF_MEMORY;
        } else {
            /* this section SHOULD in TA_OpenSessionEntryPoint, but session_id not in params */
            session_node->session_id = session_id;
            dlist_init(&session_node->session_list);
            dlist_init(&session_node->sobj_list);
            dlist_insert_head(&session_node->session_list, &g_session_object);
        }
    }

    /* 5. insert object node to session_list */
    dlist_insert_head(&object_node->object_list, &session_node->sobj_list);

    print_fd(session_id);
    return TEE_SUCCESS;
}

/* search fd in session_id's sobj_list */
static TEE_ObjectHandle search_object(uint32_t session_id, uint32_t fd)
{
    struct session_object *session_node = (struct session_object *)NULL;
    struct object_struct *object_node   = (struct object_struct *)NULL;
    bool is_found                       = false;

    if (g_session_object.prev == NULL && g_session_object.next == NULL)
        return (TEE_ObjectHandle)NULL;

    dlist_for_each_entry(session_node, &g_session_object, struct session_object, session_list) {
        if (session_node->session_id == session_id) {
            dlist_for_each_entry(object_node, &session_node->sobj_list, struct object_struct, object_list) {
                if ((uintptr_t)object_node->object->dataPtr == fd) {
                    is_found = true;
                    break;
                }
            }
        }
    }

    if (!is_found || object_node == NULL) {
        tloge("not find object\n");
        return (TEE_ObjectHandle)NULL;
    }

    return object_node->object;
}

/* delete object in session_id's sobj_list */
static void delete_object(uint32_t session_id, TEE_ObjectHandle object)
{
    struct session_object *session_node = (struct session_object *)NULL;
    struct object_struct *p_object_node = (struct object_struct *)NULL;

    if (object == NULL) {
        tloge("bad parameters\n");
        return;
    }

    if (g_session_object.prev == NULL && g_session_object.next == NULL)
        return;

    dlist_for_each_entry(session_node, &g_session_object, struct session_object, session_list) {
        if (session_node->session_id == session_id) {
            dlist_for_each_entry(p_object_node, &session_node->sobj_list, struct object_struct, object_list) {
                if (p_object_node->object == object) {
                    dlist_delete(&p_object_node->object_list);
                    TEE_Free((void *)p_object_node);
                    break;
                }
            }
        }
    }
}

/* close unclosed object, delete object list, delete session list */
static void delete_session(uint32_t session_id)
{
    /* this section SHOULD in TA_CloseSessionEntryPoint, but session_id not in params */
    struct session_object *session_node = NULL;
    struct object_struct *p_object_node = NULL;
    struct object_struct *q_object_node = NULL;

    print_fd(session_id);

    if (g_session_object.prev == NULL && g_session_object.next == NULL)
        return;

    dlist_for_each_entry(session_node, &g_session_object, struct session_object, session_list) {
        if (session_node->session_id == session_id) {
            for (p_object_node = DLIST_ENTRY(session_node->sobj_list.next, struct object_struct, object_list),
                q_object_node  = DLIST_ENTRY(p_object_node->object_list.next, struct object_struct, object_list);
                 &p_object_node->object_list != &session_node->sobj_list;
                 p_object_node = q_object_node, q_object_node = DLIST_ENTRY(q_object_node->object_list.next,
                                                                               struct object_struct, object_list)) {
                TEE_CloseObject(p_object_node->object);
                dlist_delete(&p_object_node->object_list);
                TEE_Free((void *)p_object_node);
            }
            dlist_delete(&session_node->session_list);
            TEE_Free((void *)session_node);
            break;
        }
    }
}

#define SHA_BUFF_HIGH_MASK    0xf0
#define SHA_BUFF_LOW_MASK     0x0f
#define HALF_BYTE_OFFSET      4U
#define DOUBLE(x)             ((x) * 2)
#define IS_SINGLE_DIGIT(x)    ((x) >= 0 && (x) <= 9)
#define IS_HEX_NUM(x)         ((x) >= 10 && (x) <= 15)
#define MIN_TWO_DIGIT         10
// CAUTION: the size of "dest" MUST be larger than HASH_LEN*2
static TEE_Result str_tran(const unsigned char *sha_buff, char *dest)
{
    int32_t i;

    if (sha_buff == NULL || dest == NULL) {
        tloge("bad parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    for (i = 0; i < HASH_LEN; i++) {
        int8_t hb = (sha_buff[i] & SHA_BUFF_HIGH_MASK) >> HALF_BYTE_OFFSET;
        if (IS_SINGLE_DIGIT(hb))
            hb += '0';
        else if (IS_HEX_NUM(hb))
            hb = ((hb - MIN_TWO_DIGIT) + 'A');
        else
            return TEE_ERROR_GENERIC;

        int8_t lb = sha_buff[i] & SHA_BUFF_LOW_MASK;
        if (IS_SINGLE_DIGIT(lb))
            lb += '0';
        else // lb must be between 10 and 15
            lb = (lb - MIN_TWO_DIGIT) + 'A';

        dest[DOUBLE(i)]     = hb;
        dest[DOUBLE(i) + 1] = lb;
    }

    dest[DOUBLE(HASH_LEN)] = '\0';

    return TEE_SUCCESS;
}

static TEE_Result do_hash(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len)
{
    TEE_OperationHandle hash_ops = NULL;
    TEE_Result ret;

    ret = TEE_AllocateOperation(&hash_ops, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (ret != TEE_SUCCESS) {
        tloge("alloc operation failed, errno = 0x%x\n", ret);
        return ret;
    }

    ret = TEE_DigestUpdate(hash_ops, in, in_len);
    if (ret != TEE_SUCCESS) {
        tloge("digest update failed, errno = 0x%x\n", ret);
        TEE_FreeOperation(hash_ops);
        return ret;
    }

    ret = TEE_DigestDoFinal(hash_ops, NULL, 0, out, (size_t *)out_len);
    TEE_FreeOperation(hash_ops);
    if (ret != TEE_SUCCESS)
        tloge("digest dofinal failed, errno = 0x%x\n", ret);
    return ret;
}

/* Find the last '/', to support dir create and mutiple sec_storage partition */
static uint32_t get_path_lable(const char *src, uint32_t src_len)
{
    uint32_t path_lable = 0;
    uint32_t i;
    for (i = src_len - 1; i > 0; i--) {
        if (src[i] == '/') {
            path_lable = i;
            break;
        }
    }
    return path_lable;
}

static TEE_Result check_encrypt_filename(const char *src, uint32_t src_len, const struct session_identity *identity,
                                         char *dest, uint32_t dest_len)
{
    uint32_t path_lable;
    bool parm_check_fail = (src == NULL) || (src_len >= HASH_NAME_BUFF_LEN) || (strnlen(src, src_len) != src_len) ||
                           (dest == NULL) || (identity == NULL) || (identity->len >= MAX_PACKAGE_NAME_LEN) ||
                           (dest_len < HASH_NAME_BUFF_LEN);
    if (parm_check_fail)
        return TEE_ERROR_BAD_PARAMETERS;

    path_lable = get_path_lable(src, src_len);
    if ((src_len - 1) == path_lable || path_lable >= DIR_LEN || path_lable == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    if (src != strstr(src, SFS_PARTITION_TRANSIENT))
        return TEE_ERROR_BAD_PARAMETERS;
    return TEE_SUCCESS;
}

static TEE_Result encrypt_filename(const char *src, uint32_t src_len, const struct session_identity *identity,
                                   char *dest, uint32_t dest_len)
{
    uint8_t tmp_buff[HASH_LEN] = {0};
    uint32_t tmp_buff_len = sizeof(tmp_buff);
    TEE_Result ret;
    uint8_t *mix_buff = NULL;
    uint32_t mix_buff_len;
    uint32_t path_lable;
    errno_t rc;

    ret = check_encrypt_filename(src, src_len, identity, dest, dest_len);
    if (ret != TEE_SUCCESS)
        return ret;

    /* mix_buff_len is src len and identify->val len, this use zhe max size of src(HASH_NAME_BUFF_LEN) */
    mix_buff_len = HASH_NAME_BUFF_LEN + identity->len;
    mix_buff = TEE_Malloc(mix_buff_len, 0);
    if (mix_buff == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    /* use src and identify->val to generate file HASH name(len is 2*HASH_LEN),
     * identify->val used to isolate CAs storage.
     */
    rc = memmove_s(mix_buff, mix_buff_len, (void *)src, src_len);
    if (rc != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto error;
    }
    rc = memmove_s(mix_buff + src_len, mix_buff_len - src_len, identity->val, identity->len);
    if (rc != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto error;
    }

    path_lable = get_path_lable(src, src_len);
    ret = do_hash(mix_buff + path_lable + 1, mix_buff_len - (path_lable + 1), tmp_buff, &tmp_buff_len);
    if (ret != TEE_SUCCESS)
        goto error;

    ret = str_tran(tmp_buff, dest + path_lable + 1);
    if (ret != TEE_SUCCESS)
        goto error;

    rc = memmove_s(dest, dest_len, (void *)mix_buff, path_lable + 1);
    if (rc != EOK)
        ret = TEE_ERROR_SECURITY;
    tlogd("src=%s, dest=%s\n", src, dest);

error:
    TEE_Free((void *)mix_buff);
    return ret;
}

#define OLD_CERT_SIZE  99
static TEE_Result check_storage_fopen(uint32_t param_types, const struct session_identity *identity)
{
    if (identity == NULL) {
        tloge("bad parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
                          TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((identity->len == 0) || (identity->len > OLD_CERT_SIZE)) {
        tloge("Bad expected identity length\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static struct session_identity *build_identity(void)
{
    char *old_apk_name = "com.huawei.hidisk";
    struct session_identity *new_identity = TEE_Malloc(sizeof(struct session_identity) + OLD_CERT_SIZE, 0);
    if (new_identity == NULL)
        return NULL;
    new_identity->len = strlen(old_apk_name);
    if (memcpy_s((void *)new_identity->val, OLD_CERT_SIZE, old_apk_name, strlen(old_apk_name)) != EOK) {
        TEE_Free((void *)new_identity);
        return NULL;
    }
    return new_identity;
}
static void free_identity(const struct session_identity *identity)
{
    TEE_Free((void *)identity);
}

static TEE_Result fopen_internal(uint32_t session_id, const uint8_t *object_id, size_t object_id_len,
                                 uint32_t in_flags, uint32_t *nfd)
{
    TEE_ObjectHandle object = NULL;
    uint32_t flags = in_flags & (~TEE_DATA_FLAG_AES256);
    TEE_Result ret;
    if (flags & TEE_DATA_FLAG_EXCLUSIVE)
        ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, object_id, object_id_len,
            flags, TEE_HANDLE_NULL, NULL, 0, &object);
    else if (flags & TEE_DATA_FLAG_CREATE)
        ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, object_id, object_id_len,
            flags & (~TEE_DATA_FLAG_CREATE), TEE_HANDLE_NULL, NULL, 0, &object);
    else
        ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, object_id, object_id_len, flags, &object);

    if (ret == TEE_SUCCESS) {
        (void)insert_object(session_id, &object);
        *nfd = (uint32_t)(uintptr_t)object->dataPtr;
    }
    return ret;
}

/* define for com.huawei.hidisk compatibility process */
#define COMPAT_CA_NAME "com.huawei.filemanager"
#define PARAM_1        1
#define PARAM_2        2
#define PARAM_3        3
static TEE_Result storage_task_fopen(uint32_t session_id, uint32_t param_types, TEE_Param params[PARAM_COUNT],
                                     const struct session_identity *identity)
{
    tlogd("++storage_task_fopen\n");
    TEE_Result ret;
    ret = check_storage_fopen(param_types, identity);
    if (ret != TEE_SUCCESS)
        return ret;

    char object_id[HASH_NAME_BUFF_LEN];
    size_t object_id_len;
    char *infile = (char *)(params[0].memref.buffer);
    uint32_t infile_len = params[0].memref.size;
    uint32_t nfd = 0;

    ret = encrypt_filename(infile, infile_len, identity, object_id, sizeof(object_id));
    if (ret != TEE_SUCCESS) {
        tloge("encrypt file name failed, errno = 0x%x\n", ret);
        return ret;
    }
    object_id_len = strlen(object_id);
    ret = fopen_internal(session_id, (uint8_t *)object_id, object_id_len, params[PARAM_1].value.a, &nfd);
    if (ret == TEE_SUCCESS) {
        params[PARAM_2].value.a = nfd;
        tlogd("--storage_task_fopen\n");
        return TEE_SUCCESS;
    }

    if ((strlen(COMPAT_CA_NAME) != (strlen(identity->val))) ||
        (memcmp(COMPAT_CA_NAME, identity->val, strlen(COMPAT_CA_NAME)) != 0))
        return TEE_ERROR_BAD_PARAMETERS;

    tlogd("for compatibility+++\n");
    /* for com.huawei.hidisk compatibility */
    struct session_identity *new_identity = build_identity();
    if (new_identity == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    ret = encrypt_filename(infile, infile_len, new_identity, object_id, sizeof(object_id));
    free_identity(new_identity);
    new_identity = NULL;
    if (ret != TEE_SUCCESS) {
        tloge("encrypt file name failed, errno = 0x%x\n", ret);
        return ret;
    }
    object_id_len = strlen(object_id);
    ret = fopen_internal(session_id, (uint8_t *)object_id, object_id_len, params[PARAM_1].value.a, &nfd);
    if (ret == TEE_SUCCESS)
        params[PARAM_2].value.a = nfd;

    tlogd("--storage_task_fopen\n");
    return ret;
}

static TEE_Result storage_task_fclose(uint32_t session_id, uint32_t param_types, const TEE_Param params[PARAM_COUNT])
{
    tlogd("++storage_task_fclose\n");
    uint32_t fd             = params[0].value.a;
    TEE_ObjectHandle object = NULL;

    if (!check_param_type(param_types, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((object = search_object(session_id, fd)) == NULL) {
        tloge("The fd is not exist\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    delete_object(session_id, object);
    TEE_CloseObject(object);
    tlogd("--storage_task_fclose\n");
    return TEE_SUCCESS;
}

static TEE_Result storage_task_fcloseall(uint32_t session_id)
{
    tlogd("++storage_task_fcloseall\n");
    delete_session(session_id);
    tlogd("--storage_task_fcloseall\n");
    return TEE_SUCCESS;
}

static TEE_Result storage_task_fread(uint32_t session_id, uint32_t param_types, TEE_Param params[PARAM_COUNT])
{
    tlogd("++storage_task_fread\n");
    TEE_Result ret;
    uint8_t *buffer = NULL;
    size_t size;
    size_t read_size        = 0;
    TEE_ObjectHandle object = NULL;

    if (!check_param_type(param_types, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                          TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t fd = params[0].value.a;
    buffer = (uint8_t *)params[1].memref.buffer;
    size   = params[1].memref.size;

    if ((object = search_object(session_id, fd)) == NULL) {
        tloge("The fd is not exist\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Then, call TEE Storage API to read file */
    ret = TEE_ReadObjectData(object, buffer, size, (uint32_t *)(&read_size));
    if (ret == TEE_SUCCESS)
        params[2].value.a = read_size;
    else
        params[2].value.a = 0;

    tlogd("--storage_task_fread\n");
    return ret;
}

static TEE_Result storage_task_fwrite(uint32_t session_id, uint32_t param_types, TEE_Param params[PARAM_COUNT])
{
    tlogd("++storage_task_fwrite\n");
    TEE_Result ret;
    uint8_t *buffer = NULL;
    size_t size, old_size, new_size;
    TEE_ObjectHandle object = NULL;

    if (!check_param_type(param_types, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                          TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t fd = params[0].value.a;
    buffer = (uint8_t *)params[1].memref.buffer;
    size   = params[1].memref.size;

    if ((object = search_object(session_id, fd)) == NULL) {
        tloge("The fd is not exist\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (object->ObjectInfo == NULL) {
        tloge("the object info is NULL!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Then, call TEE Storage API to write file */
    old_size          = object->ObjectInfo->dataSize;
    ret               = TEE_WriteObjectData(object, buffer, size);
    new_size          = object->ObjectInfo->dataSize;
    params[2].value.a = new_size - old_size;

    tlogd("--storage_task_fwrite\n");
    return ret;
}

static TEE_Result storage_task_fseek(uint32_t session_id, uint32_t param_types, const TEE_Param params[PARAM_COUNT])
{
    TEE_Result ret;
    uint32_t fd = -1;
    int32_t offset;
    TEE_ObjectHandle object = NULL;
    TEE_Whence whence;

    if (!check_param_type(param_types, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    fd     = params[0].value.a;
    offset = (int32_t)(params[0].value.b);
    whence = (TEE_Whence)(params[1].value.a);

    if ((object = search_object(session_id, fd)) == NULL) {
        tloge("The fd is not exist\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* Then, call TEE Storage API to write file */
    ret = TEE_SeekObjectData(object, offset, whence);

    return ret;
}

static TEE_Result storage_task_finfo(uint32_t session_id, uint32_t param_types, TEE_Param params[PARAM_COUNT])
{
    TEE_Result ret;
    uint32_t fd = -1;
    size_t pos = 0;
    size_t len = 0;
    TEE_ObjectHandle object = NULL;

    if (!check_param_type(param_types, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    fd = params[0].value.a;

    if ((object = search_object(session_id, fd)) == NULL) {
        tloge("The fd is not exist, session_id:%x, fd:%x\n", session_id, fd);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Then, call TEE Storage API to get file info */
    ret = TEE_InfoObjectData(object, (void *)&pos, (void *)&len);
    if (ret == TEE_SUCCESS) {
        params[1].value.a = pos;
        params[1].value.b = len;
    }

    return ret;
}

static TEE_Result storage_task_fclose_delete(uint32_t session_id, uint32_t param_types,
    const TEE_Param params[PARAM_COUNT])
{
    tlogd("++storage_task_remove\n");
    uint32_t fd             = params[0].value.a;
    TEE_ObjectHandle object = NULL;

    if (!check_param_type(param_types, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((object = search_object(session_id, fd)) == NULL) {
        tloge("The fd is not exist\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    delete_object(session_id, object);
    TEE_CloseAndDeletePersistentObject(object);
    tlogd("--storage_task_remove\n");
    return TEE_SUCCESS;
}

static TEE_Result storage_task_fsync(uint32_t session_id, uint32_t param_types, const TEE_Param params[TEE_PARAMS_NUM])
{
    uint32_t fd             = params[0].value.a;
    TEE_ObjectHandle object = NULL;

    if (!check_param_type(param_types, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((object = search_object(session_id, fd)) == NULL) {
        tloge("The fd is not exist\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SyncPersistentObject(object);
}

__attribute__((visibility("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
    TEE_Param params[PARAM_COUNT], void **sessionContext)
{
    if (!(TEE_PARAM_TYPE_GET(param_types, PARAM_3) == TEE_PARAM_TYPE_MEMREF_INPUT ||
          TEE_PARAM_TYPE_GET(param_types, PARAM_3) == TEE_PARAM_TYPE_MEMREF_OUTPUT ||
          TEE_PARAM_TYPE_GET(param_types, PARAM_3) == TEE_PARAM_TYPE_MEMREF_INOUT))
        return TEE_ERROR_BAD_PARAMETERS;

    struct session_identity *identity = (struct session_identity *)NULL;
    uint32_t pkg_name_len             = params[PARAM_3].memref.size;

    *sessionContext = NULL;

    if (pkg_name_len == 0 || pkg_name_len >= MAX_PACKAGE_NAME_LEN) {
        tloge("Invalid size of package name len login info!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    identity = (struct session_identity *)TEE_Malloc(sizeof(struct session_identity) + pkg_name_len, 0);
    if (identity == NULL) {
        tloge("Failed to allocate mem for session_identify\n");
        return TEE_ERROR_GENERIC;
    }

    identity->len = pkg_name_len;
    if (memmove_s((void *)(identity->val), identity->len,
        params[PARAM_3].memref.buffer, identity->len) != EOK) {
        TEE_Free((void *)identity);
        return TEE_ERROR_SECURITY;
    }

    /* set session context */
    *sessionContext = (void *)identity;
    return TEE_SUCCESS;
}

__attribute__((visibility("default"))) void TA_CloseSessionEntryPoint(void *session_context)
{
    if (session_context)
        TEE_Free((void *)session_context);
}

__attribute__((visibility("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t cmd_id,
    uint32_t param_types, TEE_Param params[PARAM_COUNT])
{
    TEE_Result ret;
    uint32_t session_id               = get_current_session_id();
    struct session_identity *identity = (struct session_identity *)session_context;

    switch (cmd_id) {
    case (uint32_t)STORAGE_CMD_ID_OPEN:
        ret = storage_task_fopen(session_id, param_types, params, identity);
        break;
    case (uint32_t)STORAGE_CMD_ID_CLOSE:
        ret = storage_task_fclose(session_id, param_types, params);
        break;
    case (uint32_t)STORAGE_CMD_ID_READ:
        ret = storage_task_fread(session_id, param_types, params);
        break;
    case (uint32_t)STORAGE_CMD_ID_WRITE:
        ret = storage_task_fwrite(session_id, param_types, params);
        break;
    case (uint32_t)STORAGE_CMD_ID_CLOSEALL:
        ret = storage_task_fcloseall(session_id);
        break;
    case (uint32_t)STORAGE_CMD_ID_SEEK:
        ret = storage_task_fseek(session_id, param_types, params);
        break;
    case (uint32_t)STORAGE_CMD_ID_REMOVE:
        ret = storage_task_fclose_delete(session_id, param_types, params);
        break;
    case (uint32_t)STORAGE_CMD_ID_FINFO:
        ret = storage_task_finfo(session_id, param_types, params);
        break;
    case (uint32_t)STORAGE_CMD_ID_FSYNC:
        ret = storage_task_fsync(session_id, param_types, params);
        break;
    default:
        ret = TEE_ERROR_GENERIC;
        break;
    }

    return ret;
}

__attribute__((visibility("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    char *package_name = "com.huawei.filemanager";
    char *modulus =
        "B8D5BDCA4257217F4D608758B5C459181A547A9EF110C952D258AD990145F3DF48162BDC814A544C32E2A2C20482DFB99714C8D405CBE"
        "34A2D82A9F054CDF02385F8586F5DBBB17BC8D80E655A971B63B8AC302A592F81F273ED692456FED2F28B51708309508E95B0B1175883"
        "A18507D1EAAC9B506C83E063DBD53D2E228B59CAD7480880D75E2CFC633BDDB3076D59526CC9F8AF1BE407F8AE7A659968EEEAB3BB10D"
        "3C83AF1C03A90ADA9354531BC176DFE4176623C64912C62CCD8CA71B27815FCE3BF6E231695162239FEB04BB423538B70ABCA289BB1FF"
        "275C43ABCEE4C8919F135AE2CF1F82D9EE0DA8EE97ADBF99016EDB1E736370636B085798ECCB7AE0AFD12D20F43AF6CBAFD9A871B0EFA"
        "A93D186EC8F43561F34F2F04BCAEEF906A49F986C03C96E69FE5C1DDCB357C37BE9A71F9B7D7CD1D8772FFF7ABD0B3FE9765C601F1FA9"
        "4E0B43D8EC241D69630CBF4CA181546EDCC4E3F63D7DC8F1F47822B067064AF72CD16D4867F84B4A11919DF58D447E76900C61993992D"
        "5613D";
    char *exponent = "10001";

#ifdef DEF_ENG
    TEE_Result ret = AddCaller_CA_exec(UT_CLIENT_APPNAME, UT_CLIENT_UID);
    if (ret != TEE_SUCCESS)
        return ret;
#endif

    return AddCaller_CA_apk(package_name, modulus, exponent);
}

__attribute__((visibility("default"))) void TA_DestroyEntryPoint(void)
{
    tlogd("storage_task_destroy\n");
}

