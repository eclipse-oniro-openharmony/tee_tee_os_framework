#include "TA_RPMBFileOperator.h"
#include "TA_Parcel.h"
#include "tee_log.h"
#include "TA_String.h"
#include "TA_BasicLibs.h"
#include "TA_Log.h"


#define SEC_STORAGE_ROOT_DIR_MAX_LEN 128
char SEC_STORAGE_ROOT_DIR[SEC_STORAGE_ROOT_DIR_MAX_LEN+1] = { 0 };
bool init_sec_storage_dir(const char* dir)
{
    static bool inited = false;
	if(!inited && dir != NULL)
    {
	    uint32_t dir_len = TA_Strlen(dir);
        if(dir_len > SEC_STORAGE_ROOT_DIR_MAX_LEN) {
		    return false;
		}
		else {
		    TEE_MemMove(SEC_STORAGE_ROOT_DIR, (void*)dir, dir_len);
			inited = true;
			return true;
		}
	}

    return true;

}

ta_string_t create_ss_file_name(const char *filename, const char *root_dir)
{
	ta_string_t str = create_string();
	TA_BOOL ret = TA_FALSE;
	if (filename != NULL && root_dir != NULL) {
		if (*filename == '/') {
			filename++;
		}

	    do {
		    if (!str.append_p(&str, root_dir)) break;
			if (!str.append_p(&str, filename)) break;
		} while (0);

		ret = TA_TRUE;
	}

	if (ret != TA_TRUE) {
		str.set_p(&str, "");
	}

	return str;
}

static TEE_ObjectHandle __ss_file_open(const char *filename, int mode)
{
	TEE_ObjectHandle handle = NULL;
	if (filename == NULL) {
		LOGE("Bad Parameters!");
		return NULL;
	}

	mode |= TEE_DATA_FLAG_AES256;
	if (mode & TEE_DATA_FLAG_CREATE) {
		if (TEE_SUCCESS != TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *) filename, TA_Strlen(filename), mode, TEE_HANDLE_NULL, NULL, 0,
				&handle)) {
			LOGE("!!ss file create failed:%s", filename);
			return NULL;
		}

		if (TEE_SUCCESS != TEE_TruncateObjectData(handle, 0)) {
			LOGE("ss file truncate failed:%s", filename);
			TEE_CloseObject(handle);
			return NULL;
		}
	} else {
		int ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *) filename, TA_Strlen(filename), mode, &handle);
		if (TEE_SUCCESS != ret) {
			LOGE("ss file TEE_OpenPersistentObject failed:%s", filename);
			if (TEE_ERROR_ITEM_NOT_FOUND == (unsigned int)ret)
            {
                LOGE("file: %s not exist!", filename);
            }
			return NULL;
		}
	}

	return handle;
}

static int __ss_file_close(TEE_ObjectHandle handle, int mode)
{
	if (handle == NULL) {
		LOGE("Bad Parameters!");
		return TEE_FAIL;
	}

	if (mode & TEE_DATA_FLAG_ACCESS_WRITE) {
		TEE_SyncPersistentObject(handle);
	}

	TEE_CloseObject(handle);
	return TEE_SUCCESS;
}

static int do_ss_file_read(const char *filename, char *buf, unsigned int len)
{
	if (filename == NULL || buf == NULL || len == 0) {
		LOGE("Bad Parameters!");
		return TEE_FAIL;
	} else {
		int mode = TEE_DATA_FLAG_ACCESS_READ;
		TEE_ObjectHandle handle = __ss_file_open(filename, mode);
		int ret = TEE_FAIL;
		uint32_t read_size = 0;

		if (NULL == handle) {
			LOGE("handle got from __ss_file_open is empty filename:%s", filename);
			return TEE_FAIL;
		}

		if (TEE_SUCCESS == TEE_ReadObjectData(handle, buf, len, &read_size)) {
			if (read_size == len) {
				ret = len;
			}
		}

		__ss_file_close(handle, mode);
		return ret;
	}
}

static int do_ss_file_write(const char *filename, const char *buf, unsigned int len, int mode)
{
	LOGI("ss file write into:%s", filename);
	if (NULL == filename || buf == NULL || len == 0) {
		LOGE("Bad Parameters!");
		return TEE_FAIL;
	} else {
		mode |= TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_CREATE;
		TEE_ObjectHandle handle = __ss_file_open(filename, mode);
		int ret = TEE_FAIL;

		if (NULL == handle) {
			LOGE("handle got from __ss_file_open is empty filename:%s", filename);
			return TEE_FAIL;
		}

		if (TEE_SUCCESS == TEE_WriteObjectData(handle, (void *) buf, len)) {
			ret = len;
		} else {
			LOGE("ss file write failed,  filename = %s", filename);
		}

		__ss_file_close(handle, mode);
		LOGI("ss file write success");
		return ret;
	}
}

static int do_ss_file_size(const char *filename)
{
	if (filename == NULL) {
		LOGE("Bad Parameters!");
		return TEE_FAIL;
	} else {
		int mode = TEE_DATA_FLAG_ACCESS_READ;
		TEE_ObjectHandle handle = __ss_file_open(filename, mode);
		uint32_t len = 0;
		uint32_t pos = 0;

		if (NULL == handle) {
			return TEE_FAIL;
		}

		if (TEE_SUCCESS != TEE_InfoObjectData(handle, &pos, &len)) {
			len = TEE_FAIL;
		}

		__ss_file_close(handle, mode);

		return len;
	}
}

static int do_ss_file_remove(const char *filename)
{
	int mode = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_AES256;
	TEE_ObjectHandle handle = NULL;
    TEE_Result ret = TEE_FAIL;

	if (filename == NULL) {
		LOGE("Bad Parameters!");
		return TEE_FAIL;
	}
    ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *) filename, TA_Strlen(filename), mode, (&handle));
	if (TEE_SUCCESS != ret) {
		LOGE("ss file remove failed, ret = %x,  filename = %s", ret, filename);
		return ret;
	}

	TEE_CloseAndDeletePersistentObject(handle);
	return 0;
}

int ss_file_read(const char *filename, char *buf, unsigned int len)
{
	ta_string_t str = create_ss_file_name(filename, SEC_STORAGE_ROOT_DIR);
	int ret = do_ss_file_read(str.get(&str), buf, len);
	delete_string(&str);
	return ret;
}


int ss_file_size(const char *filename)
{
	ta_string_t str = create_ss_file_name(filename, SEC_STORAGE_ROOT_DIR);
	int ret = do_ss_file_size(str.get(&str));
	delete_string(&str);
	return ret;
}

int ss_file_remove(const char *filename)
{
	ta_string_t str = create_ss_file_name(filename, SEC_STORAGE_ROOT_DIR);
	int ret = do_ss_file_remove(str.get(&str));
	delete_string(&str);
	return ret;
}

int ss_file_write(const char *filename, const char *buf, unsigned int len, int mode)
{
	ta_string_t str = create_ss_file_name(filename, SEC_STORAGE_ROOT_DIR);
	int ret = do_ss_file_write(str.get(&str), buf, len, mode);
	delete_string(&str);
	return ret;
}

