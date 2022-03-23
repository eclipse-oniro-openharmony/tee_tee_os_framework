#include "TA_RPMBFileOperator.h"
#include "TA_Parcel.h"
#include "tee_log.h"
#include "TA_String.h"
#include "TA_Log.h"
#include "TA_BasicLibs.h"
#define RPMB_TCIS_FILE_PREFIX ""

ta_string_t create_rpmb_file_name(const char *filename)
{
	if (filename == NULL || TA_Strlen(filename) == 0) {
		LOGE("Bad Parameters!");
	}
	ta_string_t rpmb_filename = create_string();
	TA_BOOL ret = TA_FALSE;

	if (filename != NULL) {
		do {
			if (!rpmb_filename.append_p(&rpmb_filename, RPMB_TCIS_FILE_PREFIX))
				break;
			if (!rpmb_filename.append_p(&rpmb_filename, filename))
				break;
		} while (0);
		ret = TA_TRUE;
	}

	if (ret != TA_TRUE) {
		rpmb_filename.set_p(&rpmb_filename, "");
	}
	return rpmb_filename;
}

static int do_rpmb_file_read(const char *filename, char *buf, unsigned int len)
{
	uint32_t read_size = 0;
	if (filename == NULL || buf == NULL || len == 0) {
		LOGE("Bad Parameters!");
		return TEE_FAIL;
	} else {
		int ret = TEE_RPMB_FS_Read(filename, (uint8_t *) buf, len, &read_size);
		if ((TEE_SUCCESS != ret) || (len != read_size)) {
			LOGE("TEE_RPMB_FS_Read failed, ret = %x, filename = %s, buf_len = %d, read_size = %d", ret, filename, len, read_size);
			return TEE_FAIL;
		}
		return read_size;
	}
}

static int do_rpmb_file_write(const char *filename, const char *buf, unsigned int len, int mode)
{
	if (filename == NULL || buf == NULL || len == 0) {
		LOGE("Bad Parameters!");
		return TEE_FAIL;
	}

#ifdef TA_DEBUG
	LOGE("length is %d", len);
	//printHexWithTag("do_rpmb_file_write buf", (const unsigned char *)buf, len);
#endif

	int ret = TEE_RPMB_FS_Write(filename, (uint8_t *) buf, len);
	if (ret != TEE_SUCCESS) {
		LOGE("TEE_RPMB_FS_Write failed, ret = %x, filename = %s", ret, filename);
		return TEE_FAIL;
	}
	else
	{
	    LOGD("TEE_RPMB_FS_Write successed, ret = %d, filename = %s", ret, filename);
		ret = TEE_RPMB_FS_SetAttr(filename, mode);
        if (ret != TEE_SUCCESS)
        {
            LOGE("RPMB set attr error. ret = %x, mode = %d", ret, mode);
        }
        else
        {
            LOGD("RPMB set attr %s success",filename);
        }
	}

	return len;

}

static int do_rpmb_file_remove(const char *filename)
{
	if (filename == NULL || TA_Strlen(filename) == 0) {
		LOGE("Bad Parameters!");
		return TEE_FAIL;
	}
	int ret = TEE_RPMB_FS_Rm(filename);
	if (TEE_SUCCESS != ret) {
		LOGE("TEE_RPMB_FS_Rm failed, ret = %x, filename = %s", ret, filename);
		return TEE_FAIL;
	}
    LOGD("TEE_RPMB_FS_Rm succeed,filename = %s", filename);
	return TEE_SUCCESS;
}

static int do_rpmb_file_size(const char *filename)
{
	if (NULL == filename) {
		LOGE("Bad Parameters!");
		return TEE_FAIL;
	} else {
		int ret = TEE_SUCCESS;
		struct rpmb_fs_stat stat;
		stat.size = 0;
		stat.reserved = 0;

		ret = TEE_RPMB_FS_Stat(filename, &stat);
		if (TEE_SUCCESS != ret) {
			LOGE("TEE_RPMB_FS_Stat failed, ret = %x, filename = %s", ret, filename);
			return TEE_FAIL;
		} else {

			LOGD("rpmb_file_size ok, size = %d, filename = %s", stat.size, filename);

			return stat.size;
		}
	}
}

int rpmb_file_open(const char *filename, int mode)
{
    S_VAR_NOT_USED(filename);
    S_VAR_NOT_USED(mode);

    int ret  = 0;
    return ret;
}

int rpmb_file_read(const char *filename, char *buf, unsigned int len)
{
	ta_string_t str = create_rpmb_file_name(filename);
	int ret = do_rpmb_file_read(str.get(&str), buf, len);
	delete_string(&str);
	return ret;
}

int rpmb_file_write(const char *filename, const char *buf, unsigned int len, int mode)
{
	ta_string_t str = create_rpmb_file_name(filename);

	int ret = do_rpmb_file_write(str.get(&str), buf, len, mode);

#ifdef TA_DEBUG
	LOGD("do_rpmb_file_write returned %x!", ret);
#endif

	delete_string(&str);

	return ret;
}

int rpmb_file_remove(const char *filename)
{
	ta_string_t str = create_rpmb_file_name(filename);
	int ret = do_rpmb_file_remove(str.get(&str));
	delete_string(&str);
	return ret;
}

int rpmb_file_size(const char *filename)
{
	ta_string_t str = create_rpmb_file_name(filename);
	int ret = do_rpmb_file_size(str.get(&str));
	delete_string(&str);
	return ret;
}
