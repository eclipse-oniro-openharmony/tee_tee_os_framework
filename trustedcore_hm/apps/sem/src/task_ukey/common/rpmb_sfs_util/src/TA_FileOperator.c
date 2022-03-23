#include "TA_FileOperator.h"
#include "TA_RPMBFileOperator.h"
#include "TA_SFSFileOperator.h"
#include "TA_Parcel.h"
#include <tee_internal_api.h>
#include "tee_log.h"
#include "TA_Log.h"

TA_BOOL is_rpmb_support()
{
	if (TEE_RPMB_KEY_SUCCESS == TEE_RPMB_KEY_Status()) {
		return TA_TRUE;
	} else {
		return TA_FALSE;
	}
}

ta_file_operations_t *get_security_file_ops()
{
	return get_ss_storage_ops();
}
/*===========================================================================
FUNCTION: ta_file_operations_t* get_hw_rpmb_storage_ops()
DESCRIPTION: This function is used to get rpmb storage file operator
PARAMETER:
  void
RETURN:
  @return the pointer of file operator, NULL means error.
NOTICE:
  none.
===========================================================================*/
ta_file_operations_t *get_rpmb_storage_ops()
{
	static ta_file_operations_t ops;
	ops.read = rpmb_file_read;
	ops.write = rpmb_file_write;
	ops.filesize = rpmb_file_size;
	ops.remove = rpmb_file_remove;
	return &ops;
}

/*===========================================================================
FUNCTION: ta_file_operations_t* get_hw_ss_storage_ops()
DESCRIPTION: This function is used to get ss storage file operator
PARAMETER:
  void
RETURN:
  @return the pointer of file operator, NULL means error.
NOTICE:
  none.
===========================================================================*/
ta_file_operations_t *get_ss_storage_ops()
{
	static ta_file_operations_t ops;
	ops.read = ss_file_read;
	ops.write = ss_file_write;
	ops.filesize = ss_file_size;
	ops.remove = ss_file_remove;

	return &ops;
}

/*===========================================================================
FUNCTION: TA_BOOL check_operation(ta_file_operations_t* operation)
DESCRIPTION: This function is used to check the file operator.
PARAMETER:
  @param operation:[INPUT] The pointer of the file operator.
RETURN:
  @return TA_TRUE  (ok)
  @return TA_FALSE (error)
NOTICE:
  none.
===========================================================================*/
TA_BOOL check_operation(ta_file_operations_t *operation)
{
	if (NULL == operation) {
		LOGE("Bad Parameters!");
		return TA_FALSE;
	}

	if (NULL == operation->read || NULL ==  operation->write || NULL == operation->remove || NULL == operation->filesize) {
		LOGE("operation has empty functions!");
		return TA_FALSE;
	}

	return TA_TRUE;
}

/*===========================================================================
FUNCTION: TA_BOOL read_parcel_from_file(const char* filename, ta_file_operations_t* operation, ta_parcel_t* parcel)
DESCRIPTION: This function is used to read a file into the parcel.
PARAMETER:
  @param fileanme:[INPUT] The file path name which you want to read from.
  @param operation:[INPUT] File operator.
  @param parcel:[INOUT] The pointer of the parcel storage the file data.
RETURN:
  @return TA_TRUE  (ok)
  @return TA_FALSE (error)
NOTICE:
  none.
===========================================================================*/
TA_BOOL read_parcel_from_file(const char *filename, ta_file_operations_t *operation, ta_parcel_t *parcel)
{
	if (NULL == filename || NULL == operation || NULL == parcel || (!check_operation(operation))) {
		LOGE("Bad Parameters!");
		return TA_FALSE;
	}
	int length = operation->filesize(filename);
	TA_BOOL ret = TA_FALSE;
#ifdef TA_DEBUG
	LOGD("file size = %d, filename = %s", length, filename);
#endif
	if (length > 0) {
		char *buf = TEE_Malloc(length, 0);
		if (buf != NULL) {
			// read file
			int read_size = operation->read(filename, buf, length);
			if (read_size == length) {
				ret = parcel_write(parcel, buf, length);
#ifdef TA_DEBUG
				LOGD("parcel read from file:%d", length);
#endif
			}
		}

		TEE_Free(buf);
	} else {
		LOGE("empfy file%s", filename);
	}

	return ret;
}

/*===========================================================================
FUNCTION: TA_BOOL write_parcel_into_file(const char* filename, ta_parcel_t* parcel, ta_file_operations_t* operation)
DESCRIPTION: This function is used to save the parcel into a file.
PARAMETER:
  @param fileanme:[INPUT] The file path name which you want save into.
  @param parcel:[INPUT] The parcel you want to save.
  @param operation:[INPUT] File operator.
RETURN:
  @return TA_TRUE  (ok)
  @return TA_FALSE (error)
NOTICE:
  none.
===========================================================================*/
TA_BOOL write_parcel_into_file(const char *filename, ta_parcel_t *parcel, ta_file_operations_t *operation)
{
	if (NULL == filename || NULL == parcel || NULL == operation ||  !check_operation(operation)) {
		LOGE("Bad Parameters!");
		return TA_FALSE;
	} else {
		const char *data = get_parcel_data(parcel);
		int len = get_parcel_data_size(parcel);
		if (data != NULL && len > 0) {
#ifdef TA_DEBUG
			LOGD("be about to write data into file!");
#endif
			return (len == operation->write(filename, data, len, 0));
		}

		LOGE("parcel data error!");
		return TA_FALSE;
	}
}

TA_BOOL delete_file_by_name(const char *filename, ta_file_operations_t *operation)
{
	if (NULL == filename || !check_operation(operation)) {
		LOGE("Bad Parameters!");
		return TA_FALSE;
	} else {
		return (TEE_SUCCESS == operation->remove(filename));
	}
}

