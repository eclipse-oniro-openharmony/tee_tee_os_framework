#ifndef TA_FILEOPERATION_H
#define TA_FILEOPERATION_H

#include "TA_Parcel.h"

/*===========================================================================
 * struct of file operation
  =========================================================================== */
typedef struct {
	/* Read data from file
	 *
	 * @para filename:  The path name of the file
	 * @para buf:       The buffer used to store the content readed from the file
	 * @len:            The size count in buffer trying to read from the file
	 * @return  <0  read error
	 *          >=0 real read length
	 * */
	int (*read)(const char *filename, char *buf, unsigned int len);

	/* Write data into file
	 *
	 * @para filename:  The path name of the file
	 * @para buf:       The content which you want write into the file
	 * @len:            The size of the content
	 * @return  <0  write error
	 *          >=0 real write length
	 * */
	int (*write)(const char *filename, const char *buf, unsigned int len, int mode);

	/* Delete file
	 *
	 * @para filename:  The path name of the file
	 * @return  TEE_SUCCESS  ok
	 *          others error
	 * */
	int (*remove)(const char *filename);

	/* Get file size
	 *
	 * @para filename:  The path name of the file
	 * @return  < 0 error
	 *          >=0 The size of the file
	 * */
	int (*filesize)(const char *filename);
} ta_file_operations_t;


ta_file_operations_t *get_security_file_ops();

TA_BOOL is_rpmb_support();

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
ta_file_operations_t *get_rpmb_storage_ops();

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
ta_file_operations_t *get_ss_storage_ops();


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
TA_BOOL check_operation(ta_file_operations_t *operation);

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
TA_BOOL read_parcel_from_file(const char *filename, ta_file_operations_t *operation, ta_parcel_t *parcel);

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
TA_BOOL write_parcel_into_file(const char *filename, ta_parcel_t *parcel, ta_file_operations_t *operation);

TA_BOOL delete_file_by_name(const char *filename, ta_file_operations_t *operation);

#endif
