#ifndef TA_RPMBFILEOPERATOR_H
#define TA_RPMBFILEOPERATOR_H

#include "TA_FileOperator.h"
#include "rpmb_fcntl.h"

int rpmb_file_read(const char *filename, char *buf, unsigned int len);
int rpmb_file_write(const char *filename, const char *buf, unsigned int len, int mode);
int rpmb_file_remove(const char *filename);
int rpmb_file_size(const char *filename);

#endif
