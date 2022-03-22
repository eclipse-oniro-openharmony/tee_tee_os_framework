#ifndef TA_SFSFILEOPERATOR_H
#define TA_SFSFILEOPERATOR_H

bool init_sec_storage_dir(char* dir);
int ss_file_read(const char *filename, char *buf, unsigned int len);
int ss_file_size(const char *filename);
int ss_file_remove(const char *filename);
int ss_file_write(const char *filename, const char *buf, unsigned int len, int mode);

#endif
