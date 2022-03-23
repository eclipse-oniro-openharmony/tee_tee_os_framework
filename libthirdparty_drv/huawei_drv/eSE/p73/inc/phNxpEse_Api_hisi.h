#ifndef _PHNXPSPILIB_API_HISI_H_
#define _PHNXPSPILIB_API_HISI_H_
#include "phNxpEse_Api.h"
int p73_p61_factory_test(void);
int p73_scard_connect(int reader_id, void *p_atr,
    unsigned int *atr_len);
int p73_scard_disconnect(int reader_id);
int p73_scard_transmit(int reader_id, unsigned char *p_cmd,
    unsigned int cmd_len, unsigned char *p_rsp, unsigned int *rsp_len);
int p73_EseProto7816_Reset();
phNxpEseProto7816_OsType_t GetOsMode(void);
#endif /* _PHNXPSPILIB_API_HISI_H_ */