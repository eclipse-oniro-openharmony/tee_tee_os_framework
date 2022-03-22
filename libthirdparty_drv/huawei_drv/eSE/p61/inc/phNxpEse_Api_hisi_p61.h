#ifndef _PHNXPSPILIB_API_HISI_P61_H_
#define _PHNXPSPILIB_API_HISI_P61_H_
#include "phNxpEse_Api_p61.h"
int p61_p61_factory_test(void);
int p61_scard_connect(int reader_id, void *p_atr,
    unsigned int *atr_len);
int p61_scard_disconnect(int reader_id);
int p61_scard_transmit(int reader_id, unsigned char *p_cmd,
    unsigned int cmd_len, unsigned char *p_rsp, unsigned int *rsp_len);
#endif /* _PHNXPSPILIB_API_HISI_P61_H_ */