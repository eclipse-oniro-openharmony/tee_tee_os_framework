#ifndef __P61_SE_H
#define __P61_SE_H
#endif
#ifndef SE_SUPPORT_SN110
int p61_p61_factory_test(void);
int p61_scard_connect(int reader_id, void *p_atr, unsigned int *atr_len);

int p61_scard_disconnect(int reader_id);

int p61_scard_transmit(int reader_id , unsigned char *p_cmd , unsigned int cmd_len ,
           unsigned char *p_rsp , unsigned int *rsp_len);
#endif
#ifdef SE_SUPPORT_SN110
int p61_gpio_power(int control);

void p61_gpio_control(int gpio, int control);
#endif
int scard_get_ese_type(void);