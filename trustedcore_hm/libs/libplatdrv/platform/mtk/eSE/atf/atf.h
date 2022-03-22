#ifndef __ESE_DATA_HANDLE_H__
#define __ESE_DATA_HANDLE_H__


#define ESE_TRS_OKAY                    0x00
#define ESE_TRS_PARAM_ERR               0x01
#define ESE_TRS_DATA_ERR                0x02
#define ESE_TRS_NON_EXIST               0x09

/*
 * data: pointer to data which is used to activate or disactivate
 * data_size: the length from the start to end of the pointer
 */
int ese_transmit_data(unsigned char *data, unsigned int data_size);
#endif
