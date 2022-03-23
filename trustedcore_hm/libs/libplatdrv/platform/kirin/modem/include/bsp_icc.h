/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2012-2015. All rights reserved.
 * foss@huawei.com
 *
 */
#ifndef __BSP_ICC_H__
#define __BSP_ICC_H__

#ifdef __cplusplus /* __cplusplus */
extern "C"
{
#endif /* __cplusplus */
#include <osl_balong.h>

#define ICC_CHAN_NUM_MAX      (32)

#define ICC_BUSY              (0x03 | NOTIFY_STOP_MASK)
#define ICC_OK                (0)
#define ICC_ERR               (-1)

#ifndef __ASSEMBLY__

/* CPU ID ���� */
enum CPU_ID
{
	ICC_CPU_MIN = 0,
	ICC_CPU_APP = 0,
	ICC_CPU_MODEM = 1,
	ICC_CPU_MAX
};

/* �����붨�� */
enum ICC_ERR_NO {
	ICC_CHN_INIT_FAIL = (0x80000000 + (0 << 16)),
	ICC_MALLOC_CHANNEL_FAIL,
	ICC_MALLOC_VECTOR_FAIL,
	ICC_CREATE_TASK_FAIL,
	ICC_DEBUG_INIT_FAIL,
	ICC_CREATE_SEM_FAIL,
	ICC_REGISTER_INT_FAIL,
	ICC_INVALID_PARA,
	ICC_WAIT_SEM_TIMEOUT,
	ICC_SEND_ERR,
	ICC_RECV_ERR,
	ICC_REGISTER_CB_FAIL,
	ICC_REGISTER_DPM_FAIL,
	ICC_MALLOC_MEM_FAIL,
	ICC_NULL_PTR,
	ICC_INIT_ADDR_TOO_BIG,
	ICC_INIT_SKIP

};

/* ͨ��id���� */
enum ICC_S_CHN_ID {
	ICC_CHN_ACORE_CCORE_MIN = 17, /* modem reset : ͨ����ʼ��־ */
	ICC_CHN_SEC_IFC  = 17,        /* ����IPC������ֱ�ӻص�����������ȫOS��ccore��������ͨ�� */
	ICC_CHN_SEC_VSIM = 18,        /* ˽��IPC������ֱ�ӻص������������ͨ��ȫOS��ccore����ͨ�� */
	ICC_CHN_SEC_RFILE = 19,       /* RFILE��ȫOS��ccore����ͨ�� */

	ICC_CHN_ID_MAX
};

/* ˵��: ���ջص�����ID,��ͨ�����������, "ͨ������_xxx=0��ͨ������_RECV_FUNC_ID_MAX֮�� */
enum ICC_S_RECV_FUNC_ID {
	IFC_RECV_FUNC_MODULE_VERIFY = 0,
	IFC_RECV_FUNC_TRNG_SEED_GET = 1,

	/* ��Ҫ������ͨ���϶�����ͨ��,���ڸ�ע����֮ǰ���� */
	IFC_RECV_FUNC_ID_MAX,

	VSIM_RECV_FUNC_SUB0 = 0,

	/* ��Ҫ������ͨ���϶�����ͨ��,���ڸ�ע����֮ǰ���� */
	VSIM_RECV_FUNC_ID_MAX,

	RFILE_RECV_FUNC_SUB0 = 0,

	/* ��Ҫ������ͨ���϶�����ͨ��,���ڸ�ע����֮ǰ���� */
	RFILE_RECV_FUNC_ID_MAX

};
/* ö�ٶ���end */

struct icc_channel_packet {
	unsigned int channel_id;               /* �����ݰ���¼��ͨ��id */
	unsigned int len;                      /* �����ݰ����� */
	unsigned int src_cpu_id;               /* �����ݰ��ķ����ߵ�cpu id */
	unsigned int seq_num;                  /* �����ݰ������к�: ͬ�����͵ĵȴ�������Ҫ�õ� */
	unsigned int need_responsed: 1;        /* �����ݰ��Ƿ���Ҫ�ظ����Է��˱�ʶbitλ */
	unsigned int is_responsed: 1;          /* �����ݰ��Ƿ��ǶԷ��˻ظ������ı�ʶbitλ */
	unsigned int reserved: 30;             /* ����bitλ */
	int          data;                     /* ���ݰ�ͷ��context */
	unsigned int timestamp;                /* �����ݰ���ʱ��� */
	unsigned int task_id;                  /* �����ݰ��ķ����ߵ�����id */
};

struct icc_channel_fifo {
	unsigned int  magic;     /* fifoħ������ʶͨ��fifo��״̬ */
	unsigned int  size;      /* fifo��С */
	unsigned int  write;     /* fifo��ָ�� */
	unsigned int  read;      /* fifoдָ�� */
	unsigned char data[4];  /* fifo��context */
};

#define ICC_CHANNEL_PAYLOAD                        (sizeof(struct icc_channel_packet) + 4)
#define ICC_CHANNEL_ID_MAKEUP(channel_id, func_id) ((channel_id << 16) | (func_id))


typedef int (*read_cb_func)(unsigned int channel_id , unsigned int len, void *context);
typedef int (*write_cb_func)(unsigned int channel_id , void *context);

/* ����ӿ�����start */
/*****************************************************************************
* �� �� ��  : bsp_icc_event_register
* ��������  : ʹ��iccͨ��ע��ص������ӿ�
* �������  : unsigned int channel_id  channel_id = ͨ��id << 16 || function_id, ʹ��Լ��:
                1) channel_id��16bitΪͨ����ʶID��ʹ��enum ICC_CHN_ID
                2) ��16bitΪ�ص�������ʶID��ʹ��ICC_RECV_FUNC_ID��Ӧͨ��id��ö��ֵ
*             read_cb_func read_cb      ���ص�
*             void *read_context        ���������������������Ϣ������չ��
*             write_cb_func write_cb    ���ص�
*             void *write_context       ���������������������Ϣ������չ��
* �������  : ��
* �� �� ֵ  : ��ȷ:  0;  ����: ������
* ˵    ��  : �ص������в������κλ���������������˯�ߵĺ������ã��磺
*             1) taskDelay()
*             2) �ź�����ȡ
*             3) printf()
*             4) malloc()
*****************************************************************************/
int bsp_icc_event_register(unsigned int channel_id, read_cb_func read_cb, void *read_context,
			   write_cb_func write_cb, void *write_context);

/*****************************************************************************
* �� �� ��  : bsp_icc_event_unregister
* ��������  : ʹ��iccͨ��ȥע��ص������ӿ�
* �������  : u32 channel_id  channel_id = ͨ��id << 16 || function_id, ʹ��Լ��:
                1) channel_id��16bitΪͨ����ʶID��ʹ��enum ICC_CHN_ID
                2) ��16bitΪ�ص�������ʶID��ʹ��ICC_RECV_FUNC_ID��Ӧͨ��id��ö��ֵ
* �������  : ��
* �� �� ֵ  : ��ȷ:  0;  ����: ��ֵ
*****************************************************************************/
int bsp_icc_event_unregister(unsigned int channel_id);

/*****************************************************************************
* �� �� ��  : bsp_icc_send
* ��������  : icc�첽�������ݽӿ�
* �������  : unsigned int cpuid       ����Ҫ���͵�cpu�ı�ţ�ʹ��Լ��: Ҫʹ��enum CPU_ID�����Ա��ö��ֵ
*             unsigned int channel_id  channel_id = ͨ��id << 16 || function_id, ʹ��Լ��:
                               1) channel_id��16bitΪͨ����ʶID��ʹ��enum ICC_CHN_ID��ö��ֵ
                               2) ��16bitΪ�ص�������ʶID��ʹ��ICC_RECV_FUNC_ID��Ӧͨ��id��ö��ֵ
*             u8 *buffer      Ҫ���͵�����buffer��ָ��
*             unsigned int data_len    Ҫ���͵����ݵĴ�С, ʹ��Լ��: ���ֵ < fifo_size - ICC_CHANNEL_PACKET_LEN
* �������  : ��
* �� �� ֵ  : ��ȷ:  ʵ��д��fifo�Ĵ�С;  ����: ��ֵ
* ˵    ��  : 1) ����ͨ��������ʹ�õ�ע���ڶԷ��˵Ļص����������Ҫʹ��bsp_icc_read()���������ݶ���
*            2) ר��ͨ����֧���ڸ�ͨ��ʹ��ģ���������������ʹ��bsp_icc_read()���������ݶ��ߣ������Ͷ˱����з�ѹ��ͨ�����ݷ��ͻ�����������ơ�

*****************************************************************************/
int bsp_icc_send(unsigned int cpuid, unsigned int channel_id, unsigned char *buffer, unsigned int data_len);

/*****************************************************************************
* �� �� ��  : bsp_icc_read
* ��������  : icc��fifo��ȡ���ݽӿ�
* �������  : unsigned int channel_id  channel_id = ͨ��id << 16 || function_id, ʹ��Լ��:
                1) channel_id��16bitΪͨ����ʶID��ʹ��enum ICC_CHN_ID
                2) ��16bitΪ�ص�������ʶID��ʹ��ICC_RECV_FUNC_ID��Ӧͨ��id��ö��ֵ
*             u8 *buf        Ҫ��ȡfifo������buffer��ָ��
*             unsigned int buf_len    ����buffer�Ĵ�С
* �������  : ��
* �� �� ֵ  : ��ȷ:  ʵ�ʴ�ͨ����ȡ���ݴ�С;  ����: ��ֵ
* ˵    ��  : 1) ���ڻص�������ʹ�ã���ʹ�����Լ�������������ʹ�ã������Ͷ˱����з�ѹ��ͨ�����ݷ��ͻ�����������ƣ��Ա��ֺ˼�ͨ����������ͨ
*****************************************************************************/
int bsp_icc_read(unsigned int channel_id, unsigned char *buf, unsigned int buf_len);

#define STRU_SIZE                (sizeof(struct icc_channel_fifo))

/*��ȫICCͨ��һ��Ԥ��128K,����չ*/
#define ICC_SEC_IFC_SIZE      (4 * 1024)
#define ICC_SEC_VSIM_SIZE     (16 * 1024)
#define ICC_SEC_RFILE_SIZE    (16 * 1024)

#endif

#ifdef __cplusplus /* __cplusplus */
}
#endif /* __cplusplus */

#endif    /*  __BSP_ICC_H__ */
