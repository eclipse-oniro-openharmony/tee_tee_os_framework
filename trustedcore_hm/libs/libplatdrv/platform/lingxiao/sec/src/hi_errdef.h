/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * Description: header files
 * Author: hsan
 * Create: 2019-1-31
 * History: 2019-1-31 hsan code restyle
 */

#ifndef __HI_ERRDEF_H__
#define __HI_ERRDEF_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/*
 * ��˼ʹ�ã�0x00000000 - 0x0FFFFFFF
 * ������ĸ˳������
 */
enum hi_ret_base_e {
	/* ���سɹ� */
	HI_RET_SUCC                     = 0,
	/* ����ͨ�ô����� */
	HI_RET_FAIL                     = 0xFFFFFFFF,
	/* ��������ʼ��ֵ */
	HI_RET_BASEVALUE                = 0x70000000,
	/* оƬ��֧�ָù��� */
	HI_RET_CHIP_NOT_SUPPORTED       = (HI_RET_BASEVALUE | 0x01),
	/* оƬ�Ŵ��� */
	HI_RET_CHIP_ID_ERROR            = (HI_RET_BASEVALUE | 0x02),
	/* CRCУ�������� */
	HI_RET_CRC_ERR                  = (HI_RET_BASEVALUE | 0x03),
	/* �����豸æ */
	HI_RET_DEVBUSY                  = (HI_RET_BASEVALUE | 0x04),
	/* �����豸�� */
	HI_RET_DEVEMPTY                 = (HI_RET_BASEVALUE | 0x05),
	/* �����豸�� */
	HI_RET_DEVFULL                  = (HI_RET_BASEVALUE | 0x06),
	/* �����豸��ʱ */
	HI_RET_DEVTIMEOUT               = (HI_RET_BASEVALUE | 0x07),
	/* �豸δʹ�� */
	HI_RET_DEVCLOSE                 = (HI_RET_BASEVALUE | 0x08),
	/* ���ļ����� */
	HI_RET_FILE_OPEN_FAIL           = (HI_RET_BASEVALUE | 0x09),
	/* �ر��ļ����� */
	HI_RET_FILE_CLOSE_FAIL          = (HI_RET_BASEVALUE | 0x0A),
	/* ���ļ����� */
	HI_RET_FILE_READ_FAIL           = (HI_RET_BASEVALUE | 0x0B),
	/* д�ļ����� */
	HI_RET_FILE_WRITE_FAIL          = (HI_RET_BASEVALUE | 0x0C),
	/* ��ʼ��ʧ�� */
	HI_RET_INIT_FAIL                = (HI_RET_BASEVALUE | 0x0D),
	/* ����item������ */
	HI_RET_ITEM_NOTEXIST            = (HI_RET_BASEVALUE | 0x0E),
	/* ����item�Ѿ����� */
	HI_RET_ITEM_EXIST               = (HI_RET_BASEVALUE | 0x0F),
	/* ����item������ */
	HI_RET_ITEM_FULL                = (HI_RET_BASEVALUE | 0x10),
	/* ����item�����쳣 */
	HI_RET_ITEM_EXCEPT              = (HI_RET_BASEVALUE | 0x11),
	/* ������Ч���� */
	HI_RET_INVALID_PARA             = (HI_RET_BASEVALUE | 0x12),
	/* �����״̬ */
	HI_RET_INVALID_STATE            = (HI_RET_BASEVALUE | 0x13),
	/* �Ƿ�VLAN ID */
	HI_RET_INVALID_VLAN_ID          = (HI_RET_BASEVALUE | 0x14),
	/* ���ȼ����ʹ��� */
	HI_RET_INVALID_PRIORITY_TYPE    = (HI_RET_BASEVALUE | 0x15),
	/* MAC��ַ�ϻ�ʱ��Ƿ� */
	HI_RET_INVALID_MAC_AGE_TIME     = (HI_RET_BASEVALUE | 0x16),
	/* MAC��ַѧϰ���Ƿ� */
	HI_RET_INVALID_MAC_LEARN_LIMIT  = (HI_RET_BASEVALUE | 0x17),
	/* MAC��ַ�Ƿ� */
	HI_RET_INVALID_MAC_ADDR         = (HI_RET_BASEVALUE | 0x18),
	/* �˿�TAG���ʹ��� */
	HI_RET_INVALID_PORT_TAG_MODE    = (HI_RET_BASEVALUE | 0x19),
	/* ����ĵ�ַ */
	HI_RET_INVALID_ADDR             = (HI_RET_BASEVALUE | 0x1A),
	/* �����ڴ�ʧ�� */
	HI_RET_MALLOC_FAIL              = (HI_RET_BASEVALUE | 0x1B),
	/* �ͷ��ڴ�ʧ�� */
	HI_RET_MFREE_FAIL               = (HI_RET_BASEVALUE | 0x1C),
	/* δ֪����Ϣ���� */
	HI_RET_MSG_UNKNOWN              = (HI_RET_BASEVALUE | 0x1D),
	/* ���յ�����Ϣ���ȴ��� */
	HI_RET_MSG_RCV_ERRSIZE          = (HI_RET_BASEVALUE | 0x1E),
	/* ���������ָ�� */
	HI_RET_NULLPTR                  = (HI_RET_BASEVALUE | 0x1F),
	/* ���ز�֧�� */
	HI_RET_NOTSUPPORT               = (HI_RET_BASEVALUE | 0x20),
	/* ���س���ϵͳ��Χ */
	HI_RET_OUTRANG                  = (HI_RET_BASEVALUE | 0x21),
	/* д�Ĵ���ʧ�� */
	HI_RET_REG_WRITE_ERR            = (HI_RET_BASEVALUE | 0x22),
	/* ���Ĵ���ʧ�� */
	HI_RET_REG_READ_ERR             = (HI_RET_BASEVALUE | 0x23),
	/* �ظ����� */
	HI_RET_REPEAT_OPER              = (HI_RET_BASEVALUE | 0x24),
	/* ϵͳ����ʧ�� */
	HI_RET_SYS_CALLFAIL             = (HI_RET_BASEVALUE | 0x25),
	/* ִ��ʧ�� */
	HI_RET_SYS_EXCEPTION            = (HI_RET_BASEVALUE | 0x26),
	/* �ȴ��źŷ��� */
	HI_RET_SIGNAL                   = (HI_RET_BASEVALUE | 0x27),
	/* ���ͳ�ʱ */
	HI_RET_TIMEOUT                  = (HI_RET_BASEVALUE | 0x28),
	/* ������ʱ��ʧ�� */
	HI_RET_TIMER_CREATE_FAIL        = (HI_RET_BASEVALUE | 0x29),
	/* ���� */
	HI_RET_TABLE_FULL               = (HI_RET_BASEVALUE | 0x2A),
	/* �����Ѵ��� */
	HI_RET_TABLE_EXIST              = (HI_RET_BASEVALUE | 0x2B),
	/* ���в����� */
	HI_RET_TABLE_NOTEXIST           = (HI_RET_BASEVALUE | 0x2C),
	/* ����item�����쳣 */
	HI_RET_TABLE_EXCEPT             = (HI_RET_BASEVALUE | 0x2D),
	/* û�г�ʼ�� */
	HI_RET_UNINIT                   = (HI_RET_BASEVALUE | 0x2E),
	/* �Ѿ���ʼ�� */
	HI_RET_ALREADYINIT              = (HI_RET_BASEVALUE | 0x2F),
	/* ����û�д򿪻��߼��� */
	HI_RET_UNACTIVE                 = (HI_RET_BASEVALUE | 0x30),
	/* ���ش�������ʧ�� */
	HI_RET_FORKFAIL                 = (HI_RET_BASEVALUE | 0x31),
	/* ����û�з��� */
	HI_RET_NOTFIND                  = (HI_RET_BASEVALUE | 0x32),
	/* ����δ�ڴ��쳣 */
	HI_RET_UNEXCEPT                 = (HI_RET_BASEVALUE | 0x33),
	/* �����ڴ��ǿ� */
	HI_RET_NOTEMPTY                 = (HI_RET_BASEVALUE | 0x34),
	/* �̴߳���ʧ�� */
	HI_RET_THREAD_CREATE_FAIL       = (HI_RET_BASEVALUE | 0x35),
	/* ���ز�����ֹ */
	HI_RET_STOP                     = (HI_RET_BASEVALUE | 0X37),
};

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif /* __HI_ERRDEF_H__ */
