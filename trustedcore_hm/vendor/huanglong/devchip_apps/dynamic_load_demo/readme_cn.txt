1. ����make������� $(TA_UUID).bin, $(TA_UUID).elf��
    1.1 Ĭ�����Ŀ¼ $(CURDIR)/out
    1.2 $(TA_UUID).bin ����trustedcore������manifest.txt�����ݣ�ʹ��ǩ������ǩ���󣬳�Ϊ��̬TA��
    1.3 $(TA_UUID).elf ����trustedcore

2. ����make clean�� ɾ���������ɵ��ļ���

3. manifest.txt: Trustedcore ��̬TA�����������ļ���
   gpd.ta.appID              ---- TA ��UUID
   gpd.ta.service_name       ---- TA �����֣� ��: dynamic_load_demo
   gpd.ta.singleInstance     ---- TA �Ƿ�ʵ������: true
   gpd.ta.multiSession       ---- TA �Ƿ�֧��ͬʱ���session�� ��: false
   gpd.ta.instanceKeepAlive  ---- TA �Ƿ�פ�ڴ档
                                  true  �����һ�κ�Ͳ��ټ��ء�
                                  false ��ÿ�ζ���REE����أ���ʱTA��ȫ�ֱ���ÿ�ζ����ʼ����
   gpd.ta.dataSize           ---- TA �Ѵ�С����λ�ֽڡ�TEE_Malloc(), TA���Է����ڴ�Ĵ�С�� ��: 65536
   gpd.ta.stackSize          ---- TA ջ��С����λ�ֽڡ���: 16384

4. Makefile �������������
   CROSS_COMPILE    ---- ������(Trustedcore�Ĺ���������Ҫ���ض��ģ������������)
   TA_DEV_KIT_DIR   ---- TA�Ŀ���Ŀ¼������������TA����Ҫ��ͷ�ļ������ӽű��ȵ�Ŀ¼��
   include $(TA_DEV_KIT_DIR)/mk/ta_common.mak
   BINARY           ---- TA��UUID
   TA_NAME          ---- TA������

5. sub.mk: ����������ļ�
   srcs-y += xxx.c                         ---- ����C�ļ�
   srcs-y += xxx.s                         ---- ����S�ļ�
   subdirs-y += xxx_dir                    ---- �������ļ���
   incdirs-y += xxx_include                ---- �������ҵ�ͷ�ļ�Ŀ¼
   cflags-y += -xxx                        ---- C����ѡ���ͷ�ļ����궨���,�磺 -I, -D
   aflags-y += -xxx                        ---- ����ļ�����ѡ��

6. TA��Makefile��C�ļ������ⲿ�궨��
    6.1 ���а�ȫOS��CFG_��ͷ�ĺ궨�嶼�ᴫ�ݵ�TA��Makefile��sub.mk)�У�Ҳ�ᴫ�ݵ�C�ļ���
    6.2 SDK��cfg.mak�еĶ��岻�ᴫ�ݵ�TA��Makefile��C�ļ��У�����������ݵ��˰�ȫOS������CFG��ͷ�������ʹ�á�
    6.3 ������Щ�궨�岻��һ���õ�������Ŀǰ��ô������Ϊ�˼��ݣ�����TA��Ʋ�Ҫʹ��SDK���߰�ȫ�ĺ궨�壬��Ҫ�͵ײ���ϡ�

