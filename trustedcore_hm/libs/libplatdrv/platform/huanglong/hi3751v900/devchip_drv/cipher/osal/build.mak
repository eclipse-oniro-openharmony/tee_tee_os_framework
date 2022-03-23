CIPHER_CFLAGS += -I$(CIPHER_DIR)/osal/include
CIPHER_CFLAGS += -I$(CIPHER_DIR)/test
CIPHER_CFLAGS += -I$(CIPHER_DIR)/../mem/sec_mmz/include

CIPHER_OBJS   += osal/drv_osal_init.o \
                 osal/drv_osal_sys.o
