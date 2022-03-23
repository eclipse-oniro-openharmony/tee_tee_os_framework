api_incs += .
api_srcs += hi_tee_klad.c \
            tee_klad.c \
            tee_klad_msg_queue.c \
            tee_klad_utils.c \
            tee_klad_func.c \
            tee_klad_mgmt.c \
            tee_klad_bitmap.c \
            tee_klad_syscall.c

inc-flags += -fstack-protector-all

ifeq ($(CFG_ADVCA_NAGRA),y)
api_incs += -I$(HI_TEE_DRV_DIR)/klad/nagra/
api_srcs += nagra/hi_tee_cert.c
api_srcs += nagra/tee_cert.c
inc-flags += -DHI_TEE_KLAD_CERT
endif
