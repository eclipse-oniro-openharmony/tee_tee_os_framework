api_incs += .
api_srcs += tee_otp.c tee_otp_func.c tee_otp_syscall.c otp_data_hi3796cv300.c

c-flags += -fstack-protector-all

ifeq ($(CFG_ADVCA_NAGRA),y)
api_srcs += tee_otp_nagra.c
endif
