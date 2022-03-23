#drv_flags :=

drv_incs += .

drv_flags += -fstack-protector-all
drv_srcs += drv_otp.c \
            drv_otp_intf.c \
            hal_otp.c

ifeq ($(CFG_HI_TEE_OTP_TEST_SUPPORT), y)
drv_srcs += drv_otp_proc.c
drv_flags += -DHI_OTP_TEST_SUPPORT
endif
