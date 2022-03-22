#drv_flags :=

drv_incs += .
drv_flags += -fstack-protector-all

drv_srcs += drv_keyslot.c \
            drv_keyslot_intf.c \
            hal_keyslot.c
