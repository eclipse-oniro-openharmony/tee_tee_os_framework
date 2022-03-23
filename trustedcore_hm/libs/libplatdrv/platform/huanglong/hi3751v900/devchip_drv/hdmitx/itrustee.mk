
# if you need a macro ,you can define like this
# drv_flags += -DHI_XXXX
#

drv_incs += . \
            hal \

drv_srcs += tee_drv_hdmitx.c \
            tee_drv_hdmitx_sys.c \
            hal/tee_hal_hdmitx_io.c \
            hal/tee_hal_hdmitx_hdcp2x.c \
            hal/tee_hal_hdmitx_hdcp1x.c \
            hal/tee_hal_hdmitx_ctrl.c
