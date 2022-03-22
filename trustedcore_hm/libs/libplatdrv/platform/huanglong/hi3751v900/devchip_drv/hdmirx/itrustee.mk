#drv_incs  :=
#drv_srcs  :=
#drv_flags :=

drv_incs += .
drv_incs += ./hal
drv_incs += ./product/v900es

drv_srcs += tee_drv_hdmirx.c \
            tee_drv_hdmirx_ctrl.c \
            tee_drv_hdmirx_hdcp.c \
            tee_drv_hdmirx_rpt.c \
            hal/tee_hal_hdmirx_comm.c \
            hal/tee_hal_hdmirx_ctrl.c \
            hal/tee_hal_hdmirx_hdcp.c

