ifneq ($(filter $(TARGET_BOARD_PLATFORM), kirin990), )
    ifneq ($(product_type), armpc)
        inc-flags += -DSWING_SUPPORTED
        CFILES += platform/libthirdparty_drv/huawei_drv/face_recognize/tee_face_recognize.c
    endif
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM), baltimore miamicw orlando kirin710 kirin980 denver kirin970), )
    CFILES += platform/libthirdparty_drv/huawei_drv/face_recognize/tee_face_recognize.c
endif

