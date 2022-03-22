# hisi_mailbox
list(APPEND TEE_C_DEFINITIONS
    CONFIG_HISI_MAILBOX
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/mailbox
)

list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/mailbox/ipc_mailbox.c
)