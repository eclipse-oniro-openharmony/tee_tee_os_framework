# inse
list(APPEND TEE_C_DEFINITIONS
    SE_VENDOR_GENERAL_SEE
    SE_USE_ESE_I2C
    CONFIG_GENERAL_SEE_IPC_SUPPORT_BIGDATA
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/hisee
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/huawei_drv/eSE/se_dummy.c
    platform/libthirdparty_drv/huawei_drv/eSE/hisee/hisee.c
    platform/libthirdparty_drv/huawei_drv/eSE/hisee/ese_data_handle.c
    platform/libthirdparty_drv/huawei_drv/eSE/hisee/ipc_a.c
    platform/libthirdparty_drv/huawei_drv/eSE/hisee/ipc_msg.c
)

if ("${CONFIG_HISI_SECFLASH}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_SECFLASH
        SECFLASH_TEE
    )
    list(APPEND PLATDRV_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/secflash
    )
    list(APPEND TEE_C_SOURCES
        platform/libthirdparty_drv/huawei_drv/eSE/secflash/secflash_data_link.c
        platform/libthirdparty_drv/huawei_drv/eSE/secflash/secflash_io.c
        platform/libthirdparty_drv/huawei_drv/eSE/secflash/secflash_timer.c
    )
    set(CONFIG_SECFLASH_DATA_LINK_TEST false)
    if ("${CONFIG_SECFLASH_DATA_LINK_TEST}" STREQUAL "true")
        list(APPEND TEE_C_DEFINITIONS
            SECFLASH_DATA_LINK_TEST
        )
        list(APPEND PLATDRV_INCLUDE_PATH
            ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/secflash/secflash_test
        )
        list(APPEND TEE_C_SOURCES
            platform/libthirdparty_drv/huawei_drv/eSE/secflash/secflash_data_link_test.c
        )
    endif()
endif()

# p61
list(APPEND TEE_C_DEFINITIONS
    SE_SUPPORT_ST
    SE_VENDOR_NXP
    HISI_TEE
    SE_SUPPORT_MULTISE
    SE_SUPPORT_SN110
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/p61
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/p61/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/p61/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/p73
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/t1
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/p73/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/p73/pal
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/p73/common
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/p73/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/p73/spm
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/p73/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv/eSE/p73/pal/spi
)

list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/huawei_drv/eSE/p61/p61.c
    platform/libthirdparty_drv/huawei_drv/eSE/p61/lib/phNxpEse_Api_p61.c
    platform/libthirdparty_drv/huawei_drv/eSE/p61/lib/phNxpEse_Api_hisi_p61.c
    platform/libthirdparty_drv/huawei_drv/eSE/p61/lib/phNxpEseDataMgr_p61.c
    platform/libthirdparty_drv/huawei_drv/eSE/p61/lib/phNxpEseProto7816_3_p61.c
    platform/libthirdparty_drv/huawei_drv/eSE/t1/t1.c
    platform/libthirdparty_drv/huawei_drv/eSE/p73/p73.c
    platform/libthirdparty_drv/huawei_drv/eSE/p73/pal/spi/phNxpEsePal_spi.c
    platform/libthirdparty_drv/huawei_drv/eSE/p73/pal/phNxpEsePal.c
    platform/libthirdparty_drv/huawei_drv/eSE/p73/lib/phNxpEse_Api.c
    platform/libthirdparty_drv/huawei_drv/eSE/p73/lib/phNxpEse_Api_hisi.c
    platform/libthirdparty_drv/huawei_drv/eSE/p73/lib/phNxpEse_Apdu_Api.c
    platform/libthirdparty_drv/huawei_drv/eSE/p73/lib/phNxpEseDataMgr.c
    platform/libthirdparty_drv/huawei_drv/eSE/p73/lib/phNxpEseProto7816_3.c
    platform/libthirdparty_drv/huawei_drv/eSE/p73/utils/ese_config_hisi.c
    platform/libthirdparty_drv/huawei_drv/eSE/p73/utils/ringbuffer.c
)