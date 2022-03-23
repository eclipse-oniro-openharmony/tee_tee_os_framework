if ("${chip_type}" STREQUAL "cs2")
    list(APPEND PLATDRV_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../../vendor/hisi/ap/platform/kirin990_cs2
    )
else ()
    list(APPEND PLATDRV_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../../vendor/hisi/ap/platform/kirin990
    )
endif()

list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/npu_v100
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/npu_v100/uapi
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/npu_v100/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/npu_v100/comm
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/npu_v100/device/common
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/npu_v100/device/resource
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/npu_v100/manager
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/npu_v100/platform
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../../vendor/hisi/npu/inc/driver
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secsvm/include
)
# for list.h interface
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/secmem/include
)
if ("${chip_type}" STREQUAL "cs2")
    list(APPEND PLATDRV_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/npu_v100/platform/kirin990_cs2
    )
else()
    list(APPEND PLATDRV_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/npu_v100/platform/hi3690
    )
endif()
set(USE_GNU_CXX y)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/opensource/libbz_hm/src
)
list(APPEND PLATDRV_LIBRARIES
    bz_hm
)

# npu kernel driver
# platform module
if ("${chip_type}" STREQUAL "cs2")
    list(APPEND TEE_C_SOURCES
        platform/libthirdparty_drv/plat_drv/npu_v100/platform/kirin990_cs2/npu_adapter.c
        platform/libthirdparty_drv/plat_drv/npu_v100/platform/kirin990_cs2/npu_chip_cfg.c
    )
else()
    list(APPEND TEE_C_SOURCES
        platform/libthirdparty_drv/plat_drv/npu_v100/platform/hi3690/npu_adapter.c
    )
endif()
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_irq.c
    platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_reg.c
    platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_dfx.c
    platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_gic.c
    platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_resmem.c
    platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_feature.c
    platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_platform.c
    # device common module
    platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_common.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_cma.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_shm.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_mailbox_msg.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_doorbell.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_pm.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_devinit.c
    # device resource module
    platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_mailbox.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_mailbox_utils.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_calc_sq.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_calc_cq.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_stream.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_sink_stream.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_event.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_model.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_task.c
    platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_semaphore.c
    # device service module
    platform/libthirdparty_drv/plat_drv/npu_v100/device/service/npu_calc_channel.c
)

# manager module
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/npu_v100/manager/npu_proc_ctx.c
    platform/libthirdparty_drv/plat_drv/npu_v100/manager/npu_ioctl_services.c
    platform/libthirdparty_drv/plat_drv/npu_v100/manager/npu_manager_ioctl_services.c
    platform/libthirdparty_drv/plat_drv/npu_v100/manager/npu_recycle.c
    platform/libthirdparty_drv/plat_drv/npu_v100/manager/npu_manager_common.c
    platform/libthirdparty_drv/plat_drv/npu_v100/manager/npu_manager.c
)

list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/npu_v100/device/service
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/npu_v100/inc
)