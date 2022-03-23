list(APPEND TEE_C_SOURCES
    platform/kirin/antiroot/device_status.c
    platform/kirin/antiroot/sre_rwroot.c
)
if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        platform/kirin/ccdriver_lib/cc_driver_syscall.c
    )
endif()

if (NOT "${product_type}" STREQUAL "armpc")
    list(APPEND TEE_C_SOURCES
        platform/kirin/ccdriver_lib/eps_syscall.c
    )
endif()

if ("${CONFIG_SE_SERVICE_32BIT}" STREQUAL "true" OR "${CONFIG_SE_SERVICE_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        platform/kirin/eSE/se_syscall.c
    )
endif()

if (NOT "${product_type}" STREQUAL "armpc")
    list(APPEND TEE_C_SOURCES
        platform/kirin/secmem/driver/sion/dynion.c
    )
endif()

if ("${CONFIG_OFF_DRV_TIMER}" STREQUAL "y")
    list(APPEND PLATDRV_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/rtc_timer/platform/generic/include
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/rtc_timer/platform/generic/src
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/rtc_timer/src
    )
    list(APPEND TEE_C_SOURCES
        platform/common/rtc_timer/src/rtc_timer_event.c
        platform/common/rtc_timer/src/rtc_timer_init.c
        platform/common/rtc_timer/src/rtc_timer_pm.c
        platform/common/rtc_timer/src/rtc_timer_syscall.c
        platform/common/rtc_timer/platform/generic/src/timer_rtc.c
    )
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/platform/common/gatekeeper/gatekeeper_drv.cmake)
