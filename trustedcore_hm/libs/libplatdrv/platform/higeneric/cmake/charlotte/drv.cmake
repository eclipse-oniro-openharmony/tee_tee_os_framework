# charlotte main include
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/include
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/kirin/include/platform/charlotte_es
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/isp
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/hifi
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/include
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/ivp
)

#oemkey
include(${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.cmake)

if ("${chip_type}" STREQUAL "es")
    list(
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/kirin/include/platform/charlotte_es
    )
else()
    if("${chip_type}" STREQUAL "cs2")
        list(
            ${CMAKE_CURRENT_SOURCE_DIR}/platform/kirin/include/platform/charlotte_cs2
        )
    else()
        list(
            ${CMAKE_CURRENT_SOURCE_DIR}/platform/kirin/include/platform/charlotte_cs
        )
    endif()
endif()

# drivers

# teeos shared memory
list(APPEND TEE_C_SOURCES
    platform/kirin/tee_sharedmem/bl2_sharedmem.c
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/kirin/tee_sharedmem
)
