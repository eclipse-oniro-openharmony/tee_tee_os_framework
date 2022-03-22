if ("${CONFIG_USER_FULL_RELRO}" STREQUAL "y")
    if ("${TARGET_IS_ARM32}" STREQUAL "y" AND NOT "${USE_NDK_32}" STREQUAL "y" AND NOT "${TARGET_CUSTOM_LINK_SCRIPT}" STREQUAL "y")
        set(SUBCOMMON_LDFLAGS
            ${SUBCOMMON_LDFLAGS}
            -Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/tools/common/app-arm-eabi.lds
        )
    endif()
endif()

if ("${CONFIG_USER_XOM}" STREQUAL "y" AND NOT "${TARGET_IS_ARM32}" STREQUAL "y" AND NOT "${TARGET_CUSTOM_LINK_SCRIPT}" STREQUAL "y")
    set(SUBCOMMON_LDFLAGS
        ${SUBCOMMON_LDFLAGS}
        -Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/tools/common/app-aarch64.lds
    )
endif()

if ("${BUILD_TA}" STREQUAL "y")
    list(REMOVE_ITEM COMMON_CFLAGS "-ffunction-sections")
    list(REMOVE_ITEM COMMON_CFLAGS "-fdata-sections")
    if ("${TARGET_IS_ARM32}" STREQUAL "y")
        if ("${CONFIG_DYNLINK}" STREQUAL "y")
            set(COMMON_LDFLAGS
                -Wl,-x
                -Wl,-z,text
                -Wl,-z,now
                -Wl,-z,relro
                -Wl,-shared
                -Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/tools/teeos/ta_link_new.ld
            )
        else()
            set(COMMON_LDFLAGS
                -Wl,-r
                -Wl,-d
                -Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/tools/teeos/ta_link.ld
            )
        endif()
    else()
        set(COMMON_LDFLAGS
            -Wl,-x
            -Wl,-z,text
            -Wl,-z,now
            -Wl,-z,relro
            -Wl,-shared
            -Wl,-z,max-page-size=4096
            -Wl,-T${CMAKE_CURRENT_SOURCE_DIR}/tools/teeos/ta_link_64.ld
        )
    endif()
endif()
