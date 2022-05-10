if ("${BUILD_TA}" STREQUAL "y")
    LIST(REMOVE_ITEM COMMON_CFLAGS "-ffunction-sections")
    LIST(REMOVE_ITEM COMMON_CFLAGS "-fdata-sections")

    if ("${ARCH}" STREQUAL "arm")
        if ("${CONFIG_DYNLINK}" STREQUAL "y")
            if ("${CONFIG_ENABLE_XOM32}" STREQUAL "y")
                set(COMMON_LDFLAGS
                    ${COMMON_LDFLAGS}
                    -Wl,-x
                    -Wl,-z,text
                    -Wl,-z,now
                    -Wl,-z,relro
                    -Wl,-shared
                    -Wl,-T${PROJECT_SOURCE_DIR}/tools/teeos/ta_link_new.xom.ld
                )
            else()
                set(COMMON_LDFLAGS
                    ${COMMON_LDFLAGS}
                    -Wl,-x
                    -Wl,-z,text
                    -Wl,-z,now
                    -Wl,-z,relro
                    -Wl,-shared
                    -Wl,-T${PROJECT_SOURCE_DIR}/tools/teeos/ta_link_new.ld
                )
            endif()
        else()
            set(COMMON_LDFLAGS
                ${COMMON_LDFLAGS}
                -Wl,-r
                -Wl,-d
                -Wl,-T${PROJECT_SOURCE_DIR}/tools/teeos/ta_link.ld
            )
        endif()
    else()
        set(COMMON_LDFLAGS
            ${COMMON_LDFLAGS}
            -Wl,-x
            -Wl,-z,text
            -Wl,-z,now
            -Wl,-z,relro
            -Wl,-shared
            -Wl,-z,max-page-size=4096
            -Wl,-T${PROJECT_SOURCE_DIR}/tools/teeos/ta_link_64.ld
        )
    endif()

    if ("${ARCH}" STREQUAL "aarch64")
        set(COMMON_LDFLAGS
            ${COMMON_LDFLAGS}
            -L${GCC64_TOOLCHAIN_PATH}/aarch64-linux-gnu/libc/usr/lib
            -L${GCC64_TOOLCHAIN_PATH}/aarch64-linux-gnu/libc/lib
            -L${GCC64_TOOLCHAIN_PATH}/lib/gcc/aarch64-linux-gnu/7.5.0
        )
    else()
        set(COMMON_LDFLAGS
            ${COMMON_LDFLAGS}
            -L${GCC32_TOOLCHAIN_PATH}/arm-linux-gnueabi/libc/usr/lib
            -L${GCC32_TOOLCHAIN_PATH}/arm-linux-gnueabi/libc/lib
            -L${GCC32_TOOLCHAIN_PATH}/lib/gcc/arm-linux-gnueabi/7.5.0
        )
    endif()
endif()

if(NOT "${CMAKE_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
list(APPEND COMMON_LDFLAGS
    -Wl,-z,separate-loadable-segments
)
endif()

if (NOT DEFINED "${TARGET_IS_HOST}")
    if ("${CONFIG_LLVM_LTO}" STREQUAL "y")
        if (NOT DEFINED "${CONFIG_GCOV}")
            set(COMMON_CFLAGS
                ${COMMON_CFLAGS}
		        -flto
		        -fsplit-lto-unit
            )
        endif()
    endif()
endif()


