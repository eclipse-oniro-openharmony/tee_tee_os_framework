if ("${TARGET_IS_HOST}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS
        -Os
    )
else()
    list(APPEND TEE_C_FLAGS
        -Oz
    )
endif()

if (NOT "${TARGET_IS_HOST}" STREQUAL "y")
    if ("${ARCH}" STREQUAL "arm" AND "${CONFIG_UNALIGNED_ACCESS}" STREQUAL "y")
        list(APPEND TEE_C_FLAGS
            -munaligned-access
            -fmax-type-align=1
        )
    endif()
endif()

if (NOT "${TARGET_IS_HOST}" STREQUAL "y")
    if ("${CONFIG_LLVM_LTO}" STREQUAL "y")
        list(APPEND TEE_C_FLAGS
            -flto
            -fsplit-lto-unit
        )
    endif()
endif()

if ("${TARGET_IS_TA}" STREQUAL "y" AND "${ARCH}" STREQUAL "aarch64")
    if ("$(CONFIG_LIBFUZZER_SERVICE_64BIT)" STREQUAL "true")
        include(libfuzzer_cflags)
    endif()
endif()
