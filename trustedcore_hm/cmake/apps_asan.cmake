if ("${CONFIG_KASAN}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS
        -fsanitize=kernel-address
        -fasan-shadow-offset=${CONFIG_APP_MMGR_LAYOUT_PROCESS_SIZE_32}
        --param=asan-stack=1
        --param=asan-globals=1
    )
    if ("${ARCH}" STREQUAL "aarch64")
        list(APPEND LIBS asan)
    else()
        list(APPEND LIBS asan_a32)
    endif()
endif()
