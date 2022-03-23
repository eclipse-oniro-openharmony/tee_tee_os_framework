list(APPEND HOST_C_FLAGS
    -Wall
    -Werror
    -fPIC
    -fstack-protector-all
    -Wextra
    -Wfloat-equal
    -Wformat=2
    -Wshadow
    -Wtrampolines
    -pipe
    -fno-strict-aliasing
    -fsigned-char
    -fno-common
)

if ("${GCC_VERSION}" STREQUAL "1")
    list(APPEND HOST_C_FLAGS
        -Wdate-time
    )
endif()

tee_add_executable(img_encry
    SOURCES
    img_encry.c

    COMPILE_TOOL
    host

    COMPILER_FLAGS
    ${HOST_C_FLAGS}

    LIBRARIES
    crypto

    LD_FLAGS
    -Wl,-z,relro
    -Wl,-z,noexecstack
    -Wl,-z,now
    -Wl,-pie
    -Wl,-Bsymbolic
    -rdynamic
    -Wl,--no-undefined

    INSTALL_DIR
    ${OUTPUTDIR}
)
