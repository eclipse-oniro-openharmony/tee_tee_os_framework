set(TARGET_IS_TA y)
list(APPEND TEE_C_FLAGS
    -I${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include/libhwsecurec
    -I${PROJECT_SOURCE_DIR}/thirdparty/huawei/libhwsecurec/include
    -I${PREBUILD_LIBC_INC}
    -I${PREBUILD_LIBC_INC}/arch/generic
    -I${PREBUILD_LIBC_INC}/arch/${ARCH}
    -I${PREBUILD_LIBC_INC}/arch/${ARCH}/bits
)

list(APPEND TEE_C_FLAGS
    -fPIC
    -nostdinc
    -nodefaultlibs
    -fstack-protector-strong
    -DARM_PAE=1
    -DARCH_ARM
    -DAARCH64
    -D__KERNEL_64__
    -DARMV8_A
    -DARM_CORTEX_A53
    -DDEBUG
    -DHM_DEBUG_KERNEL
    -DNDEBUG
    -include${PREBUILD_DIR}/headers/autoconf.h
)

if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS -DDX_ENABLE)
endif()

if(NOT "${CMAKE_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
    list(APPEND TA_LDFLAGS
        -Wl,-z,separate-loadable-segments
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TA_LDFLAGS
        -Wl,--discard-all
        -Wl,-z,text
        -Wl,-z,now
        -Wl,-z,relro
        -Wl,-z,max-page-size=4096
        -Wl,-shared
        -Wl,-z,noexecstack
        -Wl,--strip-debug
        -Wl,-T${PROJECT_SOURCE_DIR}/cmake/ta_link_64.ld
    )
else()
    if ("${CONFIG_DYNLINK}" STREQUAL "y")
        if ("${CONFIG_ENABLE_XOM32}" STREQUAL "y" AND NOT "${BUILD_TA}" STREQUAL "y" AND NOT "${IN_XOM32_BLACK_LIST}" STREQUAL "y")
            list(APPEND TA_LDFLAGS
                -Wl,--discard-all
                -Wl,-z,text
                -Wl,-z,now
                -Wl,-z,relro
                -Wl,-shared
                -Wl,-z,noexecstack
                -Wl,-T${PROJECT_SOURCE_DIR}/cmake/ta_link_new.xom.ld
            )
            list(APPEND TEE_C_FLAGS -fvisibility=hidden)
        else()
            list(APPEND TA_LDFLAGS
                -Wl,--discard-all
                -Wl,-z,text
                -Wl,-z,now
                -Wl,-z,relro
                -Wl,-shared
                -Wl,-z,noexecstack
                -Wl,-T${PROJECT_SOURCE_DIR}/cmake/ta_link_new.ld
            )
            list(APPEND TEE_C_FLAGS -fvisibility=hidden)
        endif()
    else()
        list(APPEND TA_LDFLAGS
            -Wl,-r
            -Wl,-d
            -Wl,-T${PROJECT_SOURCE_DIR}/cmake/ta_link.ld
        )
    endif()
endif()

list(APPEND TA_LDFLAGS -Wl,--build-id=none)
list(APPEND TA_LDFLAGS -Wl,-L${LIB_DIR} -Wl,-L${PREBUILD_ARCH_PLAT_LIBS})

list(APPEND TA_LDFLAGS
    -s
)

list(REMOVE_ITEM TA_LDFLAGS "-Wl,-pie")
list(REMOVE_ITEM TEE_LINKER_FLAGS "-Wl,-pie")
list(REMOVE_ITEM TA_LDFLAGS "-Wl,--gc-sections")
list(REMOVE_ITEM TEE_LINKER_FLAGS "-Wl,--gc-sections")
list(APPEND TA_LDFLAGS -Wl,-hash-style=sysv)
