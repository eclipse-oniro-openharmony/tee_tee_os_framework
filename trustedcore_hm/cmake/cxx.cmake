set(PREBUILD_TOOLCHAIN
    ${CMAKE_TOOLCHAIN_PATH}/clang+llvm
)
set(LLVM_LIB
    ${PREBUILD_TOOLCHAIN}/lib
)
list(APPEND TEE_CXX_FLAGS
    -nostdinc++
    -I${LLVM_INC}
)

if ("${ENABLE_CPP}" STREQUAL "true")
    if ("${ARCH}" STREQUAL "arm")
    set(CPP_LIBRARIES
            c++_static
            c++abi
            unwind
            ${CXX_COMPS}
        )
    else()
        set(CPP_LIB
            c++_static
            c++abi
        )
    endif()
    list(APPEND DRV_LDFLAGS
        -Wl,--eh-frame-hdr -Wl,--gc-sections  -Wl,-L${PREBUILD_LIBS}/${ARCH} -Wl,--allow-shlib-undefined
    )
endif()
