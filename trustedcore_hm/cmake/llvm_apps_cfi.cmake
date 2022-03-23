if ("${CONFIG_LLVM_CFI}" STREQUAL "y")
    if ("${ARCH}" STREQUAL "aarch64")
        set(apps-sanitize-cfi
            ${apps-sanitize-cfi}
            -flto
            -fvisibility=default
            -fsanitize=cfi
        )
#cfi-no-icall := libswcrypto_engine.a tarunner.elf libtimer.a libcrypto_hal.a

#        ifneq ($(filter $(cfi-no-icall),$(MODULE)), )
#        apps-sanitize-cfi += -fno-sanitize=cfi-icall
#        endif()

#        ifneq ($(filter $(cfi-no-icall),$(DRIVER)), )
#        apps-sanitize-cfi += -fno-sanitize=cfi-icall
#        endif()
    endif()

    if ("${ARCH}" STREQUAL "aarch64")
        list(APPEND TEE_C_FLAGS ${apps-sanitize-cfi})
    endif()
endif()
