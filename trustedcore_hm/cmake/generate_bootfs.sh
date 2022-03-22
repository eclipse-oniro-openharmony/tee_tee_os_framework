#!/bin/bash
# Print all commands if V=3; maximum verbosity.
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
set -e

generate_bootfs()
{
    cd ${BOOTFS_OUT}
    GET_XOM_FILE="true"
    if [ "$ARCH" = "aarch64" ]; then
        configure_aarch64
    else
        configure_arm
    fi

    if [ "$USE_XOM32"x == yx ]; then
        cmake --build . --target use_xom32 -j${parallel_threads}
        cmake --build . --target remove_xomloc_section -j${parallel_threads}
    fi
    cmake --build . --target scramble_bootfs_symbols -j${parallel_threads}
    cmake --build . --target bootfs -j${parallel_threads}

    if [ "$ARCH" = "aarch64" ]; then
        cd ${OUT64}
    else
        cd ${OUT32}
    fi

    cmake --build . --target hmfilemgr -j${parallel_threads}
    if [ "$USE_XOM32"x == yx ]; then
        cmake --build . --target use_xom32_hmfilemgr -j${parallel_threads}
        cmake --build . --target remove_xomloc_section_hmfilemgr -j${parallel_threads}
        cmake --build . --target use_xom32_hmsysmgr -j${parallel_threads}
        cmake --build . --target remove_xomloc_section_hmsysmgr -j${parallel_threads}
    fi
    cmake --build . --target scramble_hmfilemgr_symbols -j${parallel_threads}
    cmake --build . --target scramble_hmsysmgr_symbols -j${parallel_threads}
    cmake --build . --target gen_trustedcore_image -j${parallel_threads}

    if [ "$BUILD_TEST"x == yx ]; then
        cd ${OUT64}
        cmake --build . --target cp_test_ta_64 -j1
        cd ${OUT32}
        cmake --build . --target cp_test_ta_32 -j1

        if [ "$ARCH" = "aarch64" ]; then
            cd ${OUT64}
        else
            cd ${OUT32}
        fi
    fi

    clean_after_compile
}
