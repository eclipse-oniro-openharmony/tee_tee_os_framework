#!/bin/bash
# Print all commands if V=3; maximum verbosity.
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
set -e

apply_openssl_patch()
{
    crypto_path=${ABS_SOURCE_PATH}/open_source/OpenSSL/openssl-1.1.1f/crypto
    checkpatch=${ABS_SOURCE_PATH}/open_source/OpenSSL/openssl-1.1.1f/include/openssl/opensslconf.h
    if [ ! -e "$checkpatch" ]; then
        cd ${ABS_SOURCE_PATH}/open_source/OpenSSL
        patch -p3 < huawei_resolve_crypto_compile_001.patch
        patch -p3 < huawei_replace_rand_generation_002.patch
        patch -p3 < huawei_resolve_ui_dependency_003.patch
        patch -p3 < huawei_resolve_memset_link_004.patch
        patch -p3 < huawei_delete_ec448_keccak1600_kdf_005.patch
        patch -p3 < huawei_config_ec25519_006.patch
        patch -p3 < huawei_xom_64_007.patch
        patch -p3 < huawei_xom_64_008.patch
        patch -p3 < huawei_xom_64_009.patch
        patch -p3 < huawei_performance_optimization_010.patch
        patch -p5 -d openssl-1.1.1f/ < openssl-1.1.1f-CVE-2020-1967.patch
        patch -p1 -d openssl-1.1.1f/ < Backport-CVE-2020-1971-Correctly-compare-EdiPartyName-in-GENERAL_N-c.patch
        patch -p1 -d openssl-1.1.1f/ < Backport-CVE-2021-23840-fix-output-length-overflow.patch
        patch -p1 -d openssl-1.1.1f/ < Backport-CVE-2021-23841-fix-Null-pointer-deref.patch
        patch -p1 -d openssl-1.1.1f/ < Backport-CVE-2021-3449-ssl-sigalg-extension-fix-NULL-pointer-deref-c.patch
        /usr/bin/perl $crypto_path/aes/asm/aes-armv4.pl linux32 $crypto_path/aes/asm/aes-armv4.S
        /usr/bin/perl $crypto_path/aes/asm/bsaes-armv7.pl linux32 $crypto_path/aes/asm/bsaes-armv7.S
        /usr/bin/perl $crypto_path/aes/asm/aesv8-armx.pl linux64 $crypto_path/aes/asm/aesv8-armx.S
        /usr/bin/perl $crypto_path/aes/asm/vpaes-armv8.pl linux64 $crypto_path/aes/asm/vpaes-armv8.S
        /usr/bin/perl $crypto_path/bn/asm/armv4-mont.pl linux32 $crypto_path/bn/asm/armv4-mont.S
        /usr/bin/perl $crypto_path/bn/asm/armv4-gf2m.pl linux32 $crypto_path/bn/asm/armv4-gf2m.S
        /usr/bin/perl $crypto_path/bn/asm/armv8-mont.pl linux64 $crypto_path/bn/asm/armv8-mont.S
        /usr/bin/perl $crypto_path/ec/asm/ecp_nistz256-armv4.pl linux32 $crypto_path/ec/asm/ecp_nistz256-armv4.S
        /usr/bin/perl $crypto_path/ec/asm/ecp_nistz256-armv8.pl linux64 $crypto_path/ec/asm/ecp_nistz256-armv8.S
        /usr/bin/perl $crypto_path/sha/asm/keccak1600-armv4.pl linux32 $crypto_path/sha/asm/keccak1600-armv4.S
        /usr/bin/perl $crypto_path/sha/asm/sha1-armv4-large.pl linux32 $crypto_path/sha/asm/sha1-armv4-large.S
        /usr/bin/perl $crypto_path/sha/asm/sha256-armv4.pl linux32 $crypto_path/sha/asm/sha256-armv4.S
        /usr/bin/perl $crypto_path/sha/asm/sha512-armv4.pl linux32 $crypto_path/sha/asm/sha512-armv4.S
        /usr/bin/perl $crypto_path/sha/asm/keccak1600-armv8.pl linux64 $crypto_path/sha/asm/keccak1600-armv8.S
        /usr/bin/perl $crypto_path/sha/asm/sha1-armv8.pl linux64 $crypto_path/sha/asm/sha1-armv8.S
        /usr/bin/perl $crypto_path/sha/asm/sha512-armv8.pl linux64 $crypto_path/sha/asm/sha256-armv8.S
        /usr/bin/perl $crypto_path/sha/asm/sha512-armv8.pl linux64 $crypto_path/sha/asm/sha512-armv8.S
        /usr/bin/perl $crptopath/modes/asm/ghashv8-armx.pl linux64 $crptopath/modes/asm/ghashv8-armx.S
        /usr/bin/perl $crptopath/modes/asm/ghash-armv4.pl linux32 $crptopath/modes/asm/ghash-armv4.S
        /usr/bin/perl $crptopath/armv4cpuid.pl linux32 $crptopath/armv4cpuid.S
        /usr/bin/perl $crptopath/arm64cpuid.pl linux64 $crptopath/arm64cpuid.S
    fi
}
