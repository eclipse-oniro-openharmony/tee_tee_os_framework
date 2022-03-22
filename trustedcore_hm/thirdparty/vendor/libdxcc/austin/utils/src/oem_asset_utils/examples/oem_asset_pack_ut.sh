#!/bin/bash


echo
echo "**************   running oem asset utils   **************************"
echo "@@@   running oem_gen_csr_util"
../../../bin/oem_gen_csr_util -c csr.bin -p oem_keypair0.pem -w oem_passphrase0.txt
echo "@@@   encrypting secrets"
openssl enc -a -e -nosalt -aes-128-cbc -in cm_orig_secrets.bin -out cm_secrets.bin  -pass file:cm_secrets_pwd.txt
echo "@@@   running cm_gen_oem_key_util"
../../../bin/cm_gen_oem_key_util -c csr.bin -o oem_key.bin -s cm_secrets.bin -w cm_secrets_pwd.txt
echo "@@@   running oem_asset_pack_util"
../../../bin/oem_asset_pack_util -a asset_pkg.bin -b asset_bin.bin -i 0x367 -o oem_key.bin -p oem_keypair0.pem -w oem_passphrase0.txt

exit $?
