#!/bin/bash
#       "[-c csr file name <csr.bin>] "
#       "[-q optional CM public key key file name - PEM format <pubKey1.pem>]"
#       "[-o @OUTPUT@ oem key file name - PEM format <oem_key.pem>]"
#       "[-s file name for Scp and Krtl <cm_secrets.bin>]"
#	"[-w secters passphrase file name <cm_pwd.txt>]\n");

cd ../../../bin/

cp ../tester/oem_asset_prov/dat/cm_orig_secrets3.bin .
cp ../tester/oem_asset_prov/dat/key_pair0.pem .
cp ../tester/util_assisted/encrypt_encode_secrets/encrypt_encode_secrets.sh .

echo
echo " Run: gen oem scr... (1234512345)"
echo "================================================"
./oem_gen_csr_util -c csr1.bin -p key_pair0.pem
echo
echo " Run: encrypt encode secret... (1234567890)"
echo "================================================"
./encrypt_encode_secrets.sh cm_orig_secrets3.bin cm_secrets1.bin

echo
echo " Run: gen_oem_key (1234567890)"
echo "================================================"
./cm_gen_oem_key_util -c csr1.bin -o oem_key1.bin -s cm_secrets1.bin

