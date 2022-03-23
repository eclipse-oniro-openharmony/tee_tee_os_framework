#!/bin/bash
#        "[-c @OUTPUT@ csr file name <csr.bin>] "
#	 "[-p key-pair file name - PEM format <key_pair.pem>]"
#        "[-w pwd of private key file name <pwd.txt>]\n");

cd ../../../bin/

cp ../tester/oem_asset_prov/dat/key_pair0.pem .

echo
echo " Run: oem_gen_csr (1234512345)"
echo "================================================"
./oem_gen_csr_util -c csr1.bin -p key_pair0.pem

