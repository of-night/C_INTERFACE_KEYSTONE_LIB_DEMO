#!/bin/bash

CXX=riscv64-buildroot-linux-gnu-g++

VF_KEYSTONE=/home/yx/Desktop/vf-keystone

KEYSTONELIB=${VF_KEYSTONE}/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_keystone/lib
KEYSTONEINCLUDE=${VF_KEYSTONE}/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_keystone/include

MYKEYSTONEINCLUDE=${VF_KEYSTONE}/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_c_interface_keystone/include

src_name=secure_dispatch_child_process.cpp
dest_name=secure_dispatch_child_process

cpy_path=~/ipfs

src_path=lib_c_interface_keystone/src

src=${src_path}/${src_name}

rm ${dest_name} -rf

$CXX -o ${dest_name} \
	${src} \
	-I${MYKEYSTONEINCLUDE} \
	-L${KEYSTONELIB} \
	-lkeystone-host \
	-lkeystone-edge \
	-I${KEYSTONEINCLUDE}/host \
	-I${KEYSTONEINCLUDE}/edge \
	-I${KEYSTONEINCLUDE} \
	-static

sudo rm ${cpy_path}/${dest_name} -rf
sync
sudo cp ${dest_name} ${cpy_path}/
sync

