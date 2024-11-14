#!/bin/bash

SSH_OPTIONS="-i /home/yx/Desktop/keystone/build/overlay/root/.ssh/id_rsa"
SSH_OPTIONS+=" -o StrictHostKeyChecking=no"
SSH_OPTIONS+=" -o UserKnownHostsFile=/dev/null"

upload_to_qemu() {
    echo "Uploading \"$(basename $1)\" to QEMU ..."
    scp ${SSH_OPTIONS} -P 3946 $1 root@localhost:.
}

run_in_qemu() {
    echo "Running \"$1\" in QEMU ..."
    ssh ${SSH_OPTIONS} -p 3946 root@localhost "$1"
}

#run_in_qemu "insmod keystone-driver.ko"

#upload_to_qemu "/home/yx/Desktop/keystone/build/examples/tests/tests.ke"
#run_in_qemu "./tests.ke"

# upload_to_qemu "/home/yx/Desktop/vf-keystone/ipfs_386/kubo/install.sh"
# upload_to_qemu "/home/yx/Desktop/vf-keystone/ipfs_386/kubo/ipfs"

# upload_to_qemu "/home/yx/Desktop/vf-keystone/go1.23.3-riscv64/go-riscv64.tar"

upload_to_qemu "/home/yx/Desktop/vf-keystone/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/test_c_interface/testcinterface"

#run_in_qemu "./attestor.ke"

#run_in_qemu "poweroff"
