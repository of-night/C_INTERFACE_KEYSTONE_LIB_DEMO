//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_USER_H_
#define _KEYSTONE_USER_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#include "sm_call.h"

// Linux generic TEE subsystem magic defined in <linux/tee.h>
#define KEYSTONE_IOC_MAGIC 0xa4

// ioctl definition
#define KEYSTONE_IOC_CREATE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x00, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_DESTROY_ENCLAVE \
  _IOW(KEYSTONE_IOC_MAGIC, 0x01, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_RUN_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x04, struct keystone_ioctl_run_enclave)
#define KEYSTONE_IOC_RESUME_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x05, struct keystone_ioctl_run_enclave)
#define KEYSTONE_IOC_FINALIZE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x06, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_UTM_INIT \
  _IOR(KEYSTONE_IOC_MAGIC, 0x07, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_YXSTM_INIT \
  _IOR(KEYSTONE_IOC_MAGIC, 0x08, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_TEST_OS_ACCESS_STM_RUN_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x09, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_TEST_OS_ACCESS_STM_RESUME_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0a, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_TEST_OS_ACCESS_EPM_RUN_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0b, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_TEST_OS_ACCESS_EPM_RESUME_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0c, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_TEST_OTHER_OS_ACCESS_EPM_CREATE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0d, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_TEST_OTHER_OS_ACCESS_EPM_FINALIZE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0e, struct keystone_ioctl_create_enclave)

#define RT_NOEXEC 0
#define USER_NOEXEC 1
#define RT_FULL 2
#define USER_FULL 3
#define UTM_FULL 4

struct keystone_ioctl_create_enclave {
  uintptr_t eid;

  // ms
  uintptr_t ms;
  // engine id
  uintptr_t engine_id;

  // host -> driver
  uintptr_t min_pages; // create
  uintptr_t utm_size; // utm_init
  uintptr_t YXSTM_size; // YXSTM_init

  // host -> driver // finalize
  uintptr_t runtime_paddr;
  uintptr_t user_paddr;
  uintptr_t free_paddr;
  uintptr_t free_requested;

  // driver -> host
  uintptr_t epm_paddr;
  uintptr_t epm_size;
  uintptr_t utm_paddr;
  uintptr_t YXSTM_paddr;
};

struct keystone_ioctl_run_enclave {
  uintptr_t eid;
  uintptr_t error;
  uintptr_t value;
};

#endif
