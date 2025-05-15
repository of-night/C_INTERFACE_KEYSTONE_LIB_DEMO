//******************************************************************************
// Copyright (c) 2020, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>

#include "./common.h"
#include "Error.hpp"
#include "Params.hpp"
#include "shared/keystone_user.h"

namespace Keystone {

class KeystoneDevice {
 protected:
  int eid;
  uintptr_t physAddr;

 private:
  int fd;
  Error __run(bool resume, uintptr_t* ret);
  Error __test_os_access_run(bool test_os_access_stm, bool resume, uintptr_t* ret);

 public:
  virtual uintptr_t getPhysAddr() { return physAddr; }

  KeystoneDevice();
  virtual ~KeystoneDevice() {}
  virtual bool initDevice(Params params);
  virtual Error create(uint64_t minPages);
  virtual Error test_other_os_access_epm_create(uint64_t minPages);
  virtual uintptr_t initUTM(size_t size);
  virtual uintptr_t initYXSTM(size_t size, uint64_t ms);
  virtual uintptr_t initYXSTM(size_t size, uint64_t ms, uint64_t _engine_id);
  virtual Error finalize(
      uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
      uintptr_t freeRequested);
  virtual Error test_other_os_access_epm_finalize(
      uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
      uintptr_t freeRequested);
  virtual Error destroy();
  virtual Error run(uintptr_t* ret);
  virtual Error resume(uintptr_t* ret);
  virtual Error test_os_access_run(uintptr_t* ret, bool test_os_access_stm);
  virtual Error test_os_access_resume(uintptr_t* ret, bool test_os_access_stm);
  virtual void* map(uintptr_t addr, size_t size);
};

class MockKeystoneDevice : public KeystoneDevice {
 private:
  /* allocated buffer with map() */
  void* sharedBuffer;

 public:
  MockKeystoneDevice() {}
  ~MockKeystoneDevice();
  bool initDevice(Params params);
  Error create(uint64_t minPages);
  Error test_other_os_access_epm_create(uint64_t minPages);
  uintptr_t initUTM(size_t size);
  uintptr_t initYXSTM(size_t size, uint64_t ms);
  uintptr_t initYXSTM(size_t size, uint64_t ms, uint64_t _engine_id);
  Error finalize(
      uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
      uintptr_t freeRequested);
  Error test_other_os_access_epm_finalize(
      uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
      uintptr_t freeRequested);
  Error destroy();
  Error run(uintptr_t* ret);
  Error resume(uintptr_t* ret);
  Error test_os_access_run(uintptr_t* ret, bool test_os_access_stm);
  Error test_os_access_resume(uintptr_t* ret, bool test_os_access_stm);
  void* map(uintptr_t addr, size_t size);
};

}  // namespace Keystone
