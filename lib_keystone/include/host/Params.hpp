//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <cstdio>

#if __riscv_xlen == 64
#define DEFAULT_FREEMEM_SIZE 1024 * 1024  // 1 MB
#define DEFAULT_UNTRUSTED_PTR 0xffffffff80000000
#define DEFAULT_YXSTRUSTED_PTR 0xffffffffa0000000
#define DEFAULT_STACK_SIZE 1024 * 16  // 16k
#define DEFAULT_STACK_START 0x0000000040000000
#elif __riscv_xlen == 32
#define DEFAULT_FREEMEM_SIZE 1024 * 512  // 512 KiB
#define DEFAULT_UNTRUSTED_PTR 0x80000000
#define DEFAULT_YXSTRUSTED_PTR 0xa0000000
#define DEFAULT_STACK_SIZE 1024 * 8  // 3 KiB
#define DEFAULT_STACK_START 0x40000000
#else                                     // for x86 tests
#define DEFAULT_FREEMEM_SIZE 1024 * 1024  // 1 MB
#define DEFAULT_UNTRUSTED_PTR 0xffffffff80000000
#define DEFAULT_YXSTRUSTED_PTR 0xffffffffa0000000
#define DEFAULT_STACK_SIZE 1024 * 16  // 16k
#define DEFAULT_STACK_START 0x0000000040000000
#endif

#define DEFAULT_UNTRUSTED_SIZE 8192  // 8 KB
#define DEFAULT_YXSHARETRUSTED_SIZE 256 * 1024  // 256 KB
#define DEFAULT_MS_YXSTM 0  //  no ms, not use YXSTM

/* parameters for enclave creation */
namespace Keystone {

class Params {
 public:
  Params() {
    untrusted_size = DEFAULT_UNTRUSTED_SIZE;
    freemem_size   = DEFAULT_FREEMEM_SIZE;
    YXsharedtrusted_size  = DEFAULT_YXSHARETRUSTED_SIZE;
    ms                    = DEFAULT_MS_YXSTM;
  }

  void setUntrustedSize(uint64_t size) { untrusted_size = size; }
  void setFreeMemSize(uint64_t size) { freemem_size = size; }
  uintptr_t getUntrustedSize() { return untrusted_size; }
  uintptr_t getFreeMemSize() { return freemem_size; }
  uintptr_t getYXShareTrustedMemSize() { return YXsharedtrusted_size; }
  int getYXms() { return ms; }
  void setYXShareTrustedMemSize(uint64_t size) { YXsharedtrusted_size = size; }
  void setYXms(uint64_t _ms) { ms = _ms; }

 private:
  uint64_t untrusted_size;
  uint64_t freemem_size;
  uint64_t YXsharedtrusted_size;
  uint64_t ms;
};

}  // namespace Keystone
