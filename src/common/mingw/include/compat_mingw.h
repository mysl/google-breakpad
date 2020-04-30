#ifndef COMPAT_MINGW_H
#define COMPAT_MINGW_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>

#define sys_mmap mmap
#define sys_munmap munmap
#define sys_fstat fstat
#define sys_close close
#define sys_open open

#ifndef __WORDSIZE
#define __WORDSIZE 64
#endif
#ifndef __x86_64__
#define __x86_64__
#endif
// #ifndef __ARM_EABI__
// #define __ARM_EABI__ 1
// #endif
// #ifndef __ARM_ARCH_3__
// #define __ARM_ARCH_3__ 1
// #endif

#define kernel_stat stat

extern "C" int getpagesize();
extern "C" uint32_t htonl(uint32_t hostlong);
extern "C" uint16_t htons(uint16_t hostshort);

void *memrchr(const void *s, int c, size_t n);
char *realpath(const char *path, char *resolved_path);

#endif // COMPAT_MINGW_H