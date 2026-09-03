// Copyright (c) 2024, The PBC Project
//
// Wrapper to safely call randomx_create_vm from C code.
// randomx_create_vm internally allocates C++ objects via LargePageAllocator
// which throws std::bad_alloc on ENOMEM (MAP_HUGETLB failure).
// Since rx-slow-hash.c is compiled as C, it cannot catch C++ exceptions.
// This wrapper catches bad_alloc and retries without RANDOMX_FLAG_LARGE_PAGES.

#include <new>
#include <cstdio>
#include <cerrno>
#include "randomx.h"

extern "C" {

// Safe wrapper: tries with given flags, on bad_alloc strips LARGE_PAGES and retries.
// Returns NULL only if both attempts fail.
randomx_vm* randomx_create_vm_safe(randomx_flags flags,
                                    randomx_cache* cache,
                                    randomx_dataset* dataset)
{
  try {
    return randomx_create_vm(flags, cache, dataset);
  }
  catch (const std::bad_alloc&)
  {
    if (flags & RANDOMX_FLAG_LARGE_PAGES)
    {
      // bad_alloc caused by LARGE_PAGES mmap failure — retry without it
      fprintf(stderr,
        "PBC RX: randomx_create_vm bad_alloc with LARGE_PAGES flags=0x%x — retrying without LARGE_PAGES\n",
        (int)flags);
      fflush(stderr);

      randomx_flags fallback_flags = (randomx_flags)(flags & ~RANDOMX_FLAG_LARGE_PAGES);
      try {
        randomx_vm* vm = randomx_create_vm(fallback_flags, cache, dataset);
        if (vm) {
          fprintf(stderr,
            "PBC RX: randomx_create_vm fallback OK (no LARGE_PAGES) flags=0x%x\n",
            (int)fallback_flags);
          fflush(stderr);
        } else {
          fprintf(stderr,
            "PBC RX: randomx_create_vm fallback returned NULL flags=0x%x errno=%d\n",
            (int)fallback_flags, errno);
          fflush(stderr);
        }
        return vm;
      }
      catch (const std::bad_alloc&) {
        // Fallback also failed — real memory problem, propagate
        fprintf(stderr,
          "PBC RX: randomx_create_vm fallback ALSO bad_alloc flags=0x%x errno=%d — rethrowing\n",
          (int)fallback_flags, errno);
        fflush(stderr);
        throw;
      }
    }

    // bad_alloc without LARGE_PAGES = real memory problem, propagate
    fprintf(stderr,
      "PBC RX: randomx_create_vm bad_alloc WITHOUT LARGE_PAGES flags=0x%x — rethrowing\n",
      (int)flags);
    fflush(stderr);
    throw;
  }
}

// Safe wrapper for randomx_init_cache.
// initCache/initCacheCompile call generateSuperscalar which, on bad_alloc unwind,
// crashes via the cold path because C does not have unwind tables for C++ exceptions.
void randomx_init_cache_safe(randomx_cache* cache, const void* key, size_t keySize)
{
  try {
    randomx_init_cache(cache, key, keySize);
  }
  catch (const std::bad_alloc&) {
    fprintf(stderr,
      "PBC RX: randomx_init_cache bad_alloc — ignoring (cache may be uninitialized)\n");
    fflush(stderr);
  }
  catch (const std::exception& e) {
    fprintf(stderr,
      "PBC RX: randomx_init_cache exception: %s\n", e.what());
    fflush(stderr);
  }
  catch (...) {
    fprintf(stderr, "PBC RX: randomx_init_cache unknown exception\n");
    fflush(stderr);
  }
}

// Safe wrapper for randomx_init_dataset.
void randomx_init_dataset_safe(randomx_dataset* dataset, randomx_cache* cache,
                                unsigned long startItem, unsigned long itemCount)
{
  try {
    randomx_init_dataset(dataset, cache, startItem, itemCount);
  }
  catch (const std::bad_alloc&) {
    fprintf(stderr,
      "PBC RX: randomx_init_dataset bad_alloc start=%lu count=%lu\n",
      startItem, itemCount);
    fflush(stderr);
  }
  catch (const std::exception& e) {
    fprintf(stderr,
      "PBC RX: randomx_init_dataset exception: %s\n", e.what());
    fflush(stderr);
  }
  catch (...) {
    fprintf(stderr, "PBC RX: randomx_init_dataset unknown exception\n");
    fflush(stderr);
  }
}

} // extern "C"
