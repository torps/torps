#ifndef LATENCY_HASH_H_XU5DCAZ7
#define LATENCY_HASH_H_XU5DCAZ7



#include "lib/uthash/uthash.h"

struct _inner {
  uint32_t nodeidx;
  double latency;
  UT_hash_handle hh;
};

typedef struct _outer {
  uint32_t nodeidx;
  struct _inner *_inner;

  UT_hash_handle hh;
} latency_hash_t;

#define LH_OK 0x0
#define LH_DUP_INSERT 0x1
#define LH_MISSING 0x2

int
latency_hash_insert(latency_hash_t **map, uint32_t k1, uint32_t k2, double latency);

int
latency_hash_get(latency_hash_t **map, uint32_t k1, uint32_t k2, double *latency);

int
latency_hash_remove(latency_hash_t **map, uint32_t k1, uint32_t k2);

latency_hash_t *
latency_hash_new();

void latency_hash_clear(latency_hash_t **map);

#endif /* end of include guard: LATENCY_HASH_H_XU5DCAZ7 */
