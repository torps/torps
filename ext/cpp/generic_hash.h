#ifndef GENERIC_HASH_H_2SLCZHZB
#define GENERIC_HASH_H_2SLCZHZB

#include "lib/uthash/uthash.h"
#include "latency_hash.h"

typedef struct {
  uint32_t key;
  void * data;
  
  UT_hash_handle hh;
} inthash_t;

int
inthash_insert(inthash_t **map, uint32_t k1, void * data);

#define inthash_get(map,key,val) _inthash_get((map),(key),(void **)(val))
int
_inthash_get(inthash_t **map, uint32_t k1, void **inthash);

int
inthash_remove(inthash_t **map, uint32_t k1);

inthash_t * inthash_new();
void inthash_clear(inthash_t **map);

#endif /* end of include guard: GENERIC_HASH_H_2SLCZHZB */
