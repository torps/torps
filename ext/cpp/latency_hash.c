#include "latency_hash.h"

void 
latency_hash_clear(latency_hash_t **map)
{
  latency_hash_t *outer_elem, *tmp;
  struct _inner *inner_elem, *tmp2;

  HASH_ITER(hh, *map, outer_elem, tmp) {
    HASH_ITER(hh,outer_elem->_inner, inner_elem,tmp2) {
      HASH_DEL(outer_elem->_inner,inner_elem);
      free(inner_elem);
    }
    HASH_DEL(*map,outer_elem);
    free(outer_elem);
  }
  *map = 0;
}

int
latency_hash_insert(latency_hash_t **map, uint32_t k1, uint32_t k2, double latency)
{
  latency_hash_t *outer_elem;
  HASH_FIND_INT(*map,&k1,outer_elem);
  if (!outer_elem) {
    outer_elem = (latency_hash_t *) malloc(sizeof(latency_hash_t));
    outer_elem->nodeidx = k1;
    outer_elem->_inner = 0;
    HASH_ADD_INT(*map,nodeidx, outer_elem);
  }

  struct _inner *inner_elem;
  HASH_FIND_INT((outer_elem->_inner),&k2, inner_elem);
  if (!inner_elem) {
    inner_elem = (struct _inner *) malloc(sizeof(struct _inner));
    inner_elem->nodeidx = k2;
    inner_elem->latency = latency;
    HASH_ADD_INT((outer_elem->_inner),nodeidx,inner_elem);
  }
  else {
    if (inner_elem->latency != latency)
      return LH_DUP_INSERT;
  }

  return LH_OK;
}

int
latency_hash_get(latency_hash_t **map, uint32_t k1, uint32_t k2, double *latency)
{
  latency_hash_t *outer_elem;
  HASH_FIND_INT(*map,&k1,outer_elem);
  if (!outer_elem) 
    return LH_MISSING;

  struct _inner *inner_elem;
  HASH_FIND_INT((outer_elem->_inner),&k2, inner_elem);
  if (!inner_elem) 
    return LH_MISSING;

  *latency = inner_elem->latency;
  return LH_OK;
}

int latency_hash_remove(latency_hash_t **map, uint32_t k1, uint32_t k2)
{
  latency_hash_t *outer_elem;
  HASH_FIND_INT(*map,&k1,outer_elem);
  if (!outer_elem) 
    return LH_MISSING;

  struct _inner *inner_elem;
  HASH_FIND_INT((outer_elem->_inner),&k2, inner_elem);
  if (!inner_elem) 
    return LH_MISSING;

  HASH_DEL((outer_elem->_inner),inner_elem);
  free(inner_elem);

  if (HASH_COUNT((outer_elem->_inner)) == 0) {
    HASH_DEL(*map,outer_elem);
    free(outer_elem);
  }
  return LH_OK;
}

latency_hash_t *
latency_hash_new()
{
  return 0;
}
