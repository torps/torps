#include "generic_hash.h"

int
inthash_insert(inthash_t **map, uint32_t k1, void *data)
{
  inthash_t *elem;
  HASH_FIND_INT(*map,&k1,elem);
  if (!elem) {
    elem = (inthash_t *) malloc(sizeof(inthash_t));
    elem->key = k1;
    elem->data = data;
    HASH_ADD_INT(*map,key,elem);
  }
  else {
    if (elem->data != data)
      return LH_DUP_INSERT;
  }

  return LH_OK;
}

int
_inthash_get(inthash_t **map, uint32_t k1, void **data)
{
  inthash_t *elem;
  HASH_FIND_INT(*map,&k1,elem);

  if (!elem)
    return LH_MISSING;

  *data = elem->data;
  return LH_OK;

}

int          
inthash_remove(inthash_t **map, uint32_t k1)
{
  inthash_t *elem;
  HASH_FIND_INT(*map,&k1,elem);

  if (!elem)
    return LH_MISSING;

  HASH_DEL(*map,elem);
  free(elem);
  return LH_OK;
}

inthash_t * inthash_new()
{
  return 0;
}

void inthash_clear(inthash_t **map)
{
  inthash_t *curr, *tmp;
  HASH_ITER(hh,*map, curr, tmp) {
    HASH_DEL(*map,curr);
    free(curr);
  
  }
  *map = 0;
}
