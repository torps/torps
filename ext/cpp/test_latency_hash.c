#include "latency_hash.h"
#include "generic_hash.h"
#include "basic_test.h"

void test_latency_hash()
{
  int rc;
  latency_hash_t *map = latency_hash_new();

  rc = latency_hash_insert(&map,4,5,20.0);
  ASSERT_EQUALS(rc, LH_OK);

  rc = latency_hash_insert(&map,4,5,21.0);
  ASSERT_EQUALS(rc,LH_DUP_INSERT);

  rc = latency_hash_insert(&map,3,5,0.0);
  ASSERT_EQUALS(rc, LH_OK);

  double val;
  rc = latency_hash_get(&map,3,5, &val);
  ASSERT_EQUALS(rc, LH_OK);
  ASSERT_EQUALS(val, 0.0);

  rc = latency_hash_get(&map,4,5, &val);
  ASSERT_EQUALS(rc, LH_OK);
  ASSERT_EQUALS(val, 20.0);

  rc = latency_hash_get(&map,10,5, &val);
  ASSERT_EQUALS(rc, LH_MISSING);

  rc = latency_hash_remove(&map,10,5);
  ASSERT_EQUALS(rc, LH_MISSING);

  rc = latency_hash_remove(&map,4,5);
  ASSERT_EQUALS(rc, LH_OK);
  rc = latency_hash_get(&map,4,5, &val);
  ASSERT_EQUALS(rc, LH_MISSING);

  latency_hash_clear(&map);
  ASSERT_EQUALS(map, 0);
}

void
test_inthash() 
{
  inthash_t *map = inthash_new();
  int rc;

  int *a, *b;
  a = (int *)malloc(sizeof(int));
  b = (int *)malloc(sizeof(int));

  rc = inthash_insert(&map,4,a);
  ASSERT_EQUALS(rc, LH_OK);

  rc = inthash_insert(&map,4,a);
  ASSERT_EQUALS(rc, LH_OK);

  rc = inthash_insert(&map,4,b);
  ASSERT_EQUALS(rc,LH_DUP_INSERT);

  rc = inthash_insert(&map,5,b);
  ASSERT_EQUALS(rc,LH_OK);

  int * val;
  rc = inthash_get(&map,5, &val);
  ASSERT_EQUALS(rc, LH_OK);
  ASSERT_EQUALS(val, b);

  rc = inthash_get(&map,4, &val);
  ASSERT_EQUALS(rc, LH_OK);
  ASSERT_EQUALS(val, a);

  rc = inthash_get(&map,10,&val);
  ASSERT_EQUALS(rc, LH_MISSING);

  rc = inthash_remove(&map,10);
  ASSERT_EQUALS(rc, LH_MISSING);

  rc = inthash_remove(&map,4);
  ASSERT_EQUALS(rc, LH_OK);
  rc = inthash_get(&map,4,&val);
  ASSERT_EQUALS(rc, LH_MISSING);

  inthash_clear(&map);
  ASSERT_EQUALS(map, 0);

  free(a);
  free(b);
}

int main(int argc, char const *argv[])
{

  test_latency_hash();
  test_inthash();
  printf("\n");
  /* code */;
  return 0;
}
