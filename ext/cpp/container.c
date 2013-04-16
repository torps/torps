/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file container.c
 * \brief Implements a smartlist (a resizable array) along
 * with helper functions to use smartlists.  Also includes
 * hash table implementations of a string-to-void* map, and of
 * a digest-to-void* map.
 **/

/*#include "compat.h"*/
/*#include "util.h"*/
/*#include "torlog.h"*/
#include "container.h"
#include "tor_stubs.h"
/*#include "crypto.h"*/

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ht.h"

/** All newly allocated smartlists have this capacity. */
#define SMARTLIST_DEFAULT_CAPACITY 16


/** Allocate and return an empty smartlist.
 */
smartlist_t *
smartlist_new(void)
{
  smartlist_t *sl = (smartlist_t *)tor_malloc(sizeof(smartlist_t));
  sl->num_used = 0;
  sl->capacity = SMARTLIST_DEFAULT_CAPACITY;
  sl->list = (void **)tor_malloc(sizeof(void *) * sl->capacity);
  return sl;
}

/** Deallocate a smartlist.  Does not release storage associated with the
 * list's elements.
 */
void
smartlist_free(smartlist_t *sl)
{
  if (!sl)
    return;
  tor_free(sl->list);
  tor_free(sl);
}

/** Remove all elements from the list.
 */
void
smartlist_clear(smartlist_t *sl)
{
  sl->num_used = 0;
}

/** Make sure that <b>sl</b> can hold at least <b>size</b> entries. */
static inline void
smartlist_ensure_capacity(smartlist_t *sl, int size)
{
/*#if SIZEOF_SIZE_T > SIZEOF_INT*/
#define MAX_CAPACITY (INT_MAX)
/*#else*/
/*#define MAX_CAPACITY (uint64_t)((SIZE_MAX / (sizeof(void*))))*/
/*#endif*/
  if (size > sl->capacity) {
    int higher = sl->capacity;
    if (PREDICT_UNLIKELY((uint64_t)size > MAX_CAPACITY/2)) {
      assert(size <= MAX_CAPACITY);
      higher = MAX_CAPACITY;
    } else {
      while (size > higher)
        higher *= 2;
    }
    sl->capacity = higher;
    sl->list = (void **) realloc(sl->list, sizeof(void*)*((size_t)sl->capacity));
  }
}

/** Append element to the end of the list. */
void
smartlist_add(smartlist_t *sl, void *element)
{
  smartlist_ensure_capacity(sl, sl->num_used+1);
  sl->list[sl->num_used++] = element;
}

/** Append each element from S2 to the end of S1. */
void
smartlist_add_all(smartlist_t *s1, const smartlist_t *s2)
{
  int new_size = s1->num_used + s2->num_used;
  assert(new_size >= s1->num_used); /* check for overflow. */
  smartlist_ensure_capacity(s1, new_size);
  memcpy(s1->list + s1->num_used, s2->list, s2->num_used*sizeof(void*));
  s1->num_used = new_size;
}

/** Remove all elements E from sl such that E==element.  Preserve
 * the order of any elements before E, but elements after E can be
 * rearranged.
 */
void
smartlist_remove(smartlist_t *sl, const void *element)
{
  int i;
  if (element == NULL)
    return;
  for (i=0; i < sl->num_used; i++)
    if (sl->list[i] == element) {
      sl->list[i] = sl->list[--sl->num_used]; /* swap with the end */
      i--; /* so we process the new i'th element */
    }
}

/** If <b>sl</b> is nonempty, remove and return the final element.  Otherwise,
 * return NULL. */
void *
smartlist_pop_last(smartlist_t *sl)
{
  assert(sl);
  if (sl->num_used)
    return sl->list[--sl->num_used];
  else
    return NULL;
}

/** Reverse the order of the items in <b>sl</b>. */
void
smartlist_reverse(smartlist_t *sl)
{
  int i, j;
  void *tmp;
  assert(sl);
  for (i = 0, j = sl->num_used-1; i < j; ++i, --j) {
    tmp = sl->list[i];
    sl->list[i] = sl->list[j];
    sl->list[j] = tmp;
  }
}

/** If there are any strings in sl equal to element, remove and free them.
 * Does not preserve order. */
void
smartlist_string_remove(smartlist_t *sl, const char *element)
{
  int i;
  assert(sl);
  assert(element);
  for (i = 0; i < sl->num_used; ++i) {
    if (!strcmp(element, (const char *)sl->list[i])) {
      tor_free(sl->list[i]);
      sl->list[i] = sl->list[--sl->num_used]; /* swap with the end */
      i--; /* so we process the new i'th element */
    }
  }
}

/** Return true iff some element E of sl has E==element.
 */
int
smartlist_isin(const smartlist_t *sl, const void *element)
{
  int i;
  for (i=0; i < sl->num_used; i++)
    if (sl->list[i] == element)
      return 1;
  return 0;
}

/** Return true iff <b>sl</b> has some element E such that
 * !strcmp(E,<b>element</b>)
 */
int
smartlist_string_isin(const smartlist_t *sl, const char *element)
{
  int i;
  if (!sl) return 0;
  for (i=0; i < sl->num_used; i++)
    if (strcmp((const char*)sl->list[i],element)==0)
      return 1;
  return 0;
}

/** If <b>element</b> is equal to an element of <b>sl</b>, return that
 * element's index.  Otherwise, return -1. */
int
smartlist_string_pos(const smartlist_t *sl, const char *element)
{
  int i;
  if (!sl) return -1;
  for (i=0; i < sl->num_used; i++)
    if (strcmp((const char*)sl->list[i],element)==0)
      return i;
  return -1;
}

/** Return true iff <b>sl</b> has some element E such that
 * !strcasecmp(E,<b>element</b>)
 */
int
smartlist_string_isin_case(const smartlist_t *sl, const char *element)
{
  int i;
  if (!sl) return 0;
  for (i=0; i < sl->num_used; i++)
    if (strcasecmp((const char*)sl->list[i],element)==0)
      return 1;
  return 0;
}

/** Return true iff <b>sl</b> has some element E such that E is equal
 * to the decimal encoding of <b>num</b>.
 */
int
smartlist_string_num_isin(const smartlist_t *sl, int num)
{
  char buf[32]; /* long enough for 64-bit int, and then some. */
  snprintf(buf,sizeof(buf),"%d", num);
  return smartlist_string_isin(sl, buf);
}

/** Return true iff the two lists contain the same strings in the same
 * order, or if they are both NULL. */
int
smartlist_strings_eq(const smartlist_t *sl1, const smartlist_t *sl2)
{
  if (sl1 == NULL)
    return sl2 == NULL;
  if (sl2 == NULL)
    return 0;
  if (smartlist_len(sl1) != smartlist_len(sl2))
    return 0;
  SMARTLIST_FOREACH(sl1, const char *, cp1, {
      const char *cp2 = (const char *)smartlist_get(sl2, cp1_sl_idx);
      if (strcmp(cp1, cp2))
        return 0;
    });
  return 1;
}

/** Return true iff some element E of sl2 has smartlist_isin(sl1,E).
 */
int
smartlist_overlap(const smartlist_t *sl1, const smartlist_t *sl2)
{
  int i;
  for (i=0; i < sl2->num_used; i++)
    if (smartlist_isin(sl1, sl2->list[i]))
      return 1;
  return 0;
}

/** Remove every element E of sl1 such that !smartlist_isin(sl2,E).
 * Does not preserve the order of sl1.
 */
void
smartlist_intersect(smartlist_t *sl1, const smartlist_t *sl2)
{
  int i;
  for (i=0; i < sl1->num_used; i++)
    if (!smartlist_isin(sl2, sl1->list[i])) {
      sl1->list[i] = sl1->list[--sl1->num_used]; /* swap with the end */
      i--; /* so we process the new i'th element */
    }
}

/** Remove every element E of sl1 such that smartlist_isin(sl2,E).
 * Does not preserve the order of sl1.
 */
void
smartlist_subtract(smartlist_t *sl1, const smartlist_t *sl2)
{
  int i;
  for (i=0; i < sl2->num_used; i++)
    smartlist_remove(sl1, sl2->list[i]);
}

/** Remove the <b>idx</b>th element of sl; if idx is not the last
 * element, swap the last element of sl into the <b>idx</b>th space.
 */
void
smartlist_del(smartlist_t *sl, int idx)
{
  assert(sl);
  assert(idx>=0);
  assert(idx < sl->num_used);
  sl->list[idx] = sl->list[--sl->num_used];
}

/** Remove the <b>idx</b>th element of sl; if idx is not the last element,
 * moving all subsequent elements back one space. Return the old value
 * of the <b>idx</b>th element.
 */
void
smartlist_del_keeporder(smartlist_t *sl, int idx)
{
  assert(sl);
  assert(idx>=0);
  assert(idx < sl->num_used);
  --sl->num_used;
  if (idx < sl->num_used)
    memmove(sl->list+idx, sl->list+idx+1, sizeof(void*)*(sl->num_used-idx));
}

/** Insert the value <b>val</b> as the new <b>idx</b>th element of
 * <b>sl</b>, moving all items previously at <b>idx</b> or later
 * forward one space.
 */
void
smartlist_insert(smartlist_t *sl, int idx, void *val)
{
  assert(sl);
  assert(idx>=0);
  assert(idx <= sl->num_used);
  if (idx == sl->num_used) {
    smartlist_add(sl, val);
  } else {
    smartlist_ensure_capacity(sl, sl->num_used+1);
    /* Move other elements away */
    if (idx < sl->num_used)
      memmove(sl->list + idx + 1, sl->list + idx,
              sizeof(void*)*(sl->num_used-idx));
    sl->num_used++;
    sl->list[idx] = val;
  }
}

/** Sort the members of <b>sl</b> into an order defined by
 * the ordering function <b>compare</b>, which returns less then 0 if a
 * precedes b, greater than 0 if b precedes a, and 0 if a 'equals' b.
 */
void
smartlist_sort(smartlist_t *sl, int (*compare)(const void **a, const void **b))
{
  if (!sl->num_used)
    return;
  qsort(sl->list, sl->num_used, sizeof(void*),
        (int (*)(const void *,const void*))compare);
}

/** Given a smartlist <b>sl</b> sorted with the function <b>compare</b>,
 * return the most frequent member in the list.  Break ties in favor of
 * later elements.  If the list is empty, return NULL.
 */
void *
smartlist_get_most_frequent(const smartlist_t *sl,
                            int (*compare)(const void **a, const void **b))
{
  const void *most_frequent = NULL;
  int most_frequent_count = 0;

  const void *cur = NULL;
  int i, count=0;

  if (!sl->num_used)
    return NULL;
  for (i = 0; i < sl->num_used; ++i) {
    const void *item = sl->list[i];
    if (cur && 0 == compare(&cur, &item)) {
      ++count;
    } else {
      if (cur && count >= most_frequent_count) {
        most_frequent = cur;
        most_frequent_count = count;
      }
      cur = item;
      count = 1;
    }
  }
  if (cur && count >= most_frequent_count) {
    most_frequent = cur;
    most_frequent_count = count;
  }
  return (void*)most_frequent;
}

/** Given a sorted smartlist <b>sl</b> and the comparison function used to
 * sort it, remove all duplicate members.  If free_fn is provided, calls
 * free_fn on each duplicate.  Otherwise, just removes them.  Preserves order.
 */
void
smartlist_uniq(smartlist_t *sl,
               int (*compare)(const void **a, const void **b),
               void (*free_fn)(void *a))
{
  int i;
  for (i=1; i < sl->num_used; ++i) {
    if (compare((const void **)&(sl->list[i-1]),
                (const void **)&(sl->list[i])) == 0) {
      if (free_fn)
        free_fn(sl->list[i]);
      smartlist_del_keeporder(sl, i--);
    }
  }
}

/** Assuming the members of <b>sl</b> are in order, return a pointer to the
 * member that matches <b>key</b>.  Ordering and matching are defined by a
 * <b>compare</b> function that returns 0 on a match; less than 0 if key is
 * less than member, and greater than 0 if key is greater then member.
 */
void *
smartlist_bsearch(smartlist_t *sl, const void *key,
                  int (*compare)(const void *key, const void **member))
{
  int found, idx;
  idx = smartlist_bsearch_idx(sl, key, compare, &found);
  return found ? smartlist_get(sl, idx) : NULL;
}

/** Assuming the members of <b>sl</b> are in order, return the index of the
 * member that matches <b>key</b>.  If no member matches, return the index of
 * the first member greater than <b>key</b>, or smartlist_len(sl) if no member
 * is greater than <b>key</b>.  Set <b>found_out</b> to true on a match, to
 * false otherwise.  Ordering and matching are defined by a <b>compare</b>
 * function that returns 0 on a match; less than 0 if key is less than member,
 * and greater than 0 if key is greater then member.
 */
int
smartlist_bsearch_idx(const smartlist_t *sl, const void *key,
                      int (*compare)(const void *key, const void **member),
                      int *found_out)
{
  const int len = smartlist_len(sl);
  int hi, lo, cmp, mid;

  if (len == 0) {
    *found_out = 0;
    return 0;
  } else if (len == 1) {
    cmp = compare(key, (const void **) &sl->list[0]);
    if (cmp == 0) {
      *found_out = 1;
      return 0;
    } else if (cmp < 0) {
      *found_out = 0;
      return 0;
    } else {
      *found_out = 0;
      return 1;
    }
  }

  hi = smartlist_len(sl) - 1;
  lo = 0;

  while (lo <= hi) {
    mid = (lo + hi) / 2;
    cmp = compare(key, (const void**) &(sl->list[mid]));
    if (cmp>0) { /* key > sl[mid] */
      lo = mid+1;
    } else if (cmp<0) { /* key < sl[mid] */
      hi = mid-1;
    } else { /* key == sl[mid] */
      *found_out = 1;
      return mid;
    }
  }
  /* lo > hi. */
  {
    assert(lo >= 0);
    if (lo < smartlist_len(sl)) {
      cmp = compare(key, (const void**) &(sl->list[lo]));
      assert(cmp < 0);
    } else if (smartlist_len(sl)) {
      cmp = compare(key, (const void**) &(sl->list[smartlist_len(sl)-1]));
      assert(cmp > 0);
    }
  }
  *found_out = 0;
  return lo;
}

/** Helper: compare two const char **s. */
static int
_compare_string_ptrs(const void **_a, const void **_b)
{
  return strcmp((const char*)*_a, (const char*)*_b);
}

/** Sort a smartlist <b>sl</b> containing strings into lexically ascending
 * order. */
void
smartlist_sort_strings(smartlist_t *sl)
{
  smartlist_sort(sl, _compare_string_ptrs);
}

/** Return the most frequent string in the sorted list <b>sl</b> */
char *
smartlist_get_most_frequent_string(smartlist_t *sl)
{
  return (char *)smartlist_get_most_frequent(sl, _compare_string_ptrs);
}

/** Remove duplicate strings from a sorted list, and free them with tor_free().
 */
void
smartlist_uniq_strings(smartlist_t *sl)
{
  smartlist_uniq(sl, _compare_string_ptrs, _tor_free);
}

/* Heap-based priority queue implementation for O(lg N) insert and remove.
 * Recall that the heap property is that, for every index I, h[I] <
 * H[LEFT_CHILD[I]] and h[I] < H[RIGHT_CHILD[I]].
 *
 * For us to remove items other than the topmost item, each item must store
 * its own index within the heap.  When calling the pqueue functions, tell
 * them about the offset of the field that stores the index within the item.
 *
 * Example:
 *
 *   typedef struct timer_t {
 *     struct timeval tv;
 *     int heap_index;
 *   } timer_t;
 *
 *   static int compare(const void *p1, const void *p2) {
 *     const timer_t *t1 = p1, *t2 = p2;
 *     if (t1->tv.tv_sec < t2->tv.tv_sec) {
 *        return -1;
 *     } else if (t1->tv.tv_sec > t2->tv.tv_sec) {
 *        return 1;
 *     } else {
 *        return t1->tv.tv_usec - t2->tv_usec;
 *     }
 *   }
 *
 *   void timer_heap_insert(smartlist_t *heap, timer_t *timer) {
 *      smartlist_pqueue_add(heap, compare, STRUCT_OFFSET(timer_t, heap_index),
 *         timer);
 *   }
 *
 *   void timer_heap_pop(smartlist_t *heap) {
 *      return smartlist_pqueue_pop(heap, compare,
 *         STRUCT_OFFSET(timer_t, heap_index));
 *   }
 */

/** @{ */
/** Functions to manipulate heap indices to find a node's parent and children.
 *
 * For a 1-indexed array, we would use LEFT_CHILD[x] = 2*x and RIGHT_CHILD[x]
 *   = 2*x + 1.  But this is C, so we have to adjust a little. */
//#define LEFT_CHILD(i)  ( ((i)+1)*2 - 1)
//#define RIGHT_CHILD(i) ( ((i)+1)*2 )
//#define PARENT(i)      ( ((i)+1)/2 - 1)
#define LEFT_CHILD(i)  ( 2*(i) + 1 )
#define RIGHT_CHILD(i) ( 2*(i) + 2 )
#define PARENT(i)      ( ((i)-1) / 2 )
/** }@ */

/** @{ */
/** Helper macros for heaps: Given a local variable <b>idx_field_offset</b>
 * set to the offset of an integer index within the heap element structure,
 * IDX_OF_ITEM(p) gives you the index of p, and IDXP(p) gives you a pointer to
 * where p's index is stored.  Given additionally a local smartlist <b>sl</b>,
 * UPDATE_IDX(i) sets the index of the element at <b>i</b> to the correct
 * value (that is, to <b>i</b>).
 */
#define IDXP(p) ((int*)STRUCT_VAR_P(p, idx_field_offset))

#define UPDATE_IDX(i)  do {                            \
    void *updated = sl->list[i];                       \
    *IDXP(updated) = i;                                \
  } while (0)

#define IDX_OF_ITEM(p) (*IDXP(p))
/** @} */

/** Helper. <b>sl</b> may have at most one violation of the heap property:
 * the item at <b>idx</b> may be greater than one or both of its children.
 * Restore the heap property. */
static inline void
smartlist_heapify(smartlist_t *sl,
                  int (*compare)(const void *a, const void *b),
                  int idx_field_offset,
                  int idx)
{
  while (1) {
    int left_idx = LEFT_CHILD(idx);
    int best_idx;

    if (left_idx >= sl->num_used)
      return;
    if (compare(sl->list[idx],sl->list[left_idx]) < 0)
      best_idx = idx;
    else
      best_idx = left_idx;
    if (left_idx+1 < sl->num_used &&
        compare(sl->list[left_idx+1],sl->list[best_idx]) < 0)
      best_idx = left_idx + 1;

    if (best_idx == idx) {
      return;
    } else {
      void *tmp = sl->list[idx];
      sl->list[idx] = sl->list[best_idx];
      sl->list[best_idx] = tmp;
      UPDATE_IDX(idx);
      UPDATE_IDX(best_idx);

      idx = best_idx;
    }
  }
}

/** Insert <b>item</b> into the heap stored in <b>sl</b>, where order is
 * determined by <b>compare</b> and the offset of the item in the heap is
 * stored in an int-typed field at position <b>idx_field_offset</b> within
 * item.
 */
void
smartlist_pqueue_add(smartlist_t *sl,
                     int (*compare)(const void *a, const void *b),
                     int idx_field_offset,
                     void *item)
{
  int idx;
  smartlist_add(sl,item);
  UPDATE_IDX(sl->num_used-1);

  for (idx = sl->num_used - 1; idx; ) {
    int parent = PARENT(idx);
    if (compare(sl->list[idx], sl->list[parent]) < 0) {
      void *tmp = sl->list[parent];
      sl->list[parent] = sl->list[idx];
      sl->list[idx] = tmp;
      UPDATE_IDX(parent);
      UPDATE_IDX(idx);
      idx = parent;
    } else {
      return;
    }
  }
}

/** Remove and return the top-priority item from the heap stored in <b>sl</b>,
 * where order is determined by <b>compare</b> and the item's position is
 * stored at position <b>idx_field_offset</b> within the item.  <b>sl</b> must
 * not be empty. */
void *
smartlist_pqueue_pop(smartlist_t *sl,
                     int (*compare)(const void *a, const void *b),
                     int idx_field_offset)
{
  void *top;
  assert(sl->num_used);

  top = sl->list[0];
  *IDXP(top)=-1;
  if (--sl->num_used) {
    sl->list[0] = sl->list[sl->num_used];
    UPDATE_IDX(0);
    smartlist_heapify(sl, compare, idx_field_offset, 0);
  }
  return top;
}

/** Remove the item <b>item</b> from the heap stored in <b>sl</b>,
 * where order is determined by <b>compare</b> and the item's position is
 * stored at position <b>idx_field_offset</b> within the item.  <b>sl</b> must
 * not be empty. */
void
smartlist_pqueue_remove(smartlist_t *sl,
                        int (*compare)(const void *a, const void *b),
                        int idx_field_offset,
                        void *item)
{
  int idx = IDX_OF_ITEM(item);
  assert(idx >= 0);
  assert(sl->list[idx] == item);
  --sl->num_used;
  *IDXP(item) = -1;
  if (idx == sl->num_used) {
    return;
  } else {
    sl->list[idx] = sl->list[sl->num_used];
    UPDATE_IDX(idx);
    smartlist_heapify(sl, compare, idx_field_offset, idx);
  }
}

/** Assert that the heap property is correctly maintained by the heap stored
 * in <b>sl</b>, where order is determined by <b>compare</b>. */
void
smartlist_pqueue_assert_ok(smartlist_t *sl,
                           int (*compare)(const void *a, const void *b),
                           int idx_field_offset)
{
  int i;
  for (i = sl->num_used - 1; i >= 0; --i) {
    if (i>0)
      assert(compare(sl->list[PARENT(i)], sl->list[i]) <= 0);
    assert(IDX_OF_ITEM(sl->list[i]) == i);
  }
}


/** Declare a function called <b>funcname</b> that acts as a find_nth_FOO
 * function for an array of type <b>elt_t</b>*.
 *
 * NOTE: The implementation kind of sucks: It's O(n log n), whereas finding
 * the kth element of an n-element list can be done in O(n).  Then again, this
 * implementation is not in critical path, and it is obviously correct. */
#define IMPLEMENT_ORDER_FUNC(funcname, elt_t)                   \
  static int                                                    \
  _cmp_ ## elt_t(const void *_a, const void *_b)                \
  {                                                             \
    const elt_t *a = (elt_t *)_a, *b = (elt_t *)_b;                               \
    if (*a<*b)                                                  \
      return -1;                                                \
    else if (*a>*b)                                             \
      return 1;                                                 \
    else                                                        \
      return 0;                                                 \
  }                                                             \
  elt_t                                                         \
  funcname(elt_t *array, int n_elements, int nth)               \
  {                                                             \
    assert(nth >= 0);                                       \
    assert(nth < n_elements);                               \
    qsort(array, n_elements, sizeof(elt_t), _cmp_ ##elt_t);     \
    return array[nth];                                          \
  }

IMPLEMENT_ORDER_FUNC(find_nth_int, int)
IMPLEMENT_ORDER_FUNC(find_nth_time, time_t)
IMPLEMENT_ORDER_FUNC(find_nth_double, double)
IMPLEMENT_ORDER_FUNC(find_nth_uint32, uint32_t)
IMPLEMENT_ORDER_FUNC(find_nth_int32, int32_t)
IMPLEMENT_ORDER_FUNC(find_nth_long, long)

