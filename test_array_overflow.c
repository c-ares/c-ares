#include <stdio.h>
#include <stdint.h>
#include <limits.h>

#define SIZE_MAX ((size_t)-1)
#define ARES_SUCCESS 0
#define ARES_ENOMEM 1
#define ARES_EFORMERR 2
#define ARES__ARRAY_MIN 4

typedef int ares_status_t;

typedef struct {
  void   *arr;
  size_t  member_size;
  size_t  cnt;
  size_t  alloc_cnt;
} ares_array_t;

// Mock function
size_t ares_round_up_pow2(size_t n) {
  if (n == 0) return 0;
  n--;
  n |= n >> 1;
  n |= n >> 2;
  n |= n >> 4;
  n |= n >> 8;
  n |= n >> 16;
  if (sizeof(size_t) == 8) n |= n >> 32;
  n++;
  return n;
}

ares_status_t dummy_ares_array_set_size(ares_array_t *arr, size_t size)
{
  size_t rounded_size;

  if (arr == NULL || size == 0 || size < arr->cnt) {
    return ARES_EFORMERR;
  }

  rounded_size = ares_round_up_pow2(size);
  if (size > 0 && rounded_size == 0) {
    return ARES_ENOMEM;
  }
  size = rounded_size;

  if (size < ARES__ARRAY_MIN) {
    size = ARES__ARRAY_MIN;
  }

  if (size <= arr->alloc_cnt) {
    return ARES_SUCCESS;
  }

  if (arr->member_size == 0) {
    return ARES_ENOMEM;
  }

  if (size > SIZE_MAX / arr->member_size) {
    return ARES_ENOMEM;
  }

  return ARES_SUCCESS;
}

void test(size_t member_size, size_t size, ares_status_t expected) {
  ares_array_t arr;
  arr.member_size = member_size;
  arr.alloc_cnt = 0;
  arr.cnt = 0;
  ares_status_t status = dummy_ares_array_set_size(&arr, size);
  if (status == expected) {
    printf("SUCCESS: member=%zu, size=%zu, status=%d\n", member_size, size, status);
  } else {
    printf("FAILURE: member=%zu, size=%zu, status=%d, expected=%d\n", member_size, size, status, expected);
  }
}

int main() {
  // 1. Multiplication Overflow
  test(sizeof(int), SIZE_MAX / 2, ARES_ENOMEM);
  test(1024, SIZE_MAX / 512, ARES_ENOMEM);

  // 2. Rounding Overflow
  // For 64-bit, mid-point: (SIZE_MAX/2) + 1
  size_t huge = (SIZE_MAX >> 1) + 1;
  test(1, huge, ARES_ENOMEM);

  // 3. Normal Success
  test(4, 10, ARES_SUCCESS);

  // 4. member_size == 0 guard
  test(0, 10, ARES_ENOMEM);

  return 0;
}
