#include <stdio.h>
#include <stdint.h>

extern decrypt_and_call(void *stage, uint64_t *key);

void third_stage(void)
{
  printf("Third stage here...\n");
  return;
}

void second_stage(void)
{
  uint64_t n_k[] = {0x1, 0x4};
  printf("Hello World\n");
  decrypt_and_call((void *)third_stage, n_k);
  return;
}
