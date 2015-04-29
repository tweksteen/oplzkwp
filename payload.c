#include <stdio.h>
#include <stdint.h>

extern decrypt_and_call(void *);

void third_stage(void) __attribute__((aligned(0x1000)));
void second_stage(void) __attribute__((aligned(0x1000)));

void third_stage(void)
{
  printf("Third stage here...\n");
  return;
}

void second_stage(void)
{
  uint64_t n_k[] = {0x1, 0x4};
  printf("Hello World\n");
  printf("Another one\n");
  decrypt_and_call(third_stage);
  return;
}

int main(void)
{
  decrypt_and_call(second_stage);
  return 0;
}
