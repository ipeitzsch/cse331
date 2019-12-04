#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
int main() { 
  int uid = getuid();
  printf("Original uid: %d\n", uid);
  setuid(55555);
  uid = getuid();
  printf("New uid: %d\n", uid);
  return 0;
}
