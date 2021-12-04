#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
int main(void) {
  int fd = open("test_file", O_RDWR | O_CREAT, (mode_t)0600);
  const char *text = "hello world";
  char *map = mmap(0, 2056, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  memcpy(map, text, strlen(text));
  msync(map, 2056, MS_SYNC);
  munmap(map, 2056);
  close(fd);
  return 0;
}
