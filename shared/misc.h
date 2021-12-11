#ifndef MISC_H
#define MISC_H
#include <string.h>
#include <stdbool.h>
#define NO_THREAD_SAFETY 
#define USES_LOCKS

#define S_EQ(s1, s2) \
    (s1 && s2 && strcmp(s1, s2) == 0)

bool file_exists(const char *filename);

#endif