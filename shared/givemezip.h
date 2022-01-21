#ifndef GIVEMEZIP_H
#define GIVEMEZIP_H
#include <zip.h>
#include <stdbool.h>
#include "givemezip.h"
int giveme_zip_directory(const char *input_dir, const char *output_dir);
bool giveme_is_dir(const char *dir);
int giveme_walk_directory(const char *start_dir, const char *input_dir, zip_t *zipper);
int giveme_unzip_directory(const char* zip_filename, const char* output_dir);

#endif