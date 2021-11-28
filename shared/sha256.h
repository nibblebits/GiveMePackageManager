#ifndef GIVEME_SHA256
#define GIVEME_SHA256

#define SHA256_STRING_LENGTH 65
void sha256_string(char *string, char* outputBuffer);
int sha256_file(char *path, char* outputBuffer);

#endif
