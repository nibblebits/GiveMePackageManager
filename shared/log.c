#include <stdarg.h>
#include <stdio.h>
int giveme_log(const char* message, ...)
{
    va_list args;
    va_start(args, message);
    vfprintf(stdout, message, args);
    va_end(args);
}