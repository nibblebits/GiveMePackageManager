#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
bool file_exists(const char *filename)
{
    bool exists = false;
    FILE *fp = fopen(filename, "r");
    if (fp)
    {
        exists = true;
        fclose(fp);
    }
    return exists;
}