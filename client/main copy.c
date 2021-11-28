// zip.c file
#include <stdio.h>
#include <stdlib.h>
#include <zip.h>

int main(int argc, char **argv) {
struct zip *zip_file;
struct zip_file *file_in_zip;
int err;
int files_total;
int file_number;
int r;
char buffer[10000];

if (argc < 3) {
    fprintf(stderr,"usage: %s <zipfile> <fileindex>\n",argv[0]);
    return -1;
};

zip_file = zip_open(argv[1], 0, &err);
if (!zip_file) {
    fprintf(stderr,"Error: can't open file %s\n",argv[1]);
    return -1;
};

file_number = atoi(argv[2]);
files_total = zip_get_num_files(zip_file);
if (file_number > files_total) {
    printf("Error: we have only %d files in ZIP\n",files_total);
    return -1;
};

file_in_zip = zip_fopen_index(zip_file, file_number, 0);
if (file_in_zip) {
    while ( (r = zip_fread(file_in_zip, buffer, sizeof(buffer))) > 0) {
        printf("%s",buffer);
    };
    zip_fclose(file_in_zip);
} else {
    fprintf(stderr,"Error: can't open file %d in zip\n",file_number);
};

zip_close(zip_file);

return 0;
};