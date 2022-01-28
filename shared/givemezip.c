#include "givemezip.h"
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/dir.h>
#include "misc.h"
int giveme_zip_directory(const char *input_dir, const char *output_dir)
{
    int errorp;
    zip_t *zipper = zip_open(output_dir, ZIP_CREATE | ZIP_EXCL, &errorp);
    if (zipper == NULL)
    {
        zip_error_t ziperror;
        zip_error_init_with_code(&ziperror, errorp);
        return -1;
    }

    int res = giveme_walk_directory(input_dir, input_dir, zipper);
    if (res == -1)
    {
        zip_close(zipper);
        return -1;
    }

    zip_close(zipper);
    return 0;
}

bool giveme_is_dir(const char *dir)
{
    struct stat st;
    stat(dir, &st);
    return S_ISDIR(st.st_mode);
}

int giveme_walk_directory(const char *start_dir, const char *input_dir, zip_t *zipper)
{
    DIR *dp = opendir(input_dir);
    if (dp == NULL)
    {
        return -1;
    }

    struct dirent *dirp;
    while ((dirp = readdir(dp)) != NULL)
    {
        if (!S_EQ(dirp->d_name, ".") && !S_EQ(dirp->d_name, ".."))
        {
            char fullname[PATH_MAX];
            sprintf(fullname, "%s/%s", input_dir, dirp->d_name);
            if (giveme_is_dir(fullname))
            {
                if (zip_dir_add(zipper, fullname, ZIP_FL_ENC_UTF_8) < 0)
                {
                    return -1;
                }
                giveme_walk_directory(start_dir, fullname, zipper);
            }
            else
            {
                zip_source_t *source = zip_source_file(zipper, fullname, 0, 0);
                if (source == NULL)
                {
                    return -1;
                }
                if (zip_file_add(zipper, fullname, source, ZIP_FL_ENC_UTF_8) < 0)
                {

                    zip_source_free(source);
                    return -1;
                }
            }
        }
    }
    closedir(dp);
}

int giveme_unzip_directory(const char *zip_filename, const char *output_dir)
{
    int errorp;
    zip_t *zipper = zip_open(zip_filename, 0, &errorp);
    if (!zipper)
    {
        zip_error_t ziperror;
        zip_error_init_with_code(&ziperror, errorp);
        return -1;
    }

    zip_int64_t num_entries = zip_get_num_entries(zipper, 0);
    for (zip_uint64_t i = 0; i < num_entries; i++)
    {
        const char *name = zip_get_name(zipper, i, 0);
        printf("Extracting file %s\n", name);
    }
    zip_close(zipper);
    return 0;
}
