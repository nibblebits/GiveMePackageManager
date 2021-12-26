#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <zip.h>
#include "config.h"
#include "misc.h"
#include "sha256.h"
#include "network.h"
#include "log.h"
static bool is_dir(const char *dir)
{
    struct stat st;
    stat(dir, &st);
    return S_ISDIR(st.st_mode);
}

static int walk_directory(const char *start_dir, const char *input_dir, zip_t *zipper)
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
            if (is_dir(fullname))
            {
                if (zip_dir_add(zipper, fullname, ZIP_FL_ENC_UTF_8) < 0)
                {
                    return -1;
                }
                walk_directory(start_dir, fullname, zipper);
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

static int zip_directory(const char *input_dir, const char *output_dir)
{
    int errorp;
    zip_t *zipper = zip_open(output_dir, ZIP_CREATE | ZIP_EXCL, &errorp);
    if (zipper == NULL)
    {
        zip_error_t ziperror;
        zip_error_init_with_code(&ziperror, errorp);
        return -1;
    }

    int res = walk_directory(input_dir, input_dir, zipper);
    if (res == -1)
    {
        zip_close(zipper);
        return -1;
    }

    zip_close(zipper);
    return 0;
}

int giveme_package_create(const char *path, const char *package_name)
{
    int res = 0;
    char dst_path[PATH_MAX];
    sprintf(dst_path, "%s/%s/%s.zip",getenv(GIVEME_DATA_BASE_DIRECTORY_ENV), GIVEME_PACKAGE_DIRECTORY, package_name);
    char sha_buf[SHA256_STRING_LENGTH];

    res = zip_directory(path, dst_path);
    if (res < 0)
    {
        return res;
    }

    res = sha256_file(dst_path, sha_buf);
    if (res < 0)
    {
        return res;
    }
    
    char dst_path_hashed[PATH_MAX];
    sprintf(dst_path_hashed, "%s/%s/%s",getenv(GIVEME_DATA_BASE_DIRECTORY_ENV), GIVEME_PACKAGE_DIRECTORY, sha_buf);
    res = rename(dst_path, dst_path_hashed);
    if (res < 0)
    {
        return res;
    }

    struct giveme_tcp_packet packet = {};
    packet.data.type = GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PACKAGE;
    strncpy(packet.data.publish_package.data.name, package_name, sizeof(packet.data.publish_package.data.name));
    sha256_file(dst_path_hashed, packet.data.publish_package.data.filehash);

    char tmp_hash[SHA256_STRING_LENGTH];
    sha256_data(&packet.data.publish_package.data, tmp_hash, sizeof(tmp_hash));    
    // We must sign the data
    res = private_sign_key_sig_hash(&packet.data.publish_package.signature, tmp_hash);
    if (res < 0)
    {
        giveme_log("%s failed to sign the packet publish data with private key\n", __FUNCTION__);
        
        return res;
    }
    // We should sign the data.
    giveme_network_broadcast(&packet);
    
    return res;

}