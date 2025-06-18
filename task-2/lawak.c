#define FUSE_USE_VERSION 28

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <stdint.h>
#include <libgen.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#define MAX_PATH 4096
#define CONFIG_FILE "lawak.conf"
#define LOG_FILE "/var/log/lawakfs.log"

static const char *source_dir = "/home/ubuntu/Downloads";
static char secret_basename[128] = "secret";
static int access_start_hour = 8;
static int access_end_hour = 18;
#define MAX_FILTERS 64
static char *filter_words[MAX_FILTERS];
static int filter_count = 0;

void log_action(const char *action, const char *path) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    uid_t uid = getuid();
    fprintf(log, "[%04d-%02d-%02d %02d:%02d:%02d] [%d] [%s] [%s]\n",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec,
            uid, action, path);
    fclose(log);
}

void trim(char *str) {
    char *end;
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) return;
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
}

void load_config(const char *config_path) {
    FILE *f = fopen(config_path, "r");
    if (!f) return;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "FILTER_WORDS=", 13) == 0) {
            char *words = line + 13;
            trim(words);
            char *token = strtok(words, ",");
            while (token && filter_count < MAX_FILTERS) {
                filter_words[filter_count++] = strdup(token);
                token = strtok(NULL, ",");
            }
        } else if (strncmp(line, "SECRET_FILE_BASENAME=", 22) == 0) {
            strcpy(secret_basename, line + 22);
            trim(secret_basename);
        } else if (strncmp(line, "ACCESS_START=", 13) == 0) {
            int h, m;
            sscanf(line + 13, "%d:%d", &h, &m);
            access_start_hour = h;
        } else if (strncmp(line, "ACCESS_END=", 11) == 0) {
            int h, m;
            sscanf(line + 11, "%d:%d", &h, &m);
            access_end_hour = h;
        }
    }
    fclose(f);
}

bool is_secret_file_blocked_now(const char *basename) {
    if (strcmp(basename, secret_basename) != 0) return false;
    time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    int hour = lt->tm_hour;
    return (hour < access_start_hour || hour >= access_end_hour);
}

void fullpath(char fpath[MAX_PATH], const char *path) {
    snprintf(fpath, MAX_PATH, "%s%s", source_dir, path);
}

static int find_fullname_by_stripped(const char *stripped_name, char *full_name) {
    DIR *dp = opendir(source_dir);
    if (!dp) return -ENOENT;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (de->d_type == DT_REG) {
            char *dot = strrchr(de->d_name, '.');
            size_t name_len = dot ? (size_t)(dot - de->d_name) : strlen(de->d_name);
            if (strncmp(de->d_name, stripped_name, name_len) == 0 && strlen(stripped_name) == name_len) {
                char base[256];
                strncpy(base, de->d_name, name_len);
                base[name_len] = '\0';
                if (is_secret_file_blocked_now(base)) {
                    closedir(dp);
                    return -ENOENT;
                }
                strcpy(full_name, de->d_name);
                closedir(dp);
                return 0;
            }
        }
    }
    closedir(dp);
    return -ENOENT;
}

bool is_text_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char buf[512];
    size_t r = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    for (size_t i = 0; i < r; i++) {
        if (buf[i] == 0) return false;
    }
    return true;
}

void replace_keywords(char *text, size_t size) {
    for (int i = 0; i < filter_count; i++) {
        char *pos;
        while ((pos = strcasestr(text, filter_words[i])) != NULL) {
            size_t kw_len = strlen(filter_words[i]);
            memmove(pos + 5, pos + kw_len, strlen(pos + kw_len) + 1);
            memcpy(pos, "lawak", 5);
        }
    }
}

char *base64_encode(const unsigned char *input, int length, size_t *out_len) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char *buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    *out_len = bptr->length;
    BIO_free_all(b64);
    return buff;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char realname[MAX_PATH], fpath[MAX_PATH];
    if (find_fullname_by_stripped(path + 1, realname) != 0) return -ENOENT;
    int written = snprintf(fpath, MAX_PATH, "%s/%s", source_dir, realname);
if (written < 0 || written >= MAX_PATH) {
    return -ENAMETOOLONG; // or another appropriate error
}
    log_action("READ", path);

    if (is_text_file(fpath)) {
        FILE *f = fopen(fpath, "r");
        if (!f) return -errno;
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *temp = malloc(len + 1);
        fread(temp, 1, len, f);
        temp[len] = 0;
        fclose(f);

        replace_keywords(temp, len);

        size_t to_copy = (offset < len) ? ((len - offset < size) ? len - offset : size) : 0;
        memcpy(buf, temp + offset, to_copy);
        free(temp);
        return to_copy;
    } else {
        FILE *f = fopen(fpath, "rb");
        if (!f) return -errno;
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        fseek(f, 0, SEEK_SET);
        unsigned char *raw = malloc(len);
        fread(raw, 1, len, f);
        fclose(f);

        size_t enc_len;
        char *encoded = base64_encode(raw, len, &enc_len);
        free(raw);

        size_t to_copy = (offset < enc_len) ? ((enc_len - offset < size) ? enc_len - offset : size) : 0;
        memcpy(buf, encoded + offset, to_copy);
        free(encoded);
        return to_copy;
    }
}
static int xmp_getattr(const char *path, struct stat *stbuf) {
    int res;
    char realname[MAX_PATH], fpath[MAX_PATH];

    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }

    if (find_fullname_by_stripped(path + 1, realname) != 0)
        return -ENOENT;

    int written = snprintf(fpath, MAX_PATH, "%s/%s", source_dir, realname);
if (written < 0 || written >= MAX_PATH) {
    return -ENAMETOOLONG; // or another appropriate error
}



    res = lstat(fpath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi) {
    log_action("OPEN", path);
    return 0;
}

static int xmp_access(const char *path, int mask) {
    log_action("ACCESS", path);
    return 0;
}

static int xmp_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    return -EROFS;
}

static int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    return -EROFS;
}

static int xmp_truncate(const char *path, off_t size) {
    return -EROFS;
}

static int xmp_unlink(const char *path) {
    return -EROFS;
}

static int xmp_mkdir(const char *path, mode_t mode) {
    return -EROFS;
}

static int xmp_rmdir(const char *path) {
    return -EROFS;
}

static int xmp_rename(const char *from, const char *to) {
    return -EROFS;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    log_action("READDIR", path);
    char fpath[MAX_PATH];
    fullpath(fpath, path);

    DIR *dp;
    struct dirent *de;
    dp = opendir(fpath);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;

        char name_no_ext[256];
        strncpy(name_no_ext, de->d_name, sizeof(name_no_ext));
        char *dot = strrchr(name_no_ext, '.');
        if (dot) *dot = '\0';

        filler(buf, name_no_ext, &st, 0);
    }
    closedir(dp);
    return 0;
}

static struct fuse_operations xmp_oper = {
    .read       = xmp_read,
    .open       = xmp_open,
    .access     = xmp_access,
    .write      = xmp_write,
    .create     = xmp_create,
    .truncate   = xmp_truncate,
    .unlink     = xmp_unlink,
    .mkdir      = xmp_mkdir,
    .rmdir      = xmp_rmdir,
    .rename     = xmp_rename,
    .readdir    = xmp_readdir,
    .getattr    = xmp_getattr,
};

int main(int argc, char *argv[]) {
    load_config(CONFIG_FILE);
    umask(0);
    return fuse_main(argc, argv, &xmp_oper, NULL);
}
