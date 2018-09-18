#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <pthread.h>
#define FUSE_USE_VERSION 26
#include <fuse/fuse.h>
#include <libsmbclient.h>

/* Definitions */
#define LOGFILE                 "/tmp/foxtrot.log"
#define SMB_MAX_PACKET_LENGTH   65536
#define MAX_PATH                1024

/* Set this to 1 to trace all invocations of FUSE callback functions */
#define TRACE_INVOCATIONS       0


/* Global variables */
static pthread_mutex_t global_mutex;

static char *smb_workgroup = "";
static char *smb_username = "";
static char *smb_password = "";
static char *smb_url = "";


#define WARN(msg) \
    do { \
        time_t t; time(&t); \
        fprintf(stderr, "%.24s [WARNING] %s (%s:%d)\n", \
                        ctime(&t), msg, __FILE__, __LINE__); \
    } while(0)

#define NOTE(msg) \
    do { \
        time_t t; time(&t); \
        fprintf(stderr, "%.24s [NOTICE] %s (%s:%d)\n", \
                        ctime(&t), msg, __FILE__, __LINE__); \
    } while(0)

static char *mksmbpath(const char *path)
{
    size_t len;
    char *smbpath = NULL;

    /* 2 extra bytes for separating slash and terminating null */
    len = strlen(smb_url) + strlen(path) + 2;
    smbpath = calloc(len, sizeof(char));

    if (smbpath == NULL) return NULL;
    strncat(smbpath, smb_url, len);
    strncat(smbpath, "/", len);
    strncat(smbpath, path, len);

    return smbpath;
}

static int foxtrot_getattr(const char *path, struct stat *stbuf)
{
    char *smbpath = NULL;
    int result;

#if TRACE_INVOCATIONS
    fprintf(stderr, "getattr path=%s\n", path);
#endif

    memset(stbuf, 0, sizeof(struct stat));

    if (path[0] != '/')
    {
        WARN("Relative path ignored!");
        return -ENOENT;
    }

    smbpath = mksmbpath(path);
    if (smbpath == NULL)
    {
        WARN("Path too long");
        return -ENOENT;
    }

    pthread_mutex_lock(&global_mutex);
    if (smbc_stat(smbpath, stbuf) == 0) result = 0; else result = -errno;
    free(smbpath);
    pthread_mutex_unlock(&global_mutex);

    return result;
}

static int foxtrot_mkdir(const char *path, mode_t mode)
{
    char *smbpath = NULL;
    int result;

#if TRACE_INVOCATIONS
    fprintf(stderr, "mkdir path=%s mode=%4o\n", path, mode);
#endif

    if (path[0] != '/')
    {
        WARN("Relative path ignored!");
        return -ENOENT;
    }

    smbpath = mksmbpath(path);
    if (smbpath == NULL)
    {
        WARN("Path too long");
        return -ENOENT;
    }

    pthread_mutex_lock(&global_mutex);
    if (smbc_mkdir(smbpath, mode) == 0) result = 0; else result = -errno;
    free(smbpath);
    pthread_mutex_unlock(&global_mutex);

    return result;
}

static int foxtrot_unlink(const char *path)
{
    char *smbpath = NULL;
    int result;

#if TRACE_INVOCATIONS
    fprintf(stderr, "unlink path=%s\n", path);
#endif

    if (path[0] != '/')
    {
        WARN("Relative path ignored!");
        return -ENOENT;
    }

    smbpath = mksmbpath(path);
    if (smbpath == NULL)
    {
        WARN("Path too long");
        return -ENOENT;
    }

    pthread_mutex_lock(&global_mutex);
    if (smbc_unlink(smbpath) == 0) result = 0; else result = -errno;
    free(smbpath);
    pthread_mutex_unlock(&global_mutex);

    return result;
}

static int foxtrot_rmdir(const char *path)
{
    char *smbpath = NULL;
    int result;

#if TRACE_INVOCATIONS
    fprintf(stderr, "rmdir path=%s\n", path);
#endif

    if (path[0] != '/')
    {
        WARN("Relative path ignored!");
        return -ENOENT;
    }

    smbpath = mksmbpath(path);
    if (smbpath == NULL)
    {
        WARN("Path too long");
        return -ENOENT;
    }

    pthread_mutex_lock(&global_mutex);
    if (smbc_rmdir(smbpath) == 0) result = 0; else result = -errno;
    free(smbpath);
    pthread_mutex_unlock(&global_mutex);

    return result;
}

static int foxtrot_rename(const char *from, const char *to)
{
    char *smbfrom = NULL, *smbto = NULL;
    int result;

#if TRACE_INVOCATIONS
    fprintf(stderr, "rename from=%s to=%s\n", from, to);
#endif

    if (from[0] != '/' || to[0] != '/')
    {
        WARN("Relative path ignored!");
        return -ENOENT;
    }

    smbfrom = mksmbpath(from);
    smbto = mksmbpath(to);
    if (smbfrom == NULL || smbto == NULL)
    {
        WARN("Path too long");
        return -ENOENT;
    }

    pthread_mutex_lock(&global_mutex);
    if (smbc_rename(smbfrom, smbto) == 0) result = 0; else result = -errno;
    free(smbfrom);
    free(smbto);
    pthread_mutex_unlock(&global_mutex);

    return result;
}

static int foxtrot_truncate(const char *path, off_t size)
{
    char *smbpath = NULL;
    int fd;
    int result;

#if TRACE_INVOCATIONS
    fprintf(stderr, "truncate path=%s %ld\n", path, size);
#endif

    if (path[0] != '/')
    {
        WARN("Relative path ignored!");
        return -ENOENT;
    }

    smbpath = mksmbpath(path);
    if (smbpath == NULL)
    {
        WARN("Path too long");
        return -ENOENT;
    }

    pthread_mutex_lock(&global_mutex);
    fd = smbc_open(smbpath, O_WRONLY, 0);
    free(smbpath);
    if (fd >= 0)
    {
        if (smbc_ftruncate(fd, size) == 0) result = 0; else result = -errno;
        smbc_close(fd);
    }
    else
    {
        result = -errno;
    }
    pthread_mutex_unlock(&global_mutex);

    return result;
}

static int foxtrot_readdir( const char *path, void *buf, fuse_fill_dir_t filler,
                           off_t offset, struct fuse_file_info *fi )
{
    (void) offset;
    (void) fi;

#if TRACE_INVOCATIONS
    fprintf(stderr, "readdir path=%s\n", path);
#endif

    int dh;
    struct smbc_dirent *de;
    char *smbpath = NULL;

    smbpath = mksmbpath(path);
    if (smbpath == NULL)
    {
        WARN("Path too long");
        return -ENOENT;
    }

    pthread_mutex_lock(&global_mutex);
    dh = smbc_opendir(smbpath);
    free(smbpath);
    if (dh < 0)
    {
        WARN("smbc_opendir failed");
        pthread_mutex_unlock(&global_mutex);
        return -ENOENT;
    }
    while ((de = smbc_readdir(dh)) != NULL)
    {
        switch (de->smbc_type)
        {
        case SMBC_FILE_SHARE:
        case SMBC_DIR:
        case SMBC_FILE:
        case SMBC_LINK:
            filler(buf, de->name, NULL, 0);
        }
    }
    smbc_closedir(dh);
    pthread_mutex_unlock(&global_mutex);

    return 0;
}

static int foxtrot_open(const char *path, struct fuse_file_info *fi)
{
    char *smbpath = NULL;
    int fd;

#if TRACE_INVOCATIONS
    fprintf(stderr, "open path=%s flags=0%o\n", path, (int)fi->flags);
#endif

    smbpath = mksmbpath(path);
    if (smbpath == NULL)
    {
        WARN("Path too long");
        return -ENOENT;
    }

    pthread_mutex_lock(&global_mutex);
    fd = smbc_open(smbpath, fi->flags & 3, 0644);
    free(smbpath);
    pthread_mutex_unlock(&global_mutex);
    if (fd < 0)
    {
        WARN("smbc_open failed");
        return -fd;
    }
    fi->fh = fd;

    return 0;
}

int foxtrot_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
    size_t nread, chunk;
    ssize_t result;

#if TRACE_INVOCATIONS
    fprintf(stderr, "read path=%s fd=%d size=%lld offset=%lld\n",
                    path, (int)fi->fh, (long long)size, (long long)offset);
#else
    (void)path;
#endif

    pthread_mutex_lock(&global_mutex);
    if (smbc_lseek((int)fi->fh, offset, SEEK_SET) == (off_t)-1)
    {
        WARN("smbc_lseek failed");
        pthread_mutex_unlock(&global_mutex);
        return -errno;
    }

    nread = 0;
    while (nread < size)
    {
        chunk = size - nread;
        if (chunk > SMB_MAX_PACKET_LENGTH) chunk = SMB_MAX_PACKET_LENGTH;
        result = smbc_read((int)fi->fh, buf + nread, chunk);
        if (result < 0)
        {
            WARN("smbc_read failed");
            pthread_mutex_unlock(&global_mutex);
            return -errno;
        }
        if (result == 0) break; /* EOF */
        nread += result;
    }
    pthread_mutex_unlock(&global_mutex);

    return (int)nread;
}

static int foxtrot_write(const char *path, const char *buf, size_t size,
       off_t offset, struct fuse_file_info *fi)
{
    size_t nwritten, chunk;
    ssize_t result;

#if TRACE_INVOCATIONS
    fprintf(stderr, "read path=%s fd=%d size=%lld offset=%lld\n",
                    path, (int)fi->fh, (long long)size, (long long)offset);
#else
    (void)path;
#endif

    pthread_mutex_lock(&global_mutex);
    if (smbc_lseek((int)fi->fh, offset, SEEK_SET) == (off_t)-1)
    {
        WARN("smbc_lseek failed");
        pthread_mutex_unlock(&global_mutex);
        return -errno;
    }

    nwritten = 0;
    while (nwritten < size)
    {
        chunk = size - nwritten;
        if (chunk > SMB_MAX_PACKET_LENGTH) chunk = SMB_MAX_PACKET_LENGTH;
        result = smbc_write((int)fi->fh, buf + nwritten, chunk);
        if (result < 0)
        {
            WARN("smbc_write failed");
            pthread_mutex_unlock(&global_mutex);
            return -errno;
        }
        if (result == 0) break; /* EOF */
        nwritten += result;
    }
    pthread_mutex_unlock(&global_mutex);

    return (int)nwritten;
}

int foxtrot_release(const char *path, struct fuse_file_info *fi)
{
    int res;

#if TRACE_INVOCATIONS
    fprintf(stderr, "release path=%s fd=%d\n", path, (int)fi->fh);
#else
    (void)path;
#endif

    res = smbc_close(fi->fh);
    if (res != 0) WARN("smbc_close failed");

    return -res;
}

static void open_logfile()
{
    FILE *fp;

    fp = freopen(LOGFILE, "a+", stderr);
    assert(fp != NULL);
    setlinebuf(stderr);
}

static void get_auth_data(
    const char *srv,
    const char *shr,
    char *wg, int wglen,
    char *un, int unlen,
    char *pw, int pwlen )
{
    (void)srv;
    (void)shr;
    strncpy(wg, smb_workgroup, wglen);
    wg[wglen - 1] = '\0';
    strncpy(un, smb_username, unlen);
    un[unlen - 1] = '\0';
    strncpy(pw, smb_password, pwlen);
    pw[pwlen - 1] = '\0';
}

static void samba_init()
{
    int res;

    res = smbc_init(get_auth_data, 0);
    assert(res == 0);
}

void *foxtrot_init(struct fuse_conn_info *conn)
{
    (void)conn;

    open_logfile();
    NOTE("Foxtrot starting up!");

    samba_init();
    pthread_mutex_init(&global_mutex, NULL);

    return NULL;
}

void foxtrot_destroy(void *private_data)
{
    NOTE("Foxtrot shutting down!");

    (void)private_data;
    pthread_mutex_destroy(&global_mutex);
}

static int foxtrot_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    char *smbpath = NULL;
    int fd;

#if TRACE_INVOCATIONS
    fprintf(stderr, "create path=%s mode=%4o flags=0%o\n", path, mode, (int)fi->flags);
#endif

    smbpath = mksmbpath(path);
    if (smbpath == NULL)
    {
        WARN("Path too long");
        return -ENOENT;
    }

    pthread_mutex_lock(&global_mutex);
    fd = smbc_creat(smbpath, mode);
    free(smbpath);
    pthread_mutex_unlock(&global_mutex);
    if (fd < 0)
    {
        WARN("smbc_creat failed");
        return -fd;
    }
    fi->fh = fd;

    return 0;
}

static int foxtrot_ftruncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    int result;

#if TRACE_INVOCATIONS
    fprintf(stderr, "ftruncate path=%s fd=%d size=%ld\n", path, (int)fi->fh, size);
#else
    (void)path;
#endif

    pthread_mutex_lock(&global_mutex);
    if (smbc_ftruncate(fi->fh, size) == 0) result = 0; else result = -errno;
    pthread_mutex_unlock(&global_mutex);

    return result;
}

int main(int argc, char *argv[])
{
    struct fuse_operations ops;
    static struct option long_opts[] = {
	{ "workgroup", required_argument, 0, 'w' },
	{ "username", required_argument, 0, 'u' },
	{ "password", required_argument, 0, 'p' },
	{ "url", required_argument, 0, 'U' },
        { NULL, 0, 0, 0 }
    };
    int c, opt_idx = 0;
    char **fuse_argv = calloc(argc, sizeof(char*));
    int next_fuse_opt_idx = 0;

    /* copy program name as first argument */
    fuse_argv[next_fuse_opt_idx++] = argv[0];

    while ((c = getopt_long(argc, argv, "w:u:p:", long_opts, &opt_idx)) > 0) 
    {
        switch (c) 
        {
            case 'w':
                smb_workgroup = strdup(optarg);
                break;

            case 'u':
                smb_username = strdup(optarg);
                break;

            case 'p':
                smb_password = strdup(optarg);
                break;

            case 'U':
                smb_url = strdup(optarg);
                break;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "fuse options:\n\t");
        while (optind < argc)
        {
            fprintf(stderr, "%s ", argv[optind]);
            fuse_argv[next_fuse_opt_idx++] = argv[optind++];
        }
        fprintf(stderr, "\n");
    }

    /* Assign FUSE operations */
    memset(&ops, 0, sizeof(ops));
    ops.getattr = foxtrot_getattr;
    ops.mkdir   = foxtrot_mkdir;
    ops.unlink  = foxtrot_unlink;
    ops.rmdir   = foxtrot_rmdir;
    ops.rename  = foxtrot_rename;
    ops.truncate = foxtrot_truncate;
    ops.readdir = foxtrot_readdir;
    ops.open    = foxtrot_open;
    ops.read    = foxtrot_read;
    ops.write   = foxtrot_write;
    ops.release = foxtrot_release;
    ops.init    = foxtrot_init;
    ops.destroy = foxtrot_destroy;
    ops.create  = foxtrot_create;
    ops.ftruncate = foxtrot_ftruncate;

    return fuse_main(next_fuse_opt_idx, fuse_argv, &ops, NULL);
}
