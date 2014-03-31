/*
FUSE: Filesystem in Userspace
Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

This program can be distributed under the terms of the GNU GPL.
See the file COPYING.
*/

/** @file
 * @tableofcontents
 *
 * fusexmp_fh.c - FUSE: Filesystem in Userspace
 *
 * \section section_compile compiling this example
 *
 * gcc -Wall fusexmp_fh.c `pkg-config fuse3 --cflags --libs` -lulockmgr -o fusexmp_fh
 *
 * \section section_source the complete source
 * \include fusexmp_fh.c
 */

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <fuse.h>

#ifdef HAVE_LIBULOCKMGR
#include <ulockmgr.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
#include <sys/file.h> /* flock(2) */
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "interface.h"
#include "statsd-client.h"

// should configure these
const char * bfs_root = "/bfs_roots/current/store/";
const char * lfs_root = "/lfs_roots/mnt/cms/store/";
const char * migrateZMQTarget = "tcp://brazil.vampire:5555";
// lock for anyone screwing with the linked list of fds or initializing statsd
pthread_mutex_t fd_mutex = PTHREAD_MUTEX_INITIALIZER;

struct lstore_fd_t {
    struct lstore_fd_t * next;
    short is_lfs;
    int fd;
    char * path;
    char * real_path;
    int flags;
    int perms;
    mode_t mode;
    int64_t off;
};

typedef struct {
    char ** retry_errors;
    int retry_errors_count;
    char ** retry_after_sleep_errors;
    int retry_after_sleep_errors_count;
    int sleep_time;
    int migrate_on_open; // percentage * 100
    int migrate_on_fail; // percentage * 100
} lstore_multiplex_config_t;

struct lstore_fd_t * fd_head = NULL;
statsd_link * lfs_statsd_link = NULL;
lstore_multiplex_config_t lstore_multiplex_config;

// forward declarations
int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi);
short should_retry(int my_errno, struct fuse_file_info * fi);

void line_to_list_of_strings(char * buf, char *** out_list, int * count) {
    char ** retval;
    int comma_count = 0;
    char * iter;
    for (iter = buf ; *iter != '\0'; ++iter) {
        if (*iter == ',') {
            comma_count += 1;
        }
    }
    retval = malloc(comma_count * sizeof(char *));
    if (!retval) {
        free(retval);
        *out_list = NULL;
        *count = 0;
        return;
    }
    int list_target = 0;
    char * first_pos = buf;
    for (iter = buf; (*iter != '\0'); ++iter) {
        if ((*iter == '\r') || (*iter == '\n') || (*iter == ',')) {
            retval[list_target] = malloc(iter - first_pos + 1);
            if (!retval[list_target]) {
                *out_list = NULL;
                *count = 0;
                --list_target;
                for ( ; list_target > 0; --list_target) {
                    free(retval[list_target]);
                }
                free(retval);
                return;
            }
            strncpy(retval[list_target],first_pos,iter - first_pos);
            retval[list_target][iter - first_pos + 1] = '\0';
            list_target++;
            if ((*iter == '\r') || (*iter == '\n')) {
                break;
            }
            first_pos = iter + 1;
        }
    }
    *count = comma_count + 1;
    *out_list = retval;
    return;
}

char * strip_newline(char * val) {
    int i;
    for (i = strlen(val); i != 0; --i) {
        if ((val[i] == '\r') && (val[i] == '\n')) {
            val[i] = '\0';
        }
    }
    return val;
}

void check_and_update_config() {
    // periodically update our configuration with chosen values
    // I'm lazy, so the format is:
    // retry_error1,retry_error2,...,retry_errorN
    // retry_sleep1,retry_sleep2,...,retry_sleepN
    // sleep_time
    // migrate_on_open
    // migrate_on_fail
    printf("Updating config\n");
    lstore_multiplex_config_t new_config = lstore_multiplex_config;
    FILE *fh = fopen("/usr/local/cms-stageout/multiplex.cfg", "r");
    if (fh == NULL) {
        return;
    }
    char buf[1024];
    if (fgets(buf, 1023, fh) == NULL) {
        return;
    }
    line_to_list_of_strings(buf, &new_config.retry_errors, &new_config.retry_errors_count);
    if (fgets(buf, 1023, fh) == NULL) {
        goto cleanup2;
    }
    line_to_list_of_strings(buf, &new_config.retry_after_sleep_errors, &new_config.retry_after_sleep_errors_count);

    if (fgets(buf, 1023, fh) == NULL) {
        goto cleanup;
    }
    new_config.sleep_time = atoi(strip_newline(buf));

    if (fgets(buf, 1023, fh) == NULL) {
        goto cleanup;
    }
    new_config.migrate_on_open = atoi(strip_newline(buf));

    if (fgets(buf, 1023, fh) == NULL) {
        goto cleanup;
    }
    new_config.migrate_on_fail = atoi(strip_newline(buf));

    int i;
    pthread_mutex_lock(&fd_mutex);
    for (i = 0; i < lstore_multiplex_config.retry_errors_count; i++) {
        free(lstore_multiplex_config.retry_errors[i]);
    }
    free(lstore_multiplex_config.retry_errors);
    for (i = 0; i < lstore_multiplex_config.retry_after_sleep_errors_count; i++) {
        free(lstore_multiplex_config.retry_after_sleep_errors[i]);
    }
    free(lstore_multiplex_config.retry_after_sleep_errors);
    lstore_multiplex_config = new_config;
    pthread_mutex_unlock(&fd_mutex);
    return;

cleanup:
    for (i = 0; i < new_config.retry_after_sleep_errors_count; i++) {
        free(new_config.retry_after_sleep_errors[i]);
    }
    free(new_config.retry_after_sleep_errors);

cleanup2:
    for (i = 0; i < new_config.retry_errors_count; i++) {
        free(new_config.retry_errors[i]);
    }
    free(new_config.retry_errors);
    return;
}

char * resolve_path(const char *path)
{
    // should cache this result, but ideally the number of path resolutions
    // is small...
    char * lfs_path = (char *) malloc(strlen(lfs_root)+strlen(path) + 1);
    char * bfs_path = (char *) malloc(strlen(bfs_root)+strlen(path) + 1);
    if ( !lfs_path ) {
        return NULL;
    } else if ( !bfs_path ){
        free(lfs_path);
        return NULL;
    }
    strcpy(lfs_path, lfs_root);
    strcpy(bfs_path, bfs_root);
    strcpy(lfs_path + strlen(lfs_root),path);
    strcpy(bfs_path + strlen(bfs_root),path);

    int retval;
    struct stat target;
    short keepGoing = 1;
    errno = 0;
    while (keepGoing) {
        retval = stat(lfs_path, &target);
        if ((retval == -1) && (errno == ENOENT)) {
            break;
        } else if (retval == -1) {
            keepGoing = should_retry(errno, NULL);
        } else if (retval == 0) {
            free(bfs_path);
            return lfs_path;
        }
    }
    while (keepGoing) {
        retval = stat(bfs_path, &target);
        if ((retval == -1) && (errno == ENOENT)) {
            break;
        } else if (retval == -1) {
            keepGoing = should_retry(errno, NULL);
        } else if (retval == 0) {
            free(lfs_path);
            return bfs_path;
        }
    }
    free(lfs_path);
    free(bfs_path);
    return strdup(lfs_path);
}

short should_retry(int my_errno, struct fuse_file_info * fi) {
    char buf[1024], buf2[1024];
    snprintf(buf, 1023, "fault_received.%d", my_errno);
    STATSD_COUNT(buf, 1);
    printf("Received error: %d\n", my_errno);
    snprintf(buf2, 1023, "%d", my_errno);
    int i;
    pthread_mutex_lock(&fd_mutex);
    for (i = 0; i < lstore_multiplex_config.retry_after_sleep_errors_count; i++) {
        printf("comparing %s to %s\n", buf2, lstore_multiplex_config.retry_errors[i]);
        if (strcmp(buf2, lstore_multiplex_config.retry_after_sleep_errors[i]) == 0) {
            pthread_mutex_unlock(&fd_mutex);
            sleep(lstore_multiplex_config.sleep_time);
            if (fi != NULL) {
                struct lstore_fd_t * desc = ((struct lstore_fd_t *)fi->fh);
                mode_t mode = desc->mode;
                char * temp_path = strdup(desc->path);
                if (!temp_path) {
                    printf("Error %d passed throug after malloch - sleep\n", my_errno);
                    snprintf(buf, 1023, "fault_received.%d", my_errno);
                    STATSD_COUNT(buf, 1);
                    return 0;
                }
                xmp_release(desc->path, fi);
                if (xmp_create(temp_path, mode, fi) < 0) {
                    errno = my_errno;
                    snprintf(buf, 1023, "fault_received.%d", my_errno);
                    STATSD_COUNT(buf, 1);
                    printf("Error %d passed through after creating - sleep\n", my_errno);
                    return 0;
                }
            }
            printf("Error %d retried - sleep\n", my_errno);
            snprintf(buf, 1023, "fault_received.%d", my_errno);
            STATSD_COUNT(buf, 1);
            return 1;
        }
    }
    for (i = 0;i < lstore_multiplex_config.retry_errors_count; i++) {
        printf("comparing %s to %s\n", buf2, lstore_multiplex_config.retry_errors[i]);
        if (strcmp(buf2, lstore_multiplex_config.retry_errors[i]) == 0) {
            pthread_mutex_unlock(&fd_mutex);
            if (fi != NULL) {
                struct lstore_fd_t * desc = ((struct lstore_fd_t *)fi->fh);
                mode_t mode = desc->mode;
                char * temp_path = strdup(desc->path);
                if (!temp_path) {
                    printf("Error %d passed through after malloc - nosleep\n", my_errno);
                    snprintf(buf, 1023, "fault_received.%d", my_errno);
                    STATSD_COUNT(buf, 1);
                    return 0;
                }
                xmp_release(temp_path, fi);
                if (xmp_create(temp_path, mode, fi) < 0) {
                    errno = my_errno;
                    printf("Error %d passed through after create - nosleep\n", my_errno);
                    snprintf(buf, 1023, "fault_received.%d", my_errno);
                    STATSD_COUNT(buf, 1);
                    return 0;
                }
            }
            printf("Error %d retried - nosleep\n", my_errno);
            snprintf(buf, 1023, "fault_received.%d", my_errno);
            STATSD_COUNT(buf, 1);
            return 1;
        }
    }
    pthread_mutex_unlock(&fd_mutex);
    printf("Error %d passed through - nomatch\n", my_errno);
    snprintf(buf, 1023, "fault_received.%d", my_errno);
    STATSD_COUNT(buf, 1);
    return 0;
}

int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;
    char * real_path = resolve_path(path);
    if (!real_path) {
        return -ENOMEM;
    }
    free(real_path);
    if (res == -1)
        return -errno;

    return 0;
}

int xmp_fgetattr(const char *path, struct stat *stbuf,
        struct fuse_file_info *fi)
{
    int res;

    (void) path;
    int * fd = &(((struct lstore_fd_t *)fi->fh)->fd);
    while ((res = fstat(*fd, stbuf))
            && (res == -1) 
            && (should_retry(errno,fi)));

    if (res == -1)
        return -errno;

    return 0;
}

int xmp_access(const char *path, int mask)
{
    int res;
    char * real_path = resolve_path(path);
    if (!real_path) {
        return -ENOMEM;
    }
    while ((res = access(real_path, mask)) && (res == -1) && (should_retry(errno, NULL)));
    free(real_path);
    if (res == -1)
        return -errno;

    return 0;
}

int xmp_readlink(const char *path, char *buf, size_t size)
{
    int res;
    char * real_path = resolve_path(path);
    if (!real_path) {
        return -ENOMEM;
    }
    while ((res = readlink(real_path, buf, size - 1)) && (res == -1) && (should_retry(errno, NULL)));
    free(real_path);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

struct xmp_dirp {
    DIR *dp;
    struct dirent *entry;
    off_t offset;
};

int xmp_opendir(const char *path, struct fuse_file_info *fi)
{
    printf("Loading dir %s\n", path);
    int res;
    struct xmp_dirp *d = malloc(sizeof(struct xmp_dirp));
    if (d == NULL)
        return -ENOMEM;
    char * real_path = (char *) malloc(strlen(bfs_root)+strlen(path) + 1);
    if ( !real_path ){
        return -ENOMEM;
    }
    strcpy(real_path, bfs_root);
    strcpy(real_path + strlen(bfs_root),path);
    while ((d->dp = opendir(real_path)) && (d->dp == NULL) && (should_retry(errno, NULL)));
    free(real_path);
    if (d->dp == NULL) {
        res = -errno;
        free(d);
        return res;
    }
    d->offset = 0;
    d->entry = NULL;

    fi->fh = (unsigned long) d;
    return 0;
}

inline struct xmp_dirp *get_dirp(struct fuse_file_info *fi)
{
    return (struct xmp_dirp *) (uintptr_t) fi->fh;
}

int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
        off_t offset, struct fuse_file_info *fi)
{
    struct xmp_dirp *d = get_dirp(fi);

    (void) path;
    if (offset != d->offset) {
        seekdir(d->dp, offset);
        d->entry = NULL;
        d->offset = offset;
    }
    while (1) {
        struct stat st;
        off_t nextoff;

        if (!d->entry) {
            d->entry = readdir(d->dp);
            if (!d->entry)
                break;
        }

        nextoff = telldir(d->dp);
        if (filler(buf, d->entry->d_name, &st, nextoff))
            break;

        d->entry = NULL;
        d->offset = nextoff;
    }

    return 0;
}

int xmp_releasedir(const char *path, struct fuse_file_info *fi)
{
    struct xmp_dirp *d = get_dirp(fi);
    (void) path;
    closedir(d->dp);
    free(d);
    return 0;
}

int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int fd;
    check_and_update_config();
    char * real_path = resolve_path(path);
    if (!real_path) {
        return -ENOMEM;
    }
    while ((fd = open(real_path, fi->flags, mode)) && (fd == -1) && (should_retry(errno, NULL)));
    free(real_path);
    if (fd == -1)
        return -errno;

    struct lstore_fd_t * desc = malloc(sizeof(struct lstore_fd_t));
    if (!desc) {
        close(fd);
        return -ENOMEM;
    }
    desc->fd = fd;
    desc->path = strdup(path);
    desc->real_path = strdup(real_path);
    desc->flags = fi->flags;
    desc->mode = mode;
    desc->is_lfs = ( strstr(path, lfs_root) != NULL );
    // keep a linked list around .. just in case
    pthread_mutex_lock(&fd_mutex);
    desc->next = fd_head;
    fd_head = desc;
    pthread_mutex_unlock(&fd_mutex);

    fi->fh = (int64_t) desc;
    return 0;
}

int xmp_open(const char *path, struct fuse_file_info *fi)
{
    return xmp_create(path, 0666, fi);
}

int xmp_read(const char *path, char *buf, size_t size, off_t offset,
        struct fuse_file_info *fi)
{
    int res;

    (void) path;
    int * fd = &(((struct lstore_fd_t *)fi->fh)->fd);
    STATSD_TIMER_START(read_loop_timer);
    while ((res = pread(*fd, buf, size, offset)) && (res == -1) && (should_retry(errno, fi)));

    if (res == -1) {
        res = -errno;
        char buf[1024];
        snprintf(buf, 1023, "read_errors.%i", errno);
        STATSD_COUNT(buf, 1);
        return res;
    }
    if ( ((struct lstore_fd_t *)fi->fh)->is_lfs ) {
        STATSD_TIMER_END("lfs_read_time", read_loop_timer);
        STATSD_COUNT("lfs_bytes_read", res);
    } else {
        STATSD_TIMER_END("posix_read_time", read_loop_timer);
        STATSD_COUNT("posix_bytes_read", res);
    }

    return res;
}

int xmp_statfs(const char *path, struct statvfs *stbuf)
{
    int res;
    char * real_path = resolve_path(path);
    if (!real_path) {
        return -ENOMEM;
    }
    while ((res = statvfs(real_path, stbuf)) && (res == -1) && (should_retry(errno, NULL)));
    free(real_path);
    if (res == -1)
        return -errno;

    return 0;
}

int xmp_flush(const char *path, struct fuse_file_info *fi)
{
    int res;

    (void) path;
    /* This is called from every close on an open file, so call the
       close on the underlying filesystem.	But since flush may be
       called multiple times for an open file, this must not really
       close the file.  This is important if used on a network
       filesystem like NFS which flush the data/metadata on close() */
    int * fd = &(((struct lstore_fd_t *)fi->fh)->fd);
    while ((res = close(dup((*fd)))
                && (res == -1) 
                && (should_retry(errno,fi))));
    if (res == -1)
        return -errno;

    return 0;
}

int xmp_release(const char *path, struct fuse_file_info *fi)
{
    (void) path;
    int * fd = &(((struct lstore_fd_t *)fi->fh)->fd);
    int res;
    while ((res = close(*fd)) 
            && (res == -1) 
            && (should_retry(errno,fi)));

    struct lstore_fd_t * desc = (struct lstore_fd_t *) fi->fh;
    pthread_mutex_lock(&fd_mutex);
    if (fd_head == NULL) {
        /* do nothing */
    } else if (fd_head == desc) {
        fd_head = desc->next;
    } else {
        struct lstore_fd_t * iter = fd_head;
        while (iter->next != NULL) {
            if (iter->next == desc) {
                iter->next = desc->next;
                break;
            }
        }
    }
    pthread_mutex_unlock(&fd_mutex);
    free(desc);
    return 0;
}

int main(int argc, char *argv[])
{
    umask(0);
    printf("LStore-Multiplex. Written 2014 <andrew.m.melo@vanderbilt.edu>\n");

    // start up statsd
    char local_host[256];
    memset(local_host, 0, 256);
    if (gethostname(local_host, 255)) {
        strcpy(local_host, "UNKNOWN");
    }

    char statsd_namespace_prefix [] = "lfs.multiplex.";
    char * statsd_namespace = malloc(strlen(statsd_namespace_prefix)+
            strlen(local_host)+1);
    if (!statsd_namespace) {
        return -1;
    }
    strcpy(statsd_namespace, statsd_namespace_prefix);
    char * source = local_host;
    char * dest;
    for (dest = statsd_namespace + strlen(statsd_namespace_prefix);
            *source != '\0';
            ++source, ++dest) {
        if (*source == '.') {
            *dest = '_';
        } else {
            *dest = *source;
        }
    }

    // should un-hardcode this
    lfs_statsd_link = statsd_init_with_namespace("10.0.16.100",8125,statsd_namespace);
    struct fuse_operations xmp_oper;
    memset(&xmp_oper, 0, sizeof(xmp_oper));
    xmp_oper.getattr	= xmp_getattr;
    xmp_oper.fgetattr	= xmp_fgetattr;
    xmp_oper.access		= xmp_access;
    xmp_oper.readlink	= xmp_readlink;
    xmp_oper.opendir	= xmp_opendir;
    xmp_oper.readdir	= xmp_readdir;
    xmp_oper.releasedir	= xmp_releasedir;
    xmp_oper.create		= xmp_create;
    xmp_oper.open		= xmp_open;
    xmp_oper.read		= xmp_read;
    //xmp_oper.read_buf	= xmp_read_buf;
    xmp_oper.statfs		= xmp_statfs;
    xmp_oper.flush		= xmp_flush;
    xmp_oper.release	= xmp_release;

    // initialize config
    lstore_multiplex_config.retry_errors = malloc(sizeof(char *) * 2);
    lstore_multiplex_config.retry_errors[0] = strdup("4");
    lstore_multiplex_config.retry_errors[1] = strdup("11");
    lstore_multiplex_config.retry_errors_count = 2;
    lstore_multiplex_config.retry_after_sleep_errors = malloc(sizeof(char *) * 1);
    lstore_multiplex_config.retry_after_sleep_errors[0] = strdup("107");
    lstore_multiplex_config.retry_after_sleep_errors_count = 1;
    lstore_multiplex_config.sleep_time = 15;
    lstore_multiplex_config.migrate_on_fail = 0;
    lstore_multiplex_config.migrate_on_open = 0;
    check_and_update_config();

    int retval = fuse_main(argc, argv, &xmp_oper, NULL);
    printf("Shutting down.\n");
    statsd_finalize(lfs_statsd_link);
    return retval;
}