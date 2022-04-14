/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2022       Jeffy Chen <jeffy.chen@rock-chips.com>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/* Include the original fuse example source */
#define main __attribute__((unused)) _hide_main
#include "passthrough.c"
#undef main

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <linux/limits.h>

#define HOOKFS_VERSION "1.0.0~20220418"

#ifndef HOOKFS_CONFIG_FILE
#define HOOKFS_CONFIG_FILE "/etc/hookfs.conf"
#endif

#ifndef HOOKFS_LOG_FILE
#define HOOKFS_LOG_FILE "/var/log/hookfs.log"
#endif

#ifndef HOOKFS_SCRIPTS_DIR
#define HOOKFS_SCRIPTS_DIR "/etc/hookfs/"
#endif

#define HOOKFS_WRITE_SCRIPT "write.sh"
#define HOOKFS_RELEASE_SCRIPT "release.sh"

struct hookfs_options {
  const char *source;
  const char *mountpoint;
  const char *config_file;
  const char *log_file;
  const char *scripts_dir;
  int show_help;
  int show_version;
  int debug;
};

static struct {
  struct hookfs_options opts;

  const char *write_script;
  const char *release_script;

  const char *configs;

  FILE *log_fp;
  int debug;
} hookfs_ctx;

#define LOG(tag, fp, ...) { \
  fprintf(fp, __VA_ARGS__); \
  if (hookfs_ctx.log_fp) { \
    struct timeval tv; gettimeofday(&tv, NULL); \
    fprintf(hookfs_ctx.log_fp, "[%05ld.%03ld] [" tag "] %s(%d) ", \
            tv.tv_sec % 100000, tv.tv_usec / 1000, __func__, __LINE__); \
    fprintf(hookfs_ctx.log_fp, __VA_ARGS__); fflush(hookfs_ctx.log_fp); \
  } \
}

#define HOOKFS_DEBUG(...) \
  if (hookfs_ctx.debug) LOG("DEBUG", stdout, __VA_ARGS__)
#define HOOKFS_INFO(...) LOG("INFO", stdout, __VA_ARGS__)
#define HOOKFS_ERROR(...) LOG("ERROR", stderr, __VA_ARGS__)

#define HOOKFS_OPT(s, p) { s, offsetof(struct hookfs_options, p), 1 }
static const struct fuse_opt option_spec[] = {
  HOOKFS_OPT("-h", show_help),
  HOOKFS_OPT("--help", show_help),
  HOOKFS_OPT("-v", show_version),
  HOOKFS_OPT("--version", show_version),
  HOOKFS_OPT("--debug-hookfs", debug),
  HOOKFS_OPT("--config=%s", config_file),
  HOOKFS_OPT("--log-file=%s", log_file),
  HOOKFS_OPT("--scripts-dir=%s", scripts_dir),
  FUSE_OPT_END
};

static struct fuse_operations hookfs_op;

static int hookfs_exec(const char *cmd)
{
  int ret;

  HOOKFS_DEBUG("execute:\n%s\n", cmd);

  if (hookfs_ctx.log_fp) {
    int fd, fd_out, fd_err;

    /* Redirect outputs to log file */
    fd = fileno(hookfs_ctx.log_fp);
    fd_out = dup(1);
    fd_err = dup(2);
    dup2(fd, 1);
    dup2(fd, 2);

    ret = system(cmd);

    /* Restore outputs */
    dup2(fd_out, 1);
    dup2(fd_err, 2);
    close(fd_out);
    close(fd_err);
  } else {
    ret = system(cmd);
  }

  if (ret < 0) {
    ret = -errno;
    HOOKFS_ERROR("got error %d from\n%s\n", ret, cmd);
    return ret;
  }

  HOOKFS_DEBUG("result: %d\n", ret);
  return ret;
}

static int hookfs_write(const char* path, const char* buffer,
                        size_t size, off_t offset, struct fuse_file_info *fi)
{
  struct hookfs_options *opts = &hookfs_ctx.opts;
  const char *script = hookfs_ctx.write_script;

  if (!access(script, X_OK)) {
    char *buf = malloc(size + 1);
    char cmd[PATH_MAX];
    int ret;

    /* Add a tail to avoid overflow */
    memcpy(buf, buffer, size);
    buf[size] = '\0';

    HOOKFS_DEBUG("write %s with \"%s\"\n", path, buf);

    snprintf(cmd, sizeof(cmd), "%s %s \"%s\"",
             script, path + strlen(opts->source) + 1, buf);

    /* Call hook script, ret == 0 means success, ret > 0 means fallthrough */
    ret = hookfs_exec(cmd);
    if (ret < 0)
      return ret;

    if (!ret)
      return size;

    /* fallthrough */
  }

  return xmp_oper.write(path, buffer, size, offset, fi);
}

static int hookfs_release(const char *path, struct fuse_file_info *fi)
{
  struct hookfs_options *opts = &hookfs_ctx.opts;
  const char *script = hookfs_ctx.release_script;

  if (!access(script, X_OK)) {
    char cmd[PATH_MAX];

    HOOKFS_DEBUG("release %s\n", path);

    snprintf(cmd, sizeof(cmd), "%s %s",
             script, path + strlen(opts->source) + 1);

    hookfs_exec(cmd);
  }

  return xmp_oper.release(path, fi);
}

static void show_version(const char *progname)
{
  printf("%s version: " HOOKFS_VERSION "\n", progname);
}

static void show_help(const char *progname)
{
  printf("usage: %s [options] <source> <mountpoint>\n\n", progname);
  printf("File-system specific options:\n"
         "    --debug-hookfs         enable hookfs debug output\n"
         "    --config=FILE          configure file\n"
         "    --log-file=FILE        file to output hookfs log messages\n"
         "    --scripts-dir=DIR      dir of hook scripts\n"
         "\n");
}

static int hookfs_opt_proc(void *data, const char *arg, int key,
                           struct fuse_args *outargs)
{
  (void) outargs;
  struct hookfs_options *opts = data;

  if (key == FUSE_OPT_KEY_NONOPT) {
    /* Parse source dir and apply to subdir module */
    if (!opts->source) {
#define SUBDIR_OPT "-omodules=subdir,subdir="
#define SUBDIR_OPT_LEN strlen(SUBDIR_OPT)
      char subdir_opt[PATH_MAX + SUBDIR_OPT_LEN];
      char *source = subdir_opt + SUBDIR_OPT_LEN;
      strcpy(subdir_opt, SUBDIR_OPT);

      if (realpath(arg, source)) {
        DIR *dp = opendir(source);
        if (dp) {
          opts->source = strdup(source);
          closedir(dp);
        }
      }

      if (!opts->source) {
        fprintf(stderr, "error: bad source dir '%s': %s\n",
                arg, strerror(errno));
        return -1;
      }

      assert(fuse_opt_add_arg(outargs, subdir_opt) == 0);
      return 0;
    }

    /* Parse mountpoint */
    if (!opts->mountpoint) {
      char mountpoint[PATH_MAX];

      if (realpath(arg, mountpoint)) {
        DIR *dp = opendir(mountpoint);
        if (dp) {
          opts->mountpoint = strdup(mountpoint);
          closedir(dp);
        }
      }

      if (!opts->mountpoint) {
        fprintf(stderr, "error: bad mountpoint '%s': %s\n",
                arg, strerror(errno));
        return -1;
      }

      assert(fuse_opt_add_arg(outargs, mountpoint) == 0);
      return 0;
    }
  }

  /* Pass through other options */
  return 1;
}

static void hookfs_load_config(const char *file)
{
  struct stat st;
  char *configs = NULL, *ptr, *tmp;
  int fd;

  if (stat(file, &st) < 0)
    return;

  fd = open(file, O_RDONLY);
  if (fd < 0)
    return;

  ptr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (ptr == MAP_FAILED)
    goto out_close_fd;

  configs = malloc(st.st_size + 1);
  if (!configs)
    goto out_unmap;

  memcpy(configs, ptr, st.st_size);
  configs[st.st_size] = '\0';

  tmp = configs;
  while ((tmp = strchr(tmp, '#'))) {
    while (*tmp != '\n' && *tmp != '\0')
      *tmp++ = '\n';
  }

  hookfs_ctx.configs = configs;
out_unmap:
  munmap(ptr, st.st_size);
out_close_fd:
  close(fd);
}

static const char *hookfs_get_config(const char *name, const char *def)
{
  static char buf[PATH_MAX];
  const char *config;

  if (!hookfs_ctx.configs)
    return def;

  strcpy(buf, name);
  strcat(buf, "=");

  config = strstr(hookfs_ctx.configs, buf);
  if (!config)
    return def;

  sscanf(config + strlen(buf), "%4095s", buf);
  return buf;
}

static int hookfs_get_config_int(const char *name, int def)
{
  const char *config = hookfs_get_config(name, NULL);

  if (config)
    return atoi(config);

  return def;
}

static void hookfs_parse_config(const char *progname)
{
  const char *config_file = hookfs_ctx.opts.config_file;
  const char *log_file = hookfs_ctx.opts.log_file;
  const char *scripts_dir = hookfs_ctx.opts.scripts_dir;
  char dir[PATH_MAX], *write_script, *release_script;

  if (!config_file)
    config_file = HOOKFS_CONFIG_FILE;

  hookfs_load_config(config_file);

  hookfs_ctx.debug = hookfs_get_config_int("debug", hookfs_ctx.opts.debug);

  if (!scripts_dir)
    scripts_dir = hookfs_get_config("scripts-dir", HOOKFS_SCRIPTS_DIR);

  realpath(scripts_dir, dir);

  write_script = malloc(strlen(dir) + strlen(HOOKFS_WRITE_SCRIPT) + 2);
  sprintf(write_script, "%s/%s", dir, HOOKFS_WRITE_SCRIPT);
  hookfs_ctx.write_script = write_script;

  release_script = malloc(strlen(dir) + strlen(HOOKFS_RELEASE_SCRIPT) + 2);
  sprintf(release_script, "%s/%s", dir, HOOKFS_RELEASE_SCRIPT);
  hookfs_ctx.release_script = release_script;

  if (!log_file)
    log_file = hookfs_get_config("log-file", HOOKFS_LOG_FILE);

  hookfs_ctx.log_fp = fopen(log_file, "wb+");
  if (!hookfs_ctx.log_fp) {
    HOOKFS_DEBUG("failed to open log file(%s)\n", log_file);
    log_file = "null";
  }

  HOOKFS_DEBUG("%s version: " HOOKFS_VERSION "\n"
               "config: %s\n" "log-file: %s\n" "scripts-dir: %s\n",
               progname, config_file, log_file, dir);
}

int main(int argc, char *argv[])
{
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  struct hookfs_options *opts = &hookfs_ctx.opts;
  int ret = -1;

  if (fuse_opt_parse(&args, opts, option_spec, hookfs_opt_proc) < 0)
    return -1;

  if (opts->show_version) {
    show_version(argv[0]);
    assert(fuse_opt_add_arg(&args, "--version") == 0);
    args.argv[0][0] = '\0';
    goto run;
  } else if (opts->show_help) {
    show_help(argv[0]);
    assert(fuse_opt_add_arg(&args, "--help") == 0);
    args.argv[0][0] = '\0';
    goto run;
  } else if (!opts->source) {
    fprintf(stderr, "error: no source specified\n");
    goto out;
  } else if (!opts->mountpoint) {
    fprintf(stderr, "error: no mountpoint specified\n");
    goto out;
  }

  /* Allow mounting on nonempty mountpoint */
  assert(fuse_opt_add_arg(&args, "-ononempty") == 0);

  /* Wrap write func */
  hookfs_op = xmp_oper;
  hookfs_op.write = hookfs_write;
  hookfs_op.release = hookfs_release;

  hookfs_parse_config(argv[0]);

  if (hookfs_ctx.debug) {
    int i;

    HOOKFS_DEBUG("process args:\n");
    for (i = 0; i < args.argc; i++)
      HOOKFS_DEBUG("args[%d]: %s\n", i, args.argv[i]);
  }

run:
  ret = fuse_main(args.argc, args.argv, &hookfs_op, NULL);
out:
  if (opts->source)
    free((void *)opts->source);
  if (opts->mountpoint)
    free((void *)opts->mountpoint);
  if (opts->config_file)
    free((void *)opts->config_file);
  if (opts->log_file)
    free((void *)opts->log_file);
  if (opts->scripts_dir)
    free((void *)opts->scripts_dir);
  if (hookfs_ctx.write_script)
    free((void *)hookfs_ctx.write_script);
  if (hookfs_ctx.release_script)
    free((void *)hookfs_ctx.release_script);
  if (hookfs_ctx.configs)
    free((void *)hookfs_ctx.configs);
  if (hookfs_ctx.log_fp)
    fclose(hookfs_ctx.log_fp);

  fuse_opt_free_args(&args);
  return ret;
}
