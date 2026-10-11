#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ncurses.h>
#include <errno.h>
static volatile sig_atomic_t sigint_received = 0;

static void handle_sigint(int sig) {
    (void)sig;
    sigint_received = 1;
}

#define MAX_DEVICES 16
#define PATH_MAX_LEN 4096
#define DEFAULT_BLOCK_SIZE (4 * 1024 * 1024)
#define MAX_FILES 1024
#define MAX_PARTS 16
#define WIPE_SIZE (1024 * 1024)
#define SECTOR_SIZE 512
#define FILAMENT_VERSION "1.0.2"

static int tui_mode = 0;
static size_t block_size = DEFAULT_BLOCK_SIZE;
static int skip_verify = 0;
static int do_unmount = 0;
static int compute_sha256 = 0;
static int quiet_mode = 0;
static int assume_yes = 0;
static FILE *log_fp = NULL;
static char verify_source_path[PATH_MAX_LEN] = {0};

typedef struct {
    char name[32];
    char path[64];
    char model[64];
    char serial[64];
    unsigned long long size_bytes;
    int removable;
    int mounted;
    int system_device;
    char fs_type[16];
    char part_table[16];
} USBDevice;

typedef struct {
    char name[256];
    int is_dir;
    unsigned long long size;
    int is_hidden;
} FileEntry;

typedef struct {
    char name[32];
    char path[64];
    unsigned long long size_bytes;
} PartitionInfo;

typedef struct {
    uint32_t h[8];
    uint64_t bits;
    unsigned char buf[64];
    size_t buf_len;
} Sha256;

static USBDevice devices[MAX_DEVICES];
static FileEntry file_list[MAX_FILES];
static PartitionInfo partitions[MAX_PARTS];
static char current_dir[PATH_MAX_LEN];
static char iso_path[PATH_MAX_LEN];
static char target_path[64];
static int device_count, selected_device;
static int file_count, file_selected;
static int partition_count, selected_partition;
static int phase, running = 1;
static int progress_mode;
static unsigned long long total_bytes, written_bytes;
static unsigned long long target_size_bytes;
static time_t write_start_time;
static int action;
static int format_fs_type;
static int format_use_gpt;
static char format_label[32];
static int show_hidden_files;
static unsigned char source_hash[32];
static int buffering_state = 0;
static char pending_hash_output[256] = {0};
static unsigned long long honest_bytes = 0;
static time_t honest_start = 0;
static int source_is_pipe = 0;

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_compress(Sha256 *s, const unsigned char block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    uint32_t e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + sha256_k[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    s->h[0] += a;
    s->h[1] += b;
    s->h[2] += c;
    s->h[3] += d;
    s->h[4] += e;
    s->h[5] += f;
    s->h[6] += g;
    s->h[7] += h;
}

static void sha256_init(Sha256 *s) {
    s->h[0] = 0x6a09e667;
    s->h[1] = 0xbb67ae85;
    s->h[2] = 0x3c6ef372;
    s->h[3] = 0xa54ff53a;
    s->h[4] = 0x510e527f;
    s->h[5] = 0x9b05688c;
    s->h[6] = 0x1f83d9ab;
    s->h[7] = 0x5be0cd19;
    s->bits = 0;
    s->buf_len = 0;
}

static void sha256_update(Sha256 *s, const void *data, size_t len) {
    const unsigned char *p = data;
    s->bits += (uint64_t)len * 8;

    while (len > 0) {
        size_t space = 64 - s->buf_len;
        size_t take = (len < space) ? len : space;
        memcpy(s->buf + s->buf_len, p, take);
        s->buf_len += take;
        p += take;
        len -= take;
        if (s->buf_len == 64) {
            sha256_compress(s, s->buf);
            s->buf_len = 0;
        }
    }
}

static void sha256_final(Sha256 *s, unsigned char out[32]) {
    uint64_t bits = s->bits;
    unsigned char pad = 0x80;
    sha256_update(s, &pad, 1);
    unsigned char zero = 0;
    while (s->buf_len != 56) {
        sha256_update(s, &zero, 1);
    }
    unsigned char len_bytes[8];
    for (int i = 0; i < 8; i++) {
        len_bytes[i] = (unsigned char)(bits >> (56 - i * 8));
    }
    sha256_update(s, len_bytes, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (unsigned char)(s->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(s->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(s->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(s->h[i]);
    }
}

static void sha256_hex(const unsigned char hash[32], char out[65]) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = hex[hash[i] >> 4];
        out[i * 2 + 1] = hex[hash[i] & 0x0F];
    }
    out[64] = '\0';
}

static void zero_device(const char *dev_path, unsigned long long size);
static int  format_fat32(const char *dev_path, const char *label, int use_gpt);
static int  format_exfat(const char *dev_path, const char *label);
static int  is_mounted(const char *name);
static int  is_system_device(const char *name);
static unsigned long long get_device_size(const char *name);
static unsigned long long get_device_size_checked(const char *path);
static int wipe_first_mb(const char *dev_path);

static void log_line(const char *fmt, ...) {
    if (!log_fp) return;
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    fprintf(log_fp, "[%04d-%02d-%02d %02d:%02d:%02d] ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
    va_list ap; va_start(ap, fmt);
    vfprintf(log_fp, fmt, ap);
    va_end(ap);
    fputc('\n', log_fp);
    fflush(log_fp);
}

static const char *detect_compression(const char *path) {
    size_t len = strlen(path);
    if (len > 3 && strcmp(path + len - 3, ".gz") == 0)  return "gzip -dc";
    if (len > 3 && strcmp(path + len - 3, ".xz") == 0)  return "xz -dc";
    if (len > 3 && strcmp(path + len - 3, ".bz2") == 0) return "bzip2 -dc";
    if (len > 4 && strcmp(path + len - 4, ".zst") == 0) return "zstd -dc";
    return NULL;
}

static FILE *open_source_fp(const char *path) {
    const char *dec = detect_compression(path);
    if (dec) {
        char cmd[PATH_MAX_LEN + 64];
        snprintf(cmd, sizeof(cmd), "%s -- '%s'", dec, path);
        source_is_pipe = 1;
        return popen(cmd, "r");
    }
    source_is_pipe = 0;
    return fopen(path, "rb");
}

static int close_source_fp(FILE *fp) {
    if (source_is_pipe) return pclose(fp);
    return fclose(fp);
}

static int run_tool(const char *path, char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (tui_mode) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                if (devnull > STDERR_FILENO) close(devnull);
            }
        }
        execvp(path, argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static int find_tool(const char *name, const char *alt, char *out, size_t out_size) {
    const char *dirs[] = {"/sbin", "/usr/sbin", "/bin", "/usr/bin", NULL};
    for (int i = 0; dirs[i]; i++) {
        snprintf(out, out_size, "%s/%s", dirs[i], name);
        if (access(out, X_OK) == 0) return 0;
    }
    if (alt) {
        for (int i = 0; dirs[i]; i++) {
            snprintf(out, out_size, "%s/%s", dirs[i], alt);
            if (access(out, X_OK) == 0) return 0;
        }
    }
    return -1;
}

static const char *device_basename(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int check_target_safe(const char *path) {
    const char *name = device_basename(path);
    if (is_mounted(name) || is_system_device(name)) {
        fprintf(stderr, "Error: device %s is mounted or a system device.\n", path);
        return -1;
    }
    return 0;
}

static unsigned long long get_device_size_checked(const char *path) {
    unsigned long long size = get_device_size(device_basename(path));
    if (size == 0) {
        fprintf(stderr, "Error: cannot determine size of device %s.\n", path);
    }
    return size;
}

static int unmount_device(const char *dev_name) {
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) return -1;

    char entries[64][128];
    int entry_count = 0;
    char prefix[80];
    snprintf(prefix, sizeof(prefix), "/dev/%s", dev_name);
    size_t prefix_len = strlen(prefix);

    char line[512];
    while (fgets(line, sizeof(line), f) && entry_count < 64) {
        if (strncmp(line, prefix, prefix_len) != 0) continue;
        char next = line[prefix_len];
        if (next == ' ' || (next >= '0' && next <= '9') || next == 'p') {
            if (sscanf(line, "%127s", entries[entry_count]) == 1)
                entry_count++;
        }
    }
    fclose(f);

    if (entry_count == 0) return 0;

    char tool[256];
    if (find_tool("umount", NULL, tool, sizeof(tool)) < 0) return -1;

    for (int i = 0; i < entry_count; i++) {
        char *argv[] = { tool, entries[i], NULL };
        run_tool(tool, argv);
    }
    return 0;
}

static int join_path(char *out, int out_size, const char *dir, const char *name) {
    int len = (strcmp(dir, "/") == 0)
        ? snprintf(out, (size_t)out_size, "/%s", name)
        : snprintf(out, (size_t)out_size, "%s/%s", dir, name);
    return (len >= 0 && len < out_size);
}

static int read_file_str(const char *path, char *buf, int size) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(buf, size, f)) { fclose(f); return 0; }
    buf[strcspn(buf, "\n")] = 0;
    fclose(f);
    return 1;
}

static unsigned long long get_block_size(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned long long sectors = 0;
    if (fscanf(f, "%llu", &sectors) != 1) { fclose(f); return 0; }
    fclose(f);
    return sectors * 512ULL;
}

static unsigned long long get_device_size(const char *name) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/block/%s/size", name);
    return get_block_size(path);
}

static int is_mounted(const char *name) {
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) return 0;
    char line[512], dev[64];
    int dev_len = snprintf(dev, sizeof(dev), "/dev/%s", name);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, dev, (size_t)dev_len) == 0) {
            char next = line[dev_len];
            if (next == ' ' || next == '\t' || (next >= '0' && next <= '9'))
                { fclose(f); return 1; }
            if (next == 'p' && line[dev_len + 1] >= '0' && line[dev_len + 1] <= '9')
                { fclose(f); return 1; }
        }
    }
    fclose(f);
    return 0;
}

static int is_system_device(const char *name) {
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) return 0;
    char line[512], dev[64];
    int dev_len = snprintf(dev, sizeof(dev), "/dev/%s", name);
    int result = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, dev, (size_t)dev_len) != 0) continue;
        char next = line[dev_len];
        if (next != ' ' && next != '\t' && next != 'p'
            && !(next >= '0' && next <= '9')) continue;
        if (next == 'p') {
            char d = line[dev_len + 1];
            if (d < '0' || d > '9') continue;
        }
        char mp[256];
        if (sscanf(line, "%*s %255s", mp) != 1) continue;
        if (strncmp(mp, "/media/", 7) == 0) continue;
        if (strncmp(mp, "/run/media/", 11) == 0) continue;
        if (strcmp(mp, "/mnt") == 0) continue;
        if (strncmp(mp, "/mnt/", 5) == 0) continue;
        result = 1;
        break;
    }
    fclose(f);
    return result;
}

static void detect_partition_table(const char *dev_path, char *out) {
    int fd = open(dev_path, O_RDONLY);
    if (fd < 0) { strcpy(out, "Unknown"); return; }
    unsigned char mbr[512];
    if (read(fd, mbr, 512) == 512) {
        if (mbr[510] == 0x55 && mbr[511] == 0xAA) {
            if (mbr[446] == 0xEE) strcpy(out, "GPT");
            else strcpy(out, "MBR");
        } else {
            strcpy(out, "None");
        }
    } else {
        strcpy(out, "Unknown");
    }
    close(fd);
}

static unsigned long long read_partition_start(int fd, int is_gpt) {
    unsigned char buf[512];
    if (is_gpt) {
        lseek(fd, 2 * SECTOR_SIZE, SEEK_SET);
        unsigned char entry[128];
        if (read(fd, entry, 128) != 128) return 0;
        uint32_t lo, hi;
        memcpy(&lo, entry + 32, 4);
        memcpy(&hi, entry + 36, 4);
        return (unsigned long long)lo | ((unsigned long long)hi << 32);
    }
    lseek(fd, 0, SEEK_SET);
    if (read(fd, buf, 512) != 512) return 0;
    uint32_t lba;
    memcpy(&lba, buf + 446 + 8, 4);
    return lba;
}

static void detect_fs_type(const char *dev_path, char *out) {
    strcpy(out, "Unknown");
    int fd = open(dev_path, O_RDONLY);
    if (fd < 0) return;

    unsigned char mbr[512];
    if (read(fd, mbr, 512) != 512) { close(fd); return; }
    if (mbr[510] != 0x55 || mbr[511] != 0xAA) { strcpy(out, "None"); close(fd); return; }

    int is_gpt = (mbr[446] == 0xEE);
    unsigned long long part_start = read_partition_start(fd, is_gpt);
    if (part_start == 0) { close(fd); return; }

    unsigned char sig[512];
    lseek(fd, (off_t)(part_start * SECTOR_SIZE), SEEK_SET);
    if (read(fd, sig, 512) != 512) { close(fd); return; }

    if (memcmp(sig + 3, "NTFS", 4) == 0)   { strcpy(out, "NTFS"); close(fd); return; }
    if (memcmp(sig + 3, "EXFAT", 5) == 0)  { strcpy(out, "exFAT"); close(fd); return; }
    if (memcmp(sig + 82, "FAT32", 5) == 0) { strcpy(out, "FAT32"); close(fd); return; }
    if (memcmp(sig + 54, "FAT", 3) == 0)   { strcpy(out, "FAT"); close(fd); return; }

    unsigned char ext_sig[2];
    lseek(fd, (off_t)(part_start * SECTOR_SIZE + 1024 + 56), SEEK_SET);
    if (read(fd, ext_sig, 2) == 2 && ext_sig[0] == 0x53 && ext_sig[1] == 0xEF)
        strcpy(out, "ext");

    close(fd);
}

static int list_usb_devices(void) {
    DIR *d = opendir("/sys/block");
    if (!d) return 0;
    struct dirent *e;
    device_count = 0;

    while ((e = readdir(d)) != NULL && device_count < MAX_DEVICES) {
        if (e->d_name[0] == '.') continue;
        if (strncmp(e->d_name, "sd", 2) != 0 && strncmp(e->d_name, "nvme", 4) != 0)
            continue;

        char name[32];
        memcpy(name, e->d_name, sizeof(name) - 1);
        name[sizeof(name) - 1] = '\0';

        char path[128];
        snprintf(path, sizeof(path), "/sys/block/%s/removable", name);
        int removable = 0;
        FILE *f = fopen(path, "r");
        if (f) {
            if (fscanf(f, "%d", &removable) != 1) removable = 0;
            fclose(f);
        }

        if (!removable) continue;

        USBDevice *dev = &devices[device_count];
        memset(dev, 0, sizeof(USBDevice));
        memcpy(dev->name, name, sizeof(dev->name) - 1);
        dev->name[sizeof(dev->name) - 1] = '\0';
        snprintf(dev->path, sizeof(dev->path), "/dev/%s", name);

        snprintf(path, sizeof(path), "/sys/block/%s/device/model", name);
        read_file_str(path, dev->model, sizeof(dev->model));
        if (dev->model[0] == '\0') strcpy(dev->model, "Unknown");

        snprintf(path, sizeof(path), "/sys/block/%s/device/serial", name);
        read_file_str(path, dev->serial, sizeof(dev->serial));
        if (dev->serial[0] == '\0') strcpy(dev->serial, "Unknown");

        dev->size_bytes = get_device_size(name);
        dev->removable = removable;
        dev->mounted = is_mounted(name);
        dev->system_device = is_system_device(name);
        detect_partition_table(dev->path, dev->part_table);
        detect_fs_type(dev->path, dev->fs_type);

        device_count++;
    }
    closedir(d);

    for (int i = 0; i < device_count - 1; i++) {
        for (int j = i + 1; j < device_count; j++) {
            if (devices[i].size_bytes < devices[j].size_bytes) {
                USBDevice tmp = devices[i];
                devices[i] = devices[j];
                devices[j] = tmp;
            }
        }
    }

    return device_count;
}

static int list_partitions(const char *dev_name) {
    char sys_path[128];
    snprintf(sys_path, sizeof(sys_path), "/sys/block/%s", dev_name);
    DIR *d = opendir(sys_path);
    if (!d) return 0;
    struct dirent *e;
    partition_count = 0;
    selected_partition = 0;
    int dev_len = (int)strlen(dev_name);
    int sep = 0;
    if (dev_len > 0 && dev_name[dev_len - 1] >= '0' && dev_name[dev_len - 1] <= '9')
        sep = 1;

    while ((e = readdir(d)) != NULL && partition_count < MAX_PARTS) {
        if (strncmp(e->d_name, dev_name, dev_len) != 0) continue;
        int off = dev_len;
        if (sep) {
            if (e->d_name[off] != 'p') continue;
            off++;
        }
        if (e->d_name[off] < '0' || e->d_name[off] > '9') continue;

        char part_name[32];
        memcpy(part_name, e->d_name, sizeof(part_name) - 1);
        part_name[sizeof(part_name) - 1] = '\0';

        PartitionInfo *p = &partitions[partition_count];
        memset(p, 0, sizeof(PartitionInfo));
        memcpy(p->name, part_name, sizeof(p->name) - 1);
        p->name[sizeof(p->name) - 1] = '\0';
        snprintf(p->path, sizeof(p->path), "/dev/%s", part_name);

        char size_path[192];
        snprintf(size_path, sizeof(size_path), "%s/%s/size", sys_path, part_name);
        p->size_bytes = get_block_size(size_path);

        partition_count++;
    }
    closedir(d);
    return partition_count;
}

static void human_size(unsigned long long bytes, char *out, int out_size) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = (double)bytes;
    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }
    if (unit == 0) {
        snprintf(out, (size_t)out_size, "%llu B", bytes);
    } else {
        snprintf(out, (size_t)out_size, "%.1f %s", size, units[unit]);
    }
}

static int list_directory(const char *path) {
    DIR *d = opendir(path);
    if (!d) return 0;
    struct dirent *e;
    file_count = 0;
    file_selected = 0;

    while ((e = readdir(d)) != NULL && file_count < MAX_FILES) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        if (!show_hidden_files && e->d_name[0] == '.') continue;

        FileEntry *fe = &file_list[file_count];
        memset(fe, 0, sizeof(FileEntry));
        memcpy(fe->name, e->d_name, sizeof(fe->name) - 1);
        fe->name[sizeof(fe->name) - 1] = '\0';
        fe->is_hidden = (e->d_name[0] == '.');

        char full_path[PATH_MAX_LEN];
        if (join_path(full_path, sizeof(full_path), path, e->d_name)) {
            struct stat st;
            if (stat(full_path, &st) == 0) {
                fe->is_dir = S_ISDIR(st.st_mode);
                fe->size = (unsigned long long)st.st_size;
            }
        }

        file_count++;
    }
    closedir(d);

    for (int i = 0; i < file_count - 1; i++) {
        for (int j = i + 1; j < file_count; j++) {
            if (file_list[i].is_dir != file_list[j].is_dir) {
                if (!file_list[i].is_dir) {
                    FileEntry tmp = file_list[i];
                    file_list[i] = file_list[j];
                    file_list[j] = tmp;
                }
            } else if (strcmp(file_list[i].name, file_list[j].name) > 0) {
                FileEntry tmp = file_list[i];
                file_list[i] = file_list[j];
                file_list[j] = tmp;
            }
        }
    }

    return file_count;
}

static void draw_main_menu(void) {
    clear();
    attron(A_REVERSE);
    mvprintw(0, 0, " FILAMENT - USB Tool ");
    attroff(A_REVERSE);
    mvprintw(2, 2, "Select operation:");
    mvprintw(4, 4, "1. Write ISO to USB");
    mvprintw(5, 4, "2. Format USB");
    mvprintw(6, 4, "3. Wipe/Zero USB");
    mvprintw(7, 4, "4. Quit");
    mvprintw(LINES - 2, 2, "Press 1-4 to select");
    refresh();
}

static void draw_device_select(void) {
    clear();
    attron(A_REVERSE);
    mvprintw(0, 0, " FILAMENT - USB Image Writer ");
    attroff(A_REVERSE);
    mvprintw(2, 2, "Select USB device:");

    int max_rows = LINES - 5;
    if (max_rows < 1) max_rows = 1;
    int start = 0;
    if (selected_device >= max_rows) start = selected_device - max_rows + 1;

    for (int i = start; i < device_count && i < start + max_rows; i++) {
        int row = 3 + (i - start);
        if (i == selected_device) attron(A_REVERSE);
        char size_str[32];
        human_size(devices[i].size_bytes, size_str, sizeof(size_str));
        mvprintw(row, 4, "%s  %s  %s  %s  %s  %s%s%s",
                 devices[i].path, devices[i].model, size_str, devices[i].serial,
                 devices[i].fs_type, devices[i].part_table,
                 devices[i].mounted ? " [MOUNTED]" : "",
                 devices[i].system_device ? " [SYSTEM]" : "");
        if (i == selected_device) attroff(A_REVERSE);
    }

    mvprintw(LINES - 2, 2, "Up/Down: select  Enter: choose  Q: quit");
    refresh();
}

static void draw_partition_select(void) {
    clear();
    attron(A_REVERSE);
    mvprintw(0, 0, " FILAMENT - Write Target ");
    attroff(A_REVERSE);
    mvprintw(2, 2, "Select target:");

    char size_str[32];
    human_size(devices[selected_device].size_bytes, size_str, sizeof(size_str));
    if (selected_partition == 0) attron(A_REVERSE);
    mvprintw(3, 4, "[Whole device]  %s  %s", devices[selected_device].path, size_str);
    if (selected_partition == 0) attroff(A_REVERSE);

    for (int i = 0; i < partition_count; i++) {
        if (selected_partition == i + 1) attron(A_REVERSE);
        human_size(partitions[i].size_bytes, size_str, sizeof(size_str));
        mvprintw(4 + i, 4, "%s  %s", partitions[i].path, size_str);
        if (selected_partition == i + 1) attroff(A_REVERSE);
    }

    mvprintw(LINES - 2, 2, "Up/Down: select  Enter: choose  Backspace: back");
    refresh();
}

static void draw_file_browser(void) {
    clear();
    attron(A_REVERSE);
    mvprintw(0, 0, " FILAMENT - Select ISO Image ");
    attroff(A_REVERSE);
    mvprintw(2, 2, "Directory: %s%s", current_dir, show_hidden_files ? " [hidden]" : "");
    mvprintw(3, 2, "----------------------------------------");

    int max_visible = LINES - 8;
    if (max_visible < 1) max_visible = 1;
    int start_idx = (file_selected >= max_visible) ? file_selected - max_visible + 1 : 0;

    for (int i = 0; i < max_visible && (start_idx + i) < file_count; i++) {
        int idx = start_idx + i;
        if (idx == file_selected) attron(A_REVERSE);

        char size_str[32] = "";
        if (!file_list[idx].is_dir)
            human_size(file_list[idx].size, size_str, sizeof(size_str));

        mvprintw(4 + i, 4, "%s%s%s", file_list[idx].name,
                 file_list[idx].is_dir ? "/" : "",
                 file_list[idx].is_hidden ? " [hidden]" : "");
        if (!file_list[idx].is_dir && size_str[0])
            mvprintw(4 + i, 30, "%s", size_str);

        if (idx == file_selected) attroff(A_REVERSE);
    }

    if (file_count > max_visible) {
        mvprintw(LINES - 4, 2, "--- %d more files ---", file_count - max_visible);
    }
    mvprintw(LINES - 3, 2, "Up/Down: navigate  Enter: open/select  H: hidden");
    mvprintw(LINES - 2, 2, "Backspace: parent  Q: cancel");
    refresh();
}

static void draw_confirm(void) {
    clear();
    attron(A_REVERSE);
    mvprintw(0, 0, " FILAMENT - USB Image Writer ");
    attroff(A_REVERSE);

    mvprintw(2, 2, "Confirm write:");
    mvprintw(4, 4, "Target: %s", target_path);
    mvprintw(5, 4, "Model:  %s", devices[selected_device].model);
    mvprintw(6, 4, "Serial: %s", devices[selected_device].serial);
    char size_str[32];
    human_size(target_size_bytes, size_str, sizeof(size_str));
    mvprintw(7, 4, "Size:   %s", size_str);
    mvprintw(8, 4, "ISO:    %s", iso_path);
    mvprintw(9, 4, "SHA-256: %s", compute_sha256 ? "on" : "off");

    int row = 11;
    if (!source_is_pipe && detect_compression(iso_path) == NULL) {
        struct stat st;
        if (stat(iso_path, &st) == 0 && (unsigned long long)st.st_size > target_size_bytes) {
            wattron(stdscr, COLOR_PAIR(3) | A_BOLD);
            mvprintw(row++, 4, "ERROR: ISO is larger than target!");
            wattroff(stdscr, COLOR_PAIR(3) | A_BOLD);
        }
    }

    FILE *fp = fopen(iso_path, "rb");
    if (fp) {
        unsigned char sector[512];
        if (fread(sector, 1, 512, fp) == 512) {
            if (sector[510] != 0x55 || sector[511] != 0xAA) {
                wattron(stdscr, COLOR_PAIR(2) | A_BOLD);
                mvprintw(row++, 4, "WARNING: This ISO may not be bootable when written raw.");
                wattroff(stdscr, COLOR_PAIR(2) | A_BOLD);
            }
        }
        fclose(fp);
    }

    if (devices[selected_device].mounted)
        mvprintw(row++, 4, "WARNING: Device is mounted!");
    if (devices[selected_device].system_device)
        mvprintw(row++, 4, "WARNING: Device contains system partitions!");

    mvprintw(LINES - 2, 2, "V: toggle SHA-256  Enter: type '%s' to confirm  Backspace: cancel",
             devices[selected_device].name);
    refresh();
}

static void draw_format_options(void) {
    clear();
    attron(A_REVERSE);
    mvprintw(0, 0, " FILAMENT - Format USB ");
    attroff(A_REVERSE);
    mvprintw(2, 2, "Format options for %s:", devices[selected_device].path);

    const char *fs_names[] = {"FAT32", "VFAT", "exFAT"};
    mvprintw(4, 4, "Filesystem: %s", fs_names[format_fs_type]);
    mvprintw(5, 4, "Partition table: %s", format_use_gpt ? "GPT" : "MBR");
    mvprintw(6, 4, "Label: %s", format_label[0] ? format_label : "(none)");
    mvprintw(8, 2, "F: cycle filesystem (FAT32/VFAT/exFAT)");
    mvprintw(9, 2, "T: toggle partition table (MBR/GPT)");
    mvprintw(10, 2, "L: set label");
    mvprintw(11, 2, "Enter: start format  Backspace: back");
    mvprintw(13, 2, "Uses mkfs.vfat / mkfs.exfat if available.");
    if (format_fs_type == 2 && format_use_gpt)
        mvprintw(15, 2, "Note: exFAT ignores the GPT toggle.");
    refresh();
}

static void draw_zero_confirm(void) {
    clear();
    attron(A_REVERSE);
    mvprintw(0, 0, " FILAMENT - Wipe/Zero USB ");
    attroff(A_REVERSE);
    mvprintw(2, 2, "Wipe/Zero device:");
    mvprintw(4, 4, "Target: %s", devices[selected_device].path);
    mvprintw(5, 4, "Model:  %s", devices[selected_device].model);
    char size_str[32];
    human_size(devices[selected_device].size_bytes, size_str, sizeof(size_str));
    mvprintw(6, 4, "Size:   %s", size_str);
    mvprintw(8, 2, "Q: Quick wipe (first 1MB)");
    mvprintw(9, 2, "F: Full zero (entire device, slow)");
    mvprintw(10, 2, "Any other key: cancel");
    refresh();
}

static void draw_progress(void) {
    if (!tui_mode) {
        if (quiet_mode) return;
        if (total_bytes) {
            double percent = (double)written_bytes / (double)total_bytes * 100.0;
            fprintf(stderr, "\r%.1f%%  %llu / %llu bytes", percent, written_bytes, total_bytes);
        } else {
            fprintf(stderr, "\r%llu bytes", written_bytes);
        }
        fflush(stderr);
        return;
    }

    clear();
    attron(A_REVERSE);
    switch (progress_mode) {
        case 0: mvprintw(0, 0, " FILAMENT - Writing Image "); break;
        case 1: mvprintw(0, 0, " FILAMENT - Verifying Image "); break;
        case 2: mvprintw(0, 0, " FILAMENT - Formatting "); break;
        case 3: mvprintw(0, 0, " FILAMENT - Zeroing "); break;
        default: mvprintw(0, 0, " FILAMENT - Progress ");
    }
    attroff(A_REVERSE);
    mvprintw(2, 2, "%s", target_path);

    int bar_width = COLS - 10;
    if (bar_width < 10) bar_width = 10;

    if (total_bytes) {
        double percent = (double)written_bytes / (double)total_bytes * 100.0;
        int filled = (int)(percent * bar_width / 100.0);
        mvprintw(4, 2, "[");
        for (int i = 0; i < bar_width; i++) addch(i < filled ? '=' : ' ');
        addch(']');
        mvprintw(5, 2, "%.1f%% complete", percent);
    } else {
        mvprintw(4, 2, "[");
        for (int i = 0; i < bar_width; i++)
            addch(i == (int)((written_bytes / block_size) % (unsigned long long)bar_width) ? '=' : ' ');
        addch(']');
        mvprintw(5, 2, "(streaming)");
    }

    char written_str[32];
    human_size(written_bytes, written_str, sizeof(written_str));
    if (total_bytes) {
        char total_str[32];
        human_size(total_bytes, total_str, sizeof(total_str));
        mvprintw(7, 2, "%s / %s", written_str, total_str);
    } else {
        mvprintw(7, 2, "%s written", written_str);
    }

    time_t now = time(NULL);
    if (buffering_state || honest_start == 0) {
        mvprintw(8, 2, "Speed: buffering...");
        mvprintw(9, 2, "ETA: --:--");
    } else {
        double elapsed = difftime(now, honest_start);
        if (elapsed > 0 && written_bytes > honest_bytes) {
            double speed = (written_bytes - honest_bytes) / elapsed;
            char speed_str[32];
            human_size((unsigned long long)speed, speed_str, sizeof(speed_str));
            mvprintw(8, 2, "Speed: %s/s (writing)", speed_str);
            if (speed > 0 && total_bytes) {
                double eta = (double)(total_bytes - written_bytes) / speed;
                mvprintw(9, 2, "ETA: %02d:%02d", (int)(eta / 60), (int)eta % 60);
            }
        }
    }

    refresh();
}

static int do_write_verify(int mode) {
    FILE *src = open_source_fp(iso_path);
    if (!src) {
        fprintf(stderr, "Error: cannot open ISO file %s\n", iso_path);
        return 0;
    }
    int src_fd = fileno(src);

    int dst_flags = (mode == 0) ? O_WRONLY : O_RDONLY;
    int dst_fd = open(target_path, dst_flags);
    if (dst_fd < 0) {
        fprintf(stderr, "Error: cannot open target device %s\n", target_path);
        close_source_fp(src);
        return 0;
    }

    if (!source_is_pipe) {
        struct stat st;
        if (fstat(src_fd, &st) != 0) {
            fprintf(stderr, "Error: cannot stat ISO file\n");
            close_source_fp(src);
            close(dst_fd);
            return 0;
        }
        total_bytes = (unsigned long long)st.st_size;
    } else {
        total_bytes = 0;
    }

    void *src_buf = malloc(block_size);
    void *dst_buf = malloc(block_size);
    if (!src_buf || !dst_buf) {
        fprintf(stderr, "Error: out of memory\n");
        free(src_buf); free(dst_buf);
        close_source_fp(src);
        close(dst_fd);
        return 0;
    }

    Sha256 hash;
    if (compute_sha256) sha256_init(&hash);

    written_bytes = 0;
    write_start_time = time(NULL);
    progress_mode = mode;
    if (mode == 1) {
        buffering_state = 0;
        honest_start = time(NULL);
        honest_bytes = 0;
    } else {
        buffering_state = 1;
        honest_start = 0;
        honest_bytes = 0;
    }

    size_t n;
    while ((n = fread(src_buf, 1, block_size, src)) > 0 && !sigint_received) {
        if (mode == 0) {
            if (compute_sha256) sha256_update(&hash, src_buf, n);
            size_t off = 0;
            while (off < n && !sigint_received) {
                struct timespec wt0, wt1;
                clock_gettime(CLOCK_MONOTONIC, &wt0);
                ssize_t w = write(dst_fd, (char *)src_buf + off, n - off);
                clock_gettime(CLOCK_MONOTONIC, &wt1);
                if (w < 0) {
                    fprintf(stderr, "Error: write failed\n");
                    goto fail;
                }
                double write_ms = (wt1.tv_sec - wt0.tv_sec) * 1000.0
                                + (wt1.tv_nsec - wt0.tv_nsec) / 1000000.0;
                buffering_state = (write_ms < 5.0);
                if (!buffering_state && honest_start == 0) {
                    honest_start = time(NULL);
                    honest_bytes = written_bytes;
                }
                off += (size_t)w;
                written_bytes += (unsigned long long)w;
                draw_progress();
                if (tui_mode) {
                    timeout(0);
                    int ch = getch();
                    timeout(-1);
                    if (ch == 'q' || ch == 'Q') { progress_mode = -1; goto done; }
                }
            }
        } else {
            size_t off = 0;
            while (off < n) {
                ssize_t r = read(dst_fd, (char *)dst_buf + off, n - off);
                if (r < 0) {
                    fprintf(stderr, "Error: read back failed\n");
                    goto fail;
                }
                if (r == 0) {
                    fprintf(stderr, "Error: unexpected EOF during verification\n");
                    goto fail;
                }
                off += (size_t)r;
            }
            if (compute_sha256) sha256_update(&hash, dst_buf, n);
            if (memcmp(src_buf, dst_buf, n) != 0) {
                fprintf(stderr, "Error: verification failed - data mismatch\n");
                goto fail;
            }
            written_bytes += (unsigned long long)n;
            draw_progress();
        }
    }

    if (ferror(src) && !sigint_received) {
        fprintf(stderr, "Error: source read failed\n");
        goto fail;
    }

done:
    if (mode == 0 && progress_mode != -1) {
        if (tui_mode) {
            clear();
            attron(A_REVERSE);
            mvprintw(0, 0, " FILAMENT - Syncing to Device ");
            attroff(A_REVERSE);
            mvprintw(2, 2, "%s", target_path);
            mvprintw(4, 2, "Flushing page cache to USB device...");
            mvprintw(6, 2, "This may take a minute on slow devices.");
            mvprintw(8, 2, "Do not remove the device.");
            refresh();
        } else if (!quiet_mode) {
            fprintf(stderr, "\nSyncing to device (this may take a minute)...\n");
        }
        fsync(dst_fd);
    }

    if (!tui_mode && !quiet_mode) fprintf(stderr, "\n");

    if (compute_sha256 && progress_mode != -1) {
        unsigned char final_hash[32];
        char hex[65];
        sha256_final(&hash, final_hash);
        sha256_hex(final_hash, hex);

        if (mode == 0) {
            memcpy(source_hash, final_hash, 32);
        } else {
            char src_hex[65];
            sha256_hex(source_hash, src_hex);
            snprintf(pending_hash_output, sizeof(pending_hash_output),
                     "SHA-256 (source): %s\n"
                     "SHA-256 (target): %s\n"
                     "SHA-256 match: %s",
                     src_hex, hex,
                     memcmp(source_hash, final_hash, 32) == 0 ? "yes" : "NO");
        }
    }

    free(src_buf); free(dst_buf);
    close_source_fp(src);
    close(dst_fd);
    sigint_received = 0;
    if (mode == 0 && skip_verify) return written_bytes > 0;
    if (mode == 0) return written_bytes > 0;
    return written_bytes == total_bytes || total_bytes == 0;

fail:
    if (!tui_mode && !quiet_mode) fprintf(stderr, "\n");
    free(src_buf); free(dst_buf);
    close_source_fp(src);
    close(dst_fd);
    sigint_received = 0;
    return 0;
}

static void draw_done(int success) {
    clear();
    mvprintw(2, 2, success ? "Operation complete." : "Operation failed.");
    mvprintw(4, 2, "Sync complete. Safe to remove.");
    mvprintw(6, 2, "Press any key to exit.");
    refresh();
    timeout(-1);
    getch();
}

static void device_select_phase(void) {
    draw_device_select();
    int ch = getch();
    if (ch == KEY_UP && selected_device > 0) selected_device--;
    else if (ch == KEY_DOWN && selected_device < device_count - 1) selected_device++;
    else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
        if (devices[selected_device].mounted || devices[selected_device].system_device) {
            mvprintw(LINES - 3, 2, "Cannot use this device: mounted or system device.");
            refresh();
            getch();
        } else {
            if (action == 1) {
                if (list_partitions(devices[selected_device].name) > 0) {
                    phase = 2;
                    selected_partition = 0;
                } else {
                    strcpy(target_path, devices[selected_device].path);
                    target_size_bytes = devices[selected_device].size_bytes;
                    phase = 3;
                    list_directory(current_dir);
                }
            } else if (action == 2) {
                strcpy(target_path, devices[selected_device].path);
                target_size_bytes = devices[selected_device].size_bytes;
                format_fs_type = 0;
                format_use_gpt = 0;
                format_label[0] = '\0';
                phase = 5;
            } else if (action == 3) {
                strcpy(target_path, devices[selected_device].path);
                target_size_bytes = devices[selected_device].size_bytes;
                phase = 6;
            }
        }
    } else if (ch == 'q' || ch == 'Q') running = 0;
}

static void partition_select_phase(void) {
    draw_partition_select();
    int ch = getch();
    if (ch == KEY_UP && selected_partition > 0) selected_partition--;
    else if (ch == KEY_DOWN && selected_partition < partition_count) selected_partition++;
    else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
        if (selected_partition == 0) {
            strcpy(target_path, devices[selected_device].path);
            target_size_bytes = devices[selected_device].size_bytes;
        } else {
            int idx = selected_partition - 1;
            strcpy(target_path, partitions[idx].path);
            target_size_bytes = partitions[idx].size_bytes;
        }
        phase = 3;
        list_directory(current_dir);
    } else if (ch == KEY_BACKSPACE || ch == 127) phase = 1;
}

static void file_browse_phase(void) {
    draw_file_browser();
    int ch = getch();
    if (ch == KEY_UP && file_selected > 0) file_selected--;
    else if (ch == KEY_DOWN && file_selected < file_count - 1) file_selected++;
    else if (ch == 'h' || ch == 'H') {
        show_hidden_files = !show_hidden_files;
        list_directory(current_dir);
    } else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
        FileEntry *fe = &file_list[file_selected];
        if (fe->is_dir) {
            char new_dir[PATH_MAX_LEN];
            if (join_path(new_dir, sizeof(new_dir), current_dir, fe->name) &&
                list_directory(new_dir) > 0)
                strcpy(current_dir, new_dir);
        } else if (join_path(iso_path, sizeof(iso_path), current_dir, fe->name)) {
            phase = 4;
        }
    } else if (ch == KEY_BACKSPACE || ch == 127) {
        char *slash = strrchr(current_dir, '/');
        if (slash && slash != current_dir) *slash = '\0';
        else if (slash == current_dir) current_dir[1] = '\0';
        list_directory(current_dir);
    } else if (ch == 'q' || ch == 'Q') phase = 0;
}

static void confirm_write_phase(void) {
    for (;;) {
        draw_confirm();
        int ch = getch();

        if (ch == 'v' || ch == 'V') {
            compute_sha256 = !compute_sha256;
            continue;
        }
        if (ch == KEY_BACKSPACE || ch == 127 || ch == 'q' || ch == 'Q') {
            phase = 3;
            return;
        }
        if (ch != '\n' && ch != '\r' && ch != KEY_ENTER) continue;

        echo();
        curs_set(1);
        mvprintw(LINES - 4, 2, "Type exactly: %s", devices[selected_device].name);
        refresh();
        char confirm[64];
        mvwgetnstr(stdscr, LINES - 3, 2, confirm, sizeof(confirm) - 1);
        noecho();
        curs_set(0);

        if (strcmp(confirm, devices[selected_device].name) != 0) {
            phase = 0;
            return;
        }

        if (!source_is_pipe && detect_compression(iso_path) == NULL) {
            struct stat st;
            if (stat(iso_path, &st) == 0 && (unsigned long long)st.st_size > target_size_bytes) {
                mvprintw(LINES - 3, 2, "ISO too large for target.");
                refresh();
                getch();
                continue;
            }
        }

        log_line("TUI write start: target=%s iso=%s", target_path, iso_path);
        pending_hash_output[0] = '\0';
        int write_ok = do_write_verify(0);
        if (!write_ok) {
            log_line("TUI write failed: target=%s", target_path);
            draw_done(0);
            running = 0;
            return;
        }

        int verify_ok = 1;
        if (!skip_verify) {
            verify_ok = do_write_verify(1);
        }

        if (verify_ok && compute_sha256) {
            endwin();
            if (pending_hash_output[0])
                printf("\n%s\n", pending_hash_output);
            if (skip_verify) {
                char src_hex[65];
                sha256_hex(source_hash, src_hex);
                printf("\nSHA-256 (source): %s\n", src_hex);
            }
            printf("\nPress Enter to continue.\n");
            getchar();
            initscr();
            cbreak();
            noecho();
            curs_set(0);
            keypad(stdscr, TRUE);
            timeout(-1);
            if (has_colors()) {
                start_color();
                init_pair(1, COLOR_GREEN, COLOR_BLACK);
                init_pair(2, COLOR_YELLOW, COLOR_BLACK);
                init_pair(3, COLOR_RED, COLOR_BLACK);
            }
        }
        log_line("TUI write end: verify=%s", verify_ok ? "ok" : "fail");
        draw_done(verify_ok);
        running = 0;
        return;
    }
}

static void format_options_phase(void) {
    draw_format_options();
    int ch = getch();
    if (ch == 'f' || ch == 'F') {
        format_fs_type = (format_fs_type + 1) % 3;
    } else if (ch == 't' || ch == 'T') {
        format_use_gpt = !format_use_gpt;
    } else if (ch == 'l' || ch == 'L') {
        echo();
        curs_set(1);
        mvprintw(17, 2, "Enter label (max 11 chars): ");
        mvwgetnstr(stdscr, 18, 2, format_label, sizeof(format_label) - 1);
        noecho();
        curs_set(0);
        format_label[11] = '\0';
    } else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
        echo();
        curs_set(1);
        char confirm[64];
        mvprintw(19, 2, "Type exactly '%s' to confirm: ", devices[selected_device].name);
        refresh();
        mvwgetnstr(stdscr, 20, 2, confirm, sizeof(confirm) - 1);
        noecho();
        curs_set(0);

        if (strcmp(confirm, devices[selected_device].name) != 0) {
            phase = 0;
            return;
        }

        int rc;
        log_line("TUI format start: target=%s fs=%d gpt=%d label=%s",
                 devices[selected_device].path, format_fs_type, format_use_gpt, format_label);
        if (format_fs_type == 2)
            rc = format_exfat(devices[selected_device].path, format_label);
        else
            rc = format_fat32(devices[selected_device].path, format_label, format_use_gpt);
        log_line("TUI format end: rc=%d", rc);

        draw_done(rc == 0);
        running = 0;
    } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 'q' || ch == 'Q') {
        phase = 0;
    }
}

static void zero_confirm_phase(void) {
    draw_zero_confirm();
    int ch = getch();
    int mode = 0;
    if (ch == 'q' || ch == 'Q') mode = 1;
    else if (ch == 'f' || ch == 'F') mode = 2;
    else { phase = 0; return; }

    echo();
    curs_set(1);
    mvprintw(12, 2, "Type exactly: %s", devices[selected_device].name);
    refresh();
    char confirm[64];
    mvwgetnstr(stdscr, 13, 2, confirm, sizeof(confirm) - 1);
    noecho();
    curs_set(0);

    if (strcmp(confirm, devices[selected_device].name) != 0) { phase = 0; return; }

    log_line("TUI wipe start: target=%s mode=%s",
             devices[selected_device].path, mode == 1 ? "quick" : "full");
    if (mode == 1) {
        draw_done(wipe_first_mb(devices[selected_device].path) == 0);
    } else {
        zero_device(devices[selected_device].path, devices[selected_device].size_bytes);
        draw_done(1);
    }
    log_line("TUI wipe end: target=%s", devices[selected_device].path);
    running = 0;
}

static int wipe_first_mb(const char *dev_path) {
    int fd = open(dev_path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "wipe_first_mb: open %s failed: %s\n", dev_path, strerror(errno));
        return -1;
    }
    void *buf = calloc(1, WIPE_SIZE);
    if (!buf) { close(fd); return -1; }
    size_t off = 0;
    while (off < WIPE_SIZE) {
        ssize_t w = write(fd, (char *)buf + off, WIPE_SIZE - off);
        if (w < 0) {
            fprintf(stderr, "wipe_first_mb: write failed: %s\n", strerror(errno));
            free(buf); close(fd);
            return -1;
        }
        if (w == 0) break;
        off += (size_t)w;
    }
    free(buf);
    fsync(fd);
    close(fd);
    return (off == WIPE_SIZE) ? 0 : -1;
}

static void zero_device(const char *dev_path, unsigned long long size) {
    int fd = open(dev_path, O_WRONLY);
    if (fd < 0) return;
    void *buf = malloc(block_size);
    if (!buf) { close(fd); return; }
    memset(buf, 0, block_size);

    total_bytes = size;
    written_bytes = 0;
    progress_mode = 3;
    write_start_time = time(NULL);
    buffering_state = 0;
    honest_start = time(NULL);
    honest_bytes = 0;

    unsigned long long written = 0;
    while (written < size && !sigint_received) {
        unsigned long long remaining = size - written;
        size_t to_write = (remaining > block_size) ? block_size : (size_t)remaining;
        ssize_t w = write(fd, buf, to_write);
        if (w < 0) break;
        written += (unsigned long long)w;
        written_bytes = written;
        draw_progress();
    }
    fsync(fd);
    free(buf);
    close(fd);
    if (!tui_mode && !quiet_mode) fprintf(stderr, "\n");
    sigint_received = 0;
}

static int format_fat32(const char *dev_path, const char *label, int use_gpt) {
    if (wipe_first_mb(dev_path) < 0) return -1;

    char tool[256];
    if (find_tool("mkfs.vfat", "mkfs.fat", tool, sizeof(tool)) < 0)
        return -1;

    char safe_label[12] = "";
    if (label && label[0]) {
        strncpy(safe_label, label, 11);
        safe_label[11] = '\0';
    }

    char *argv[8];
    int n = 0;
    argv[n++] = tool;
    argv[n++] = "-F";
    argv[n++] = "32";
    if (safe_label[0]) {
        argv[n++] = "-n";
        argv[n++] = safe_label;
    }
    if (use_gpt) argv[n++] = "--gpt=y";
    else argv[n++] = "--mbr=y";
    argv[n++] = (char *)dev_path;
    argv[n] = NULL;

    int rc = run_tool(tool, argv);
    if (rc == 0) return 0;

    n = 0;
    argv[n++] = tool;
    argv[n++] = "-F";
    argv[n++] = "32";
    if (safe_label[0]) {
        argv[n++] = "-n";
        argv[n++] = safe_label;
    }
    argv[n++] = (char *)dev_path;
    argv[n] = NULL;

    rc = run_tool(tool, argv);
    sigint_received = 0;
    return (rc == 0) ? 0 : -1;
}

static int format_exfat(const char *dev_path, const char *label) {
    if (wipe_first_mb(dev_path) < 0) return -1;

    char tool[256];
    if (find_tool("mkfs.exfat", "mkexfatfs", tool, sizeof(tool)) < 0)
        return -1;

    char safe_label[12] = "";
    if (label && label[0]) {
        strncpy(safe_label, label, 11);
        safe_label[11] = '\0';
    }

    char *argv[6];
    int n = 0;
    argv[n++] = tool;
    if (safe_label[0]) {
        argv[n++] = "-n";
        argv[n++] = safe_label;
    }
    argv[n++] = (char *)dev_path;
    argv[n] = NULL;

    int rc = run_tool(tool, argv);
    sigint_received = 0;
    return (rc == 0) ? 0 : -1;
}

static int verify_source_hash(const char *iso, const char *sumfile) {
    FILE *f = fopen(sumfile, "r");
    if (!f) { fprintf(stderr, "Error: cannot open %s\n", sumfile); return -1; }
    char expected[65] = {0};
    char line[1024];
    const char *base = device_basename(iso);
    while (fgets(line, sizeof(line), f)) {
        if (strlen(line) < 66) continue;
        if (line[64] != ' ' && line[64] != '\t') continue;
        char hex[65];
        memcpy(hex, line, 64); hex[64] = '\0';
        char *fn = line + 65;
        while (*fn == ' ' || *fn == '*') fn++;
        fn[strcspn(fn, "\r\n")] = '\0';
        if (strcmp(device_basename(fn), base) == 0 || strcmp(fn, iso) == 0) {
            memcpy(expected, hex, 64);
            break;
        }
    }
    fclose(f);
    if (!expected[0]) {
        fprintf(stderr, "Error: no entry for %s in %s\n", base, sumfile);
        return -1;
    }

    FILE *sfp = fopen(iso, "rb");
    if (!sfp) { fprintf(stderr, "Error: cannot open %s\n", iso); return -1; }
    Sha256 s; sha256_init(&s);
    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), sfp)) > 0) sha256_update(&s, buf, n);
    fclose(sfp);
    unsigned char h[32]; char hx[65];
    sha256_final(&s, h); sha256_hex(h, hx);
    if (strcmp(hx, expected) != 0) {
        fprintf(stderr, "Error: source hash mismatch.\n  expected %s\n  got      %s\n",
                expected, hx);
        return -1;
    }
    printf("Source hash OK: %s\n", hx);
    log_line("Source hash verified: %s %s", iso, hx);
    return 0;
}

static void cli_list_devices(void) {
    if (!list_usb_devices()) {
        printf("No USB devices found.\n");
        return;
    }
    printf("Removable USB devices:\n");
    for (int i = 0; i < device_count; i++) {
        char size_str[32];
        human_size(devices[i].size_bytes, size_str, sizeof(size_str));
        printf("%s  %s  %s  %s  %s  %s%s%s\n",
               devices[i].path, devices[i].model, size_str, devices[i].serial,
               devices[i].fs_type, devices[i].part_table,
               devices[i].mounted ? " [MOUNTED]" : "",
               devices[i].system_device ? " [SYSTEM]" : "");
    }
}

static void cli_usage(const char *prog) {
    printf("Filament v%s\n", FILAMENT_VERSION);
    printf("Usage:\n");
    printf("  %s --list\n", prog);
    printf("  %s --list-partitions /dev/sdX\n", prog);
    printf("  %s --write /dev/sdX image.iso [--dry-run] [--no-verify] [--sha256] [--unmount] [--block-size=N]\n", prog);
    printf("                                  [--verify-source=FILE.sha256]\n");
    printf("  %s --zero /dev/sdX [--unmount] [--block-size=N]\n", prog);
    printf("  %s --wipe /dev/sdX [--unmount]\n", prog);
    printf("  %s --format /dev/sdX --fat32|--vfat|--exfat [--gpt] [--label=NAME] [--unmount]\n", prog);
    printf("  %s --version\n", prog);
    printf("  %s --help\n", prog);
    printf("\nGlobal flags:\n");
    printf("  --yes            skip interactive confirmation\n");
    printf("  --quiet          suppress progress output\n");
    printf("  --log FILE       append an audit log\n");
    printf("\nCompressed sources (.gz .xz .bz2 .zst) are decompressed on the fly.\n");
    printf("Formatting requires dosfstools (mkfs.vfat) and/or\n");
    printf("exfatprogs / exfat-utils (mkfs.exfat).\n");
}

static int preflight_or_die(const char *op) {
    if (assume_yes) return 0;
    if (!isatty(STDIN_FILENO)) {
        fprintf(stderr, "Error: %s on non-tty requires --yes.\n", op);
        return -1;
    }
    printf("About to %s %s\n", op, target_path);
    printf("Type 'yes' to continue: ");
    fflush(stdout);
    char buf[16];
    if (!fgets(buf, sizeof(buf), stdin)) return -1;
    if (strcmp(buf, "yes\n") != 0) { fprintf(stderr, "Aborted.\n"); return -1; }
    return 0;
}

static int parse_write_flags(int argc, char **argv, int *dry_run) {
    *dry_run = 0;
    skip_verify = 0;
    do_unmount = 0;
    compute_sha256 = 0;
    block_size = DEFAULT_BLOCK_SIZE;
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--dry-run") == 0) *dry_run = 1;
        else if (strcmp(argv[i], "--no-verify") == 0) skip_verify = 1;
        else if (strcmp(argv[i], "--unmount") == 0) do_unmount = 1;
        else if (strcmp(argv[i], "--sha256") == 0) compute_sha256 = 1;
        else if (strncmp(argv[i], "--block-size=", 13) == 0) {
            unsigned long long bs = 0;
            if (sscanf(argv[i] + 13, "%llu", &bs) == 1 && bs >= 4096 && bs <= 64ULL * 1024 * 1024)
                block_size = (size_t)bs;
            else {
                fprintf(stderr, "Error: --block-size must be between 4096 and 67108864.\n");
                return -1;
            }
        } else if (strncmp(argv[i], "--verify-source=", 16) == 0) {
            strncpy(verify_source_path, argv[i] + 16, sizeof(verify_source_path) - 1);
            verify_source_path[sizeof(verify_source_path) - 1] = '\0';
        }
    }
    return 0;
}

static int cmd_write(int argc, char **argv) {
    if (argc < 4) { cli_usage(argv[0]); return 1; }

    int dry_run = 0;
    if (parse_write_flags(argc, argv, &dry_run) < 0) return 1;

    if (!dry_run && geteuid() != 0) {
        fprintf(stderr, "Error: this operation requires root. Run with sudo.\n");
        return 1;
    }

    if (snprintf(target_path, sizeof(target_path), "%s", argv[2]) >= (int)sizeof(target_path)) {
        fprintf(stderr, "Error: device path too long.\n");
        return 1;
    }
    if (snprintf(iso_path, sizeof(iso_path), "%s", argv[3]) >= (int)sizeof(iso_path)) {
        fprintf(stderr, "Error: ISO path too long.\n");
        return 1;
    }

    if (verify_source_path[0]) {
        if (verify_source_hash(iso_path, verify_source_path) < 0) return 1;
    }

    if (do_unmount && !dry_run) unmount_device(device_basename(target_path));
    if (check_target_safe(target_path) < 0) return 1;

    target_size_bytes = get_device_size_checked(target_path);
    if (target_size_bytes == 0) return 1;

    int compressed = detect_compression(iso_path) != NULL;
    if (!compressed) {
        struct stat st;
        if (stat(iso_path, &st) != 0) {
            fprintf(stderr, "Error: ISO file not found.\n");
            return 1;
        }
        if ((unsigned long long)st.st_size > target_size_bytes) {
            fprintf(stderr, "Error: ISO larger than target device.\n");
            return 1;
        }
    } else {
        if (access(iso_path, R_OK) != 0) {
            fprintf(stderr, "Error: ISO file not found or not readable.\n");
            return 1;
        }
    }

    if (dry_run) {
        if (compressed)
            printf("Would write %s (compressed) to %s\n", iso_path, target_path);
        else
            printf("Would write %s to %s (%llu bytes)\n", iso_path, target_path, target_size_bytes);
        return 0;
    }

    if (preflight_or_die("write") < 0) return 1;

    log_line("CLI write start: target=%s iso=%s block=%zu sha256=%d verify=%d",
             target_path, iso_path, block_size, compute_sha256, !skip_verify);

    if (!do_write_verify(0)) {
        fprintf(stderr, "Write failed.\n");
        log_line("CLI write failed: target=%s", target_path);
        return 1;
    }
    if (!skip_verify) {
        if (!do_write_verify(1)) {
            fprintf(stderr, "Verification failed.\n");
            log_line("CLI verify failed: target=%s", target_path);
            return 1;
        }
        if (compute_sha256)
            printf("Write and verify successful. Safe to remove.\n");
        else
            printf("Write and verify successful. Safe to remove.\n");
    } else {
        if (compute_sha256) {
            char src_hex[65];
            sha256_hex(source_hash, src_hex);
            printf("SHA-256 (source): %s\n", src_hex);
        }
        printf("Write successful (verification skipped). Safe to remove.\n");
    }
    log_line("CLI write end: target=%s", target_path);
    return 0;
}

static int cmd_zero(int argc, char **argv) {
    if (argc < 3) { cli_usage(argv[0]); return 1; }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: this operation requires root. Run with sudo.\n");
        return 1;
    }

    do_unmount = 0;
    block_size = DEFAULT_BLOCK_SIZE;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--unmount") == 0) do_unmount = 1;
        else if (strncmp(argv[i], "--block-size=", 13) == 0) {
            unsigned long long bs = 0;
            if (sscanf(argv[i] + 13, "%llu", &bs) == 1 && bs >= 4096 && bs <= 64ULL * 1024 * 1024)
                block_size = (size_t)bs;
        }
    }

    if (snprintf(target_path, sizeof(target_path), "%s", argv[2]) >= (int)sizeof(target_path)) {
        fprintf(stderr, "Error: device path too long.\n");
        return 1;
    }
    if (do_unmount) unmount_device(device_basename(target_path));
    if (check_target_safe(target_path) < 0) return 1;

    target_size_bytes = get_device_size_checked(target_path);
    if (target_size_bytes == 0) return 1;

    if (preflight_or_die("zero") < 0) return 1;

    log_line("CLI zero start: target=%s", target_path);
    printf("Zeroing %s...\n", target_path);
    zero_device(target_path, target_size_bytes);
    log_line("CLI zero end: target=%s", target_path);
    printf("Done. Safe to remove.\n");
    return 0;
}

static int cmd_wipe(int argc, char **argv) {
    if (argc < 3) { cli_usage(argv[0]); return 1; }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: this operation requires root. Run with sudo.\n");
        return 1;
    }

    do_unmount = 0;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--unmount") == 0) do_unmount = 1;
    }

    if (snprintf(target_path, sizeof(target_path), "%s", argv[2]) >= (int)sizeof(target_path)) {
        fprintf(stderr, "Error: device path too long.\n");
        return 1;
    }
    if (do_unmount) unmount_device(device_basename(target_path));
    if (check_target_safe(target_path) < 0) return 1;

    if (preflight_or_die("wipe") < 0) return 1;

    log_line("CLI wipe start: target=%s", target_path);
    printf("Quick wipe %s (first 1 MB)...\n", target_path);
    if (wipe_first_mb(target_path) < 0) {
        fprintf(stderr, "Error: wipe failed.\n");
        log_line("CLI wipe failed: target=%s", target_path);
        return 1;
    }
    log_line("CLI wipe end: target=%s", target_path);
    printf("Done. Safe to remove.\n");
    return 0;
}

static int cmd_format(int argc, char **argv) {
    if (argc < 4) { cli_usage(argv[0]); return 1; }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: this operation requires root. Run with sudo.\n");
        return 1;
    }

    if (snprintf(target_path, sizeof(target_path), "%s", argv[2]) >= (int)sizeof(target_path)) {
        fprintf(stderr, "Error: device path too long.\n");
        return 1;
    }

    int fs = 0;
    int use_gpt = 0;
    do_unmount = 0;
    char label[32] = "";
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--fat32") == 0) fs = 0;
        else if (strcmp(argv[i], "--vfat") == 0) fs = 1;
        else if (strcmp(argv[i], "--exfat") == 0) fs = 2;
        else if (strcmp(argv[i], "--gpt") == 0) use_gpt = 1;
        else if (strcmp(argv[i], "--unmount") == 0) do_unmount = 1;
        else if (strncmp(argv[i], "--label=", 8) == 0) {
            strncpy(label, argv[i] + 8, sizeof(label) - 1);
            label[sizeof(label) - 1] = '\0';
        }
    }

    if (do_unmount) unmount_device(device_basename(target_path));
    if (check_target_safe(target_path) < 0) return 1;

    target_size_bytes = get_device_size_checked(target_path);
    if (target_size_bytes == 0) return 1;

    if (preflight_or_die("format") < 0) return 1;

    if (fs == 2 && use_gpt)
        fprintf(stderr, "Note: exFAT partition style is chosen by mkfs.exfat; --gpt ignored.\n");

    log_line("CLI format start: target=%s fs=%d gpt=%d label=%s",
             target_path, fs, use_gpt, label);
    int rc;
    if (fs == 2) rc = format_exfat(target_path, label);
    else rc = format_fat32(target_path, label, use_gpt);

    if (rc != 0) {
        fprintf(stderr, "Format failed. Ensure dosfstools and/or exfatprogs are installed.\n");
        log_line("CLI format failed: target=%s", target_path);
        return 1;
    }
    log_line("CLI format end: target=%s", target_path);
    printf("Done. Safe to remove.\n");
    return 0;
}

static int cmd_list_partitions(int argc, char **argv) {
    if (argc < 3) { cli_usage(argv[0]); return 1; }
    const char *dev = argv[2];
    if (strncmp(dev, "/dev/", 5) != 0) {
        fprintf(stderr, "Error: expected /dev/... path.\n");
        return 1;
    }
    int n = list_partitions(device_basename(dev));
    if (n == 0) { printf("No partitions on %s.\n", dev); return 0; }
    for (int i = 0; i < n; i++) {
        char sz[32];
        human_size(partitions[i].size_bytes, sz, sizeof(sz));
        printf("%s  %s\n", partitions[i].path, sz);
    }
    return 0;
}

static int run_tui(void) {
    if (!list_usb_devices()) {
        printf("[FILAMENT] No USB devices found.\n");
        return 1;
    }

    tui_mode = 1;

    initscr();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);
    timeout(-1);

    if (has_colors()) {
        start_color();
        init_pair(1, COLOR_GREEN, COLOR_BLACK);
        init_pair(2, COLOR_YELLOW, COLOR_BLACK);
        init_pair(3, COLOR_RED, COLOR_BLACK);
    }

    if (getcwd(current_dir, sizeof(current_dir)) == NULL) {
        strcpy(current_dir, "/");
    }
    show_hidden_files = 0;

    phase = 0;
    while (running) {
        switch (phase) {
            case 0: {
                draw_main_menu();
                int ch = getch();
                if (ch == '1') { action = 1; phase = 1; selected_device = 0; }
                else if (ch == '2') { action = 2; phase = 1; selected_device = 0; }
                else if (ch == '3') { action = 3; phase = 1; selected_device = 0; }
                else if (ch == '4' || ch == 'q' || ch == 'Q') running = 0;
                break;
            }
            case 1: device_select_phase(); break;
            case 2: partition_select_phase(); break;
            case 3: file_browse_phase(); break;
            case 4: confirm_write_phase(); break;
            case 5: format_options_phase(); break;
            case 6: zero_confirm_phase(); break;
            default: running = 0;
        }
    }

    endwin();
    tui_mode = 0;
    printf("[FILAMENT] Done.\n");
    return 0;
}

static void prescan_global_flags(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--yes") == 0) assume_yes = 1;
        else if (strcmp(argv[i], "--quiet") == 0) quiet_mode = 1;
        else if (strncmp(argv[i], "--log=", 6) == 0) {
            const char *path = argv[i] + 6;
            log_fp = fopen(path, "a");
            if (!log_fp) fprintf(stderr, "Warning: cannot open log file %s\n", path);
        }
    }
}

int main(int argc, char **argv) {
    signal(SIGINT, handle_sigint);

    prescan_global_flags(argc, argv);

    if (argc > 1) {
        if (strcmp(argv[1], "--version") == 0) {
            printf("Filament v%s\n", FILAMENT_VERSION);
            if (log_fp) fclose(log_fp);
            return 0;
        }
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            cli_usage(argv[0]);
            if (log_fp) fclose(log_fp);
            return 0;
        }
        if (strcmp(argv[1], "--list") == 0) {
            cli_list_devices();
            if (log_fp) fclose(log_fp);
            return 0;
        }
        if (strcmp(argv[1], "--list-partitions") == 0) {
            int rc = cmd_list_partitions(argc, argv);
            if (log_fp) fclose(log_fp);
            return rc;
        }
        if (strcmp(argv[1], "--write") == 0) {
            int rc = cmd_write(argc, argv);
            if (log_fp) fclose(log_fp);
            return rc;
        }
        if (strcmp(argv[1], "--zero") == 0) {
            int rc = cmd_zero(argc, argv);
            if (log_fp) fclose(log_fp);
            return rc;
        }
        if (strcmp(argv[1], "--wipe") == 0) {
            int rc = cmd_wipe(argc, argv);
            if (log_fp) fclose(log_fp);
            return rc;
        }
        if (strcmp(argv[1], "--format") == 0) {
            int rc = cmd_format(argc, argv);
            if (log_fp) fclose(log_fp);
            return rc;
        }
        cli_usage(argv[0]);
        if (log_fp) fclose(log_fp);
        return 0;
    }

    if (geteuid() != 0) {
        printf("[FILAMENT] Run with: sudo filament\n");
        if (log_fp) fclose(log_fp);
        return 1;
    }

    int rc = run_tui();
    if (log_fp) fclose(log_fp);
    return rc;
}