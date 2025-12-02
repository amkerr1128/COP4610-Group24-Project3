#ifndef FAT32_H
#define FAT32_H

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

/* Part 4: File operations */
typedef struct {
    int fd;
    uint32_t cluster;
    uint32_t size;
    unsigned long long offset;
    char name[256];
    char mode[4]; /* -r, -w, -rw, -wr */
    int is_open;
} OpenFile;

typedef struct {
    FILE *fp;
    char image_name[256];

    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sector_count;
    uint8_t num_fats;
    uint32_t sectors_per_fat;
    uint32_t root_cluster;
    uint32_t total_sectors;
    uint32_t first_data_sector;
    uint32_t total_clusters;
    uint32_t entries_per_fat;

    unsigned long long image_size_bytes;

    uint32_t current_cluster;
    char current_path[256];

    /* Part 4: Open file management */
    OpenFile open_files[32];
    int next_fd;
} FAT32;

int fat32_mount(FAT32 *fs, const char *image_path);
void fat32_unmount(FAT32 *fs);
void fat32_print_info(const FAT32 *fs);
int fat32_cd(FAT32 *fs, const char *dirname);
int fat32_ls(const FAT32 *fs);
int fat32_mkdir(FAT32 *fs, const char *dirname);
int fat32_creat(FAT32 *fs, const char *filename);

int fat32_open(FAT32 *fs, const char *filename, const char *mode, int *fd_out);
int fat32_close(FAT32 *fs, const char *filename);
int fat32_lsof(const FAT32 *fs);
int fat32_lseek(FAT32 *fs, const char *filename, unsigned long long offset);
int fat32_read(FAT32 *fs, const char *filename, size_t count);

/* Part 5: Update operations */
int fat32_write(FAT32 *fs, const char *filename, const char *data);
int fat32_mv(FAT32 *fs, const char *source, const char *dest);

/* Part 6: Delete operations */
int fat32_rm(FAT32 *fs, const char *filename);
int fat32_rmdir(FAT32 *fs, const char *dirname);

#endif
