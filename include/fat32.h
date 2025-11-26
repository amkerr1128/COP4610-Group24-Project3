#ifndef FAT32_H
#define FAT32_H

#include <stdint.h>
#include <stdio.h>

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
} FAT32;

int fat32_mount(FAT32 *fs, const char *image_path);
void fat32_unmount(FAT32 *fs);
void fat32_print_info(const FAT32 *fs);
int fat32_cd(FAT32 *fs, const char *dirname);
int fat32_ls(const FAT32 *fs);

#endif
