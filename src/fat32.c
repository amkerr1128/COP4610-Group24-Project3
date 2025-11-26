#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "../include/fat32.h"

static unsigned long long get_image_size(FILE *fp)
{
    long cur = ftell(fp);
    long end;

    if (fseek(fp, 0, SEEK_END) != 0) {
        return 0;
    }

    end = ftell(fp);
    if (end < 0) {
        end = 0;
    }

    if (fseek(fp, cur, SEEK_SET) != 0) {
        return 0;
    }

    return (unsigned long long) end;
}

static void set_image_name(FAT32 *fs, const char *image_path)
{
    const char *base = image_path;
    const char *slash = strrchr(image_path, '/');
    const char *bslash = strrchr(image_path, '\\');

    if (slash != NULL && (bslash == NULL || slash > bslash)) {
        base = slash + 1;
    } else if (bslash != NULL) {
        base = bslash + 1;
    }

    strncpy(fs->image_name, base, sizeof(fs->image_name) - 1);
    fs->image_name[sizeof(fs->image_name) - 1] = '\0';
}

int fat32_mount(FAT32 *fs, const char *image_path)
{
    unsigned char sector[512];

    memset(fs, 0, sizeof(*fs));

    fs->fp = fopen(image_path, "rb+");
    if (fs->fp == NULL) {
        return -1;
    }

    set_image_name(fs, image_path);
    fs->image_size_bytes = get_image_size(fs->fp);

    if (fseek(fs->fp, 0, SEEK_SET) != 0) {
        fclose(fs->fp);
        fs->fp = NULL;
        return -1;
    }

    if (fread(sector, 1, sizeof(sector), fs->fp) != sizeof(sector)) {
        fclose(fs->fp);
        fs->fp = NULL;
        return -1;
    }

    fs->bytes_per_sector = (uint16_t) (sector[11] | (sector[12] << 8));
    fs->sectors_per_cluster = sector[13];
    fs->reserved_sector_count =
        (uint16_t) (sector[14] | (sector[15] << 8));
    fs->num_fats = sector[16];

    {
        uint16_t total_sectors_16 =
            (uint16_t) (sector[19] | (sector[20] << 8));
        uint32_t total_sectors_32 =
            (uint32_t) (sector[32] | (sector[33] << 8) |
                        (sector[34] << 16) | (sector[35] << 24));

        if (total_sectors_16 != 0) {
            fs->total_sectors = total_sectors_16;
        } else {
            fs->total_sectors = total_sectors_32;
        }
    }

    fs->sectors_per_fat =
        (uint32_t) (sector[36] | (sector[37] << 8) |
                    (sector[38] << 16) | (sector[39] << 24));

    fs->root_cluster =
        (uint32_t) (sector[44] | (sector[45] << 8) |
                    (sector[46] << 16) | (sector[47] << 24));

    fs->first_data_sector =
        fs->reserved_sector_count + (fs->num_fats * fs->sectors_per_fat);

    {
        uint32_t data_sectors =
            fs->total_sectors - fs->first_data_sector;

        if (fs->sectors_per_cluster != 0) {
            fs->total_clusters =
                data_sectors / fs->sectors_per_cluster;
        } else {
            fs->total_clusters = 0;
        }
    }

    if (fs->bytes_per_sector != 0) {
        fs->entries_per_fat =
            (fs->sectors_per_fat * fs->bytes_per_sector) / 4U;
    } else {
        fs->entries_per_fat = 0;
    }

    fs->current_cluster = fs->root_cluster;
    fs->current_path[0] = '\0';

    return 0;
}

void fat32_unmount(FAT32 *fs)
{
    if (fs->fp != NULL) {
        fclose(fs->fp);
        fs->fp = NULL;
    }
}

/* Helpers for directory navigation */

static long cluster_to_offset(const FAT32 *fs, uint32_t cluster)
{
    uint32_t first_sector =
        fs->first_data_sector +
        (cluster - 2U) * fs->sectors_per_cluster;

    return (long) first_sector * (long) fs->bytes_per_sector;
}

static uint32_t read_fat_entry(const FAT32 *fs, uint32_t cluster)
{
    unsigned char buf[4];
    uint32_t fat_offset = cluster * 4U;
    uint32_t fat_sector =
        fs->reserved_sector_count +
        (fat_offset / fs->bytes_per_sector);
    uint32_t offset_in_sector =
        fat_offset % fs->bytes_per_sector;
    long byte_offset =
        (long) fat_sector * (long) fs->bytes_per_sector +
        (long) offset_in_sector;

    if (fseek(fs->fp, byte_offset, SEEK_SET) != 0) {
        return 0x0FFFFFFFU;
    }

    if (fread(buf, 1, 4, fs->fp) != 4) {
        return 0x0FFFFFFFU;
    }

    {
        uint32_t entry =
            (uint32_t) (buf[0] | (buf[1] << 8) |
                        (buf[2] << 16) | (buf[3] << 24));

        return entry & 0x0FFFFFFFU;
    }
}

static void get_short_name(const unsigned char *entry, char *out)
{
    char name[9];
    int i;

    memcpy(name, entry, 8);
    name[8] = '\0';

    for (i = 7; i >= 0; --i) {
        if (name[i] == ' ') {
            name[i] = '\0';
        } else {
            break;
        }
    }

    strcpy(out, name);
}

static void to_upper_str(char *s)
{
    while (*s != '\0') {
        *s = (char) toupper((unsigned char) *s);
        ++s;
    }
}

static int names_equal(const char *a, const char *b)
{
    char aa[16];
    char bb[16];

    strncpy(aa, a, sizeof(aa) - 1);
    aa[sizeof(aa) - 1] = '\0';
    strncpy(bb, b, sizeof(bb) - 1);
    bb[sizeof(bb) - 1] = '\0';

    to_upper_str(aa);
    to_upper_str(bb);

    return strcmp(aa, bb) == 0;
}

static int find_dir_entry(const FAT32 *fs,
                          uint32_t start_cluster,
                          const char *target_name,
                          unsigned char *attr_out,
                          uint32_t *cluster_out)
{
    uint32_t cluster = start_cluster;
    unsigned char entry[32];

    while (cluster >= 2U && cluster < 0x0FFFFFF8U) {
        long offset = cluster_to_offset(fs, cluster);
        uint32_t bytes_per_cluster =
            (uint32_t) fs->bytes_per_sector *
            (uint32_t) fs->sectors_per_cluster;
        uint32_t pos = 0;

        if (fseek(fs->fp, offset, SEEK_SET) != 0) {
            return -1;
        }

        while (pos < bytes_per_cluster) {
            if (fread(entry, 1, 32, fs->fp) != 32) {
                return -1;
            }

            pos += 32;

            if (entry[0] == 0x00) {
                return -1;
            }

            if (entry[0] == 0xE5) {
                continue;
            }

            if (entry[11] == 0x0F) {
                continue;
            }

            {
                char name[16];
                get_short_name(entry, name);

                if (name[0] == '\0') {
                    continue;
                }

                if (names_equal(name, target_name)) {
                    uint16_t high =
                        (uint16_t) (entry[20] | (entry[21] << 8));
                    uint16_t low =
                        (uint16_t) (entry[26] | (entry[27] << 8));
                    uint32_t first_cluster =
                        ((uint32_t) high << 16) | low;

                    if (attr_out != NULL) {
                        *attr_out = entry[11];
                    }
                    if (cluster_out != NULL) {
                        *cluster_out = first_cluster;
                    }
                    return 0;
                }
            }
        }

        cluster = read_fat_entry(fs, cluster);
    }

    return -1;
}

/* Public APIs */

void fat32_print_info(const FAT32 *fs)
{
    printf("Root cluster (cluster #): %u\n", fs->root_cluster);
    printf("Bytes per sector: %u\n", fs->bytes_per_sector);
    printf("Sectors per cluster: %u\n", fs->sectors_per_cluster);
    printf("Total data clusters: %u\n", fs->total_clusters);
    printf("Entries in one FAT: %u\n", fs->entries_per_fat);
    printf("Image size (bytes): %llu\n",
           (unsigned long long) fs->image_size_bytes);
}

int fat32_cd(FAT32 *fs, const char *dirname)
{
    unsigned char attr;
    uint32_t new_cluster;

    if (strcmp(dirname, ".") == 0) {
        return 0;
    }

    if (strcmp(dirname, "..") == 0 &&
        fs->current_path[0] == '\0') {
        return 0;
    }

    if (strcmp(dirname, "..") == 0) {
        if (find_dir_entry(fs,
                           fs->current_cluster,
                           "..",
                           &attr,
                           &new_cluster) != 0) {
            return -1;
        }

        if ((attr & 0x10U) == 0U) {
            return -1;
        }

        fs->current_cluster = new_cluster;

        {
            char *slash = strrchr(fs->current_path, '/');
            if (slash != NULL) {
                *slash = '\0';
            } else {
                fs->current_path[0] = '\0';
            }
        }

        return 0;
    }

    if (find_dir_entry(fs,
                       fs->current_cluster,
                       dirname,
                       &attr,
                       &new_cluster) != 0) {
        return -1;
    }

    if ((attr & 0x10U) == 0U) {
        return -1;
    }

    fs->current_cluster = new_cluster;

    if (fs->current_path[0] == '\0') {
        strncpy(fs->current_path, dirname,
                sizeof(fs->current_path) - 1);
        fs->current_path[sizeof(fs->current_path) - 1] = '\0';
    } else {
        size_t len = strlen(fs->current_path);
        size_t remaining =
            sizeof(fs->current_path) - 1U - len;

        if (remaining > 1U) {
            fs->current_path[len] = '/';
            fs->current_path[len + 1] = '\0';
            strncat(fs->current_path, dirname, remaining - 1U);
        }
    }

    return 0;
}

int fat32_ls(const FAT32 *fs)
{
    uint32_t cluster = fs->current_cluster;
    unsigned char entry[32];

    while (cluster >= 2U && cluster < 0x0FFFFFF8U) {
        long offset = cluster_to_offset(fs, cluster);
        uint32_t bytes_per_cluster =
            (uint32_t) fs->bytes_per_sector *
            (uint32_t) fs->sectors_per_cluster;
        uint32_t pos = 0;

        if (fseek(fs->fp, offset, SEEK_SET) != 0) {
            return -1;
        }

        while (pos < bytes_per_cluster) {
            if (fread(entry, 1, 32, fs->fp) != 32) {
                return -1;
            }

            pos += 32;

            if (entry[0] == 0x00) {
                return 0;
            }

            if (entry[0] == 0xE5) {
                continue;
            }

            if (entry[11] == 0x0F) {
                continue;
            }

            {
                char name[16];
                get_short_name(entry, name);

                if (name[0] == '\0') {
                    continue;
                }

                printf("%s\n", name);
            }
        }

        cluster = read_fat_entry(fs, cluster);
    }

    return 0;
}
