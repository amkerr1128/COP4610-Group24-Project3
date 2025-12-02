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

    /* Initialize open files array */
    memset(fs->open_files, 0, sizeof(fs->open_files));
    fs->next_fd = 0;

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
    char ext[4];
    int i;
    int has_ext = 0;

    memcpy(name, entry, 8);
    name[8] = '\0';

    for (i = 7; i >= 0; --i) {
        if (name[i] == ' ') {
            name[i] = '\0';
        } else {
            break;
        }
    }

    memcpy(ext, entry + 8, 3);
    ext[3] = '\0';

    for (i = 2; i >= 0; --i) {
        if (ext[i] == ' ') {
            ext[i] = '\0';
        } else {
            has_ext = 1;
            break;
        }
    }

    if (has_ext && ext[0] != '\0') {
        strcpy(out, name);
        strcat(out, ".");
        strcat(out, ext);
    } else {
        strcpy(out, name);
    }
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

/* Part 3: Helper functions for creating directories and files */

static int write_fat_entry(const FAT32 *fs, uint32_t cluster, uint32_t value)
{
    uint32_t fat_offset = cluster * 4U;
    uint32_t fat_sector =
        fs->reserved_sector_count +
        (fat_offset / fs->bytes_per_sector);
    uint32_t offset_in_sector =
        fat_offset % fs->bytes_per_sector;
    long byte_offset =
        (long) fat_sector * (long) fs->bytes_per_sector +
        (long) offset_in_sector;
    unsigned char buf[4];
    int i;

    value = value & 0x0FFFFFFFU;

    buf[0] = (unsigned char) (value & 0xFFU);
    buf[1] = (unsigned char) ((value >> 8) & 0xFFU);
    buf[2] = (unsigned char) ((value >> 16) & 0xFFU);
    buf[3] = (unsigned char) ((value >> 24) & 0xFFU);

    /* Write to all FATs */
    for (i = 0; i < fs->num_fats; ++i) {
        long current_offset = byte_offset + (long) i * (long) fs->sectors_per_fat * (long) fs->bytes_per_sector;

        if (fseek(fs->fp, current_offset, SEEK_SET) != 0) {
            return -1;
        }

        if (fwrite(buf, 1, 4, fs->fp) != 4) {
            return -1;
        }
    }

    return 0;
}

static uint32_t find_free_cluster(const FAT32 *fs)
{
    uint32_t cluster;

    for (cluster = 2; cluster < fs->total_clusters + 2U; ++cluster) {
        uint32_t entry = read_fat_entry(fs, cluster);
        if (entry == 0) {
            return cluster;
        }
    }

    return 0;
}

static void format_short_name(const char *name, char *out_name, char *out_ext)
{
    const char *dot = strchr(name, '.');
    int i;
    int name_len;
    int ext_len;

    memset(out_name, ' ', 8);
    memset(out_ext, ' ', 3);

    if (dot == NULL) {
        name_len = (int) strlen(name);
        if (name_len > 8) {
            name_len = 8;
        }
        for (i = 0; i < name_len; ++i) {
            out_name[i] = (char) toupper((unsigned char) name[i]);
        }
        out_ext[0] = ' ';
        out_ext[1] = ' ';
        out_ext[2] = ' ';
    } else {
        name_len = (int) (dot - name);
        if (name_len > 8) {
            name_len = 8;
        }
        for (i = 0; i < name_len; ++i) {
            out_name[i] = (char) toupper((unsigned char) name[i]);
        }

        ext_len = (int) strlen(dot + 1);
        if (ext_len > 3) {
            ext_len = 3;
        }
        for (i = 0; i < ext_len; ++i) {
            out_ext[i] = (char) toupper((unsigned char) dot[i + 1]);
        }
    }
}

static int find_empty_dir_entry_slot(const FAT32 *fs,
                                      uint32_t start_cluster,
                                      uint32_t *cluster_out,
                                      uint32_t *offset_out)
{
    uint32_t cluster = start_cluster;
    unsigned char entry[32];

    while (cluster >= 2U && cluster < 0x0FFFFFF8U) {
        long cluster_offset = cluster_to_offset(fs, cluster);
        uint32_t bytes_per_cluster =
            (uint32_t) fs->bytes_per_sector *
            (uint32_t) fs->sectors_per_cluster;
        uint32_t pos = 0;

        if (fseek(fs->fp, cluster_offset, SEEK_SET) != 0) {
            return -1;
        }

        while (pos < bytes_per_cluster) {
            if (fread(entry, 1, 32, fs->fp) != 32) {
                return -1;
            }

            if (entry[0] == 0x00 || entry[0] == 0xE5) {
                if (cluster_out != NULL) {
                    *cluster_out = cluster;
                }
                if (offset_out != NULL) {
                    *offset_out = pos;
                }
                return 0;
            }

            pos += 32;
        }

        cluster = read_fat_entry(fs, cluster);
    }

    return -1;
}

static int allocate_cluster_chain(const FAT32 *fs, uint32_t first_cluster)
{
    if (write_fat_entry(fs, first_cluster, 0x0FFFFFF8U) != 0) {
        return -1;
    }
    return 0;
}

static int create_dir_entry(const FAT32 *fs,
                             uint32_t parent_cluster,
                             const char *name,
                             uint32_t first_cluster,
                             uint8_t attributes)
{
    uint32_t entry_cluster;
    uint32_t entry_offset;
    unsigned char entry[32];
    char short_name[9];
    char ext[4];
    uint16_t time = 0;
    uint16_t date = 0;
    int i;

    if (find_empty_dir_entry_slot(fs, parent_cluster, &entry_cluster, &entry_offset) != 0) {
        return -1;
    }

    memset(entry, 0, 32);

    format_short_name(name, short_name, ext);

    for (i = 0; i < 8; ++i) {
        entry[i] = (unsigned char) short_name[i];
    }
    for (i = 0; i < 3; ++i) {
        entry[8 + i] = (unsigned char) ext[i];
    }

    entry[11] = attributes;
    entry[20] = (unsigned char) ((first_cluster >> 16) & 0xFFU);
    entry[21] = (unsigned char) ((first_cluster >> 24) & 0xFFU);
    entry[26] = (unsigned char) (first_cluster & 0xFFU);
    entry[27] = (unsigned char) ((first_cluster >> 8) & 0xFFU);
    entry[22] = (unsigned char) (time & 0xFFU);
    entry[23] = (unsigned char) ((time >> 8) & 0xFFU);
    entry[24] = (unsigned char) (date & 0xFFU);
    entry[25] = (unsigned char) ((date >> 8) & 0xFFU);
    entry[28] = 0;
    entry[29] = 0;
    entry[30] = 0;
    entry[31] = 0;

    {
        long write_offset = cluster_to_offset(fs, entry_cluster) + (long) entry_offset;
        if (fseek(fs->fp, write_offset, SEEK_SET) != 0) {
            return -1;
        }
        if (fwrite(entry, 1, 32, fs->fp) != 32) {
            return -1;
        }
    }

    return 0;
}

static int initialize_directory_cluster(const FAT32 *fs, uint32_t cluster, uint32_t parent_cluster)
{
    unsigned char entry[32];
    long offset = cluster_to_offset(fs, cluster);
    uint32_t bytes_per_cluster =
        (uint32_t) fs->bytes_per_sector *
        (uint32_t) fs->sectors_per_cluster;
    int i;

    memset(entry, 0, 32);

    if (fseek(fs->fp, offset, SEEK_SET) != 0) {
        return -1;
    }

    /* Create . entry */
    entry[0] = '.';
    for (i = 1; i < 11; ++i) {
        entry[i] = ' ';
    }
    entry[11] = 0x10;
    entry[20] = (unsigned char) ((cluster >> 16) & 0xFFU);
    entry[21] = (unsigned char) ((cluster >> 24) & 0xFFU);
    entry[26] = (unsigned char) (cluster & 0xFFU);
    entry[27] = (unsigned char) ((cluster >> 8) & 0xFFU);

    if (fwrite(entry, 1, 32, fs->fp) != 32) {
        return -1;
    }

    /* Create .. entry */
    memset(entry, 0, 32);
    entry[0] = '.';
    entry[1] = '.';
    for (i = 2; i < 11; ++i) {
        entry[i] = ' ';
    }
    entry[11] = 0x10;
    entry[20] = (unsigned char) ((parent_cluster >> 16) & 0xFFU);
    entry[21] = (unsigned char) ((parent_cluster >> 24) & 0xFFU);
    entry[26] = (unsigned char) (parent_cluster & 0xFFU);
    entry[27] = (unsigned char) ((parent_cluster >> 8) & 0xFFU);

    if (fwrite(entry, 1, 32, fs->fp) != 32) {
        return -1;
    }

    /* Zero out the rest of the cluster */
    {
        unsigned char zero = 0;
        uint32_t remaining = bytes_per_cluster - 64;
        for (i = 0; i < (int) remaining; ++i) {
            if (fwrite(&zero, 1, 1, fs->fp) != 1) {
                return -1;
            }
        }
    }

    return 0;
}

/* Part 3: Public APIs for creating directories and files */

int fat32_mkdir(FAT32 *fs, const char *dirname)
{
    unsigned char attr;
    uint32_t dummy;

    /* Check if directory already exists */
    if (find_dir_entry(fs, fs->current_cluster, dirname, &attr, &dummy) == 0) {
        return -1;
    }

    /* Find a free cluster */
    uint32_t new_cluster = find_free_cluster(fs);
    if (new_cluster == 0) {
        return -1;
    }

    /* Initialize the directory cluster with . and .. */
    if (initialize_directory_cluster(fs, new_cluster, fs->current_cluster) != 0) {
        return -1;
    }

    /* Mark cluster as end of chain */
    if (allocate_cluster_chain(fs, new_cluster) != 0) {
        return -1;
    }

    /* Create directory entry in parent */
    if (create_dir_entry(fs, fs->current_cluster, dirname, new_cluster, 0x10) != 0) {
        return -1;
    }

    return 0;
}

int fat32_creat(FAT32 *fs, const char *filename)
{
    unsigned char attr;
    uint32_t dummy;

    /* Check if file already exists */
    if (find_dir_entry(fs, fs->current_cluster, filename, &attr, &dummy) == 0) {
        return -1;
    }

    /* Find a free cluster */
    uint32_t new_cluster = find_free_cluster(fs);
    if (new_cluster == 0) {
        return -1;
    }

    /* Zero out the cluster */
    {
        long offset = cluster_to_offset(fs, new_cluster);
        uint32_t bytes_per_cluster =
            (uint32_t) fs->bytes_per_sector *
            (uint32_t) fs->sectors_per_cluster;
        unsigned char zero = 0;
        uint32_t i;

        if (fseek(fs->fp, offset, SEEK_SET) != 0) {
            return -1;
        }

        for (i = 0; i < bytes_per_cluster; ++i) {
            if (fwrite(&zero, 1, 1, fs->fp) != 1) {
                return -1;
            }
        }
    }

    /* Mark cluster as end of chain */
    if (allocate_cluster_chain(fs, new_cluster) != 0) {
        return -1;
    }

    /* Create file entry in parent (attribute 0x20 = archive) */
    if (create_dir_entry(fs, fs->current_cluster, filename, new_cluster, 0x20) != 0) {
        return -1;
    }

    return 0;
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

/* Part 4: File operations */

static int get_file_info(const FAT32 *fs,
                         uint32_t start_cluster,
                         const char *filename,
                         uint32_t *cluster_out,
                         uint32_t *size_out)
{
    unsigned char attr;
    uint32_t first_cluster;
    unsigned char entry[32];
    uint32_t cluster;
    uint32_t total_size = 0;

    if (find_dir_entry(fs, start_cluster, filename, &attr, &first_cluster) != 0) {
        return -1;
    }

    /* Check if it's a file (not a directory) */
    if ((attr & 0x10U) != 0U) {
        return -1;
    }

    /* Read directory entry to get file size */
    cluster = start_cluster;
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

                if (names_equal(name, filename)) {
                    total_size = (uint32_t) (entry[28] |
                                             (entry[29] << 8) |
                                             (entry[30] << 16) |
                                             (entry[31] << 24));

                    if (cluster_out != NULL) {
                        *cluster_out = first_cluster;
                    }
                    if (size_out != NULL) {
                        *size_out = total_size;
                    }
                    return 0;
                }
            }
        }

        cluster = read_fat_entry(fs, cluster);
    }

    return -1;
}

int fat32_open(FAT32 *fs, const char *filename, const char *mode, int *fd_out)
{
    uint32_t file_cluster;
    uint32_t file_size;
    int i;
    int fd;

    /* Validate mode */
    if (strcmp(mode, "-r") != 0 && strcmp(mode, "-w") != 0 && 
        strcmp(mode, "-rw") != 0 && strcmp(mode, "-wr") != 0) {
        fprintf(stderr, "Error: invalid mode '%s'\n", mode);
        return -1;
    }

    /* Check if file is already open */
    for (i = 0; i < 32; ++i) {
        if (fs->open_files[i].is_open && 
            names_equal(fs->open_files[i].name, filename)) {
            fprintf(stderr, "Error: file is already open\n");
            return -1;
        }
    }

    if (get_file_info(fs, fs->current_cluster, filename, &file_cluster, &file_size) != 0) {
        fprintf(stderr, "Error: file does not exist\n");
        return -1;
    }

    /* Find an available file descriptor slot */
    for (i = 0; i < 32; ++i) {
        if (fs->open_files[i].is_open == 0) {
            fd = fs->next_fd++;
            if (fs->next_fd < 0) {
                fs->next_fd = 0;
            }

            fs->open_files[i].fd = fd;
            fs->open_files[i].cluster = file_cluster;
            fs->open_files[i].size = file_size;
            fs->open_files[i].offset = 0;
            strncpy(fs->open_files[i].name, filename, sizeof(fs->open_files[i].name) - 1);
            fs->open_files[i].name[sizeof(fs->open_files[i].name) - 1] = '\0';
            strncpy(fs->open_files[i].mode, mode, sizeof(fs->open_files[i].mode) - 1);
            fs->open_files[i].mode[sizeof(fs->open_files[i].mode) - 1] = '\0';
            fs->open_files[i].is_open = 1;

            if (fd_out != NULL) {
                *fd_out = fd;
            }
            return 0;
        }
    }

    fprintf(stderr, "Error: too many open files\n");
    return -1;
}

int fat32_close(FAT32 *fs, const char *filename)
{
    int i;

    for (i = 0; i < 32; ++i) {
        if (fs->open_files[i].is_open && 
            names_equal(fs->open_files[i].name, filename)) {
            fs->open_files[i].is_open = 0;
            return 0;
        }
    }

    fprintf(stderr, "Error: file is not open\n");
    return -1;
}

int fat32_lsof(const FAT32 *fs)
{
    int i;
    int count = 0;

    printf("%-5s %-20s %-6s %-10s %-10s\n", 
           "Index", "Filename", "Mode", "Offset", "Path");
    printf("-----------------------------------------------------\n");

    for (i = 0; i < 32; ++i) {
        if (fs->open_files[i].is_open) {
            char path[512];
            if (fs->current_path[0] == '\0') {
                snprintf(path, sizeof(path), "/%s", fs->open_files[i].name);
            } else {
                snprintf(path, sizeof(path), "/%s/%s", 
                        fs->current_path, fs->open_files[i].name);
            }
            
            printf("%-5d %-20s %-6s %-10llu %s\n",
                   i,
                   fs->open_files[i].name,
                   fs->open_files[i].mode,
                   (unsigned long long) fs->open_files[i].offset,
                   path);
            ++count;
        }
    }

    return count;
}

int fat32_lseek(FAT32 *fs, const char *filename, unsigned long long offset)
{
    int i;

    for (i = 0; i < 32; ++i) {
        if (fs->open_files[i].is_open && 
            names_equal(fs->open_files[i].name, filename)) {
            if (offset > (unsigned long long) fs->open_files[i].size) {
                fprintf(stderr, "Error: offset larger than file size\n");
                return -1;
            }
            fs->open_files[i].offset = offset;
            return 0;
        }
    }

    fprintf(stderr, "Error: file is not open\n");
    return -1;
}

static uint32_t cluster_at_offset(const FAT32 *fs, uint32_t start_cluster, unsigned long long offset)
{
    uint32_t cluster = start_cluster;
    uint32_t bytes_per_cluster =
        (uint32_t) fs->bytes_per_sector *
        (uint32_t) fs->sectors_per_cluster;
    unsigned long long cluster_num = offset / (unsigned long long) bytes_per_cluster;
    unsigned long long i;

    for (i = 0; i < cluster_num; ++i) {
        if (cluster < 2U || cluster >= 0x0FFFFFF8U) {
            return 0;
        }
        cluster = read_fat_entry(fs, cluster);
    }

    return cluster;
}

int fat32_read(FAT32 *fs, const char *filename, size_t count)
{
    int i;
    OpenFile *file = NULL;
    uint32_t bytes_per_cluster;
    unsigned long long remaining;
    size_t total_read = 0;
    char *buf;

    /* Find the open file */
    for (i = 0; i < 32; ++i) {
        if (fs->open_files[i].is_open && 
            names_equal(fs->open_files[i].name, filename)) {
            file = &fs->open_files[i];
            break;
        }
    }

    if (file == NULL) {
        fprintf(stderr, "Error: file is not open\n");
        return -1;
    }

    /* Check read permission */
    if (strcmp(file->mode, "-w") == 0) {
        fprintf(stderr, "Error: file not opened for reading\n");
        return -1;
    }

    bytes_per_cluster = fs->bytes_per_sector * fs->sectors_per_cluster;

    remaining = (unsigned long long) file->size - file->offset;
    if ((unsigned long long) count > remaining) {
        count = (size_t) remaining;
    }

    buf = malloc(count + 1);
    if (buf == NULL) {
        fprintf(stderr, "Error: could not allocate memory\n");
        return -1;
    }

    while (count > 0 && file->offset < (unsigned long long) file->size) {
        uint32_t cluster = cluster_at_offset(fs, file->cluster, file->offset);
        if (cluster < 2U || cluster >= 0x0FFFFFF8U) {
            break;
        }

        uint32_t offset_in_cluster = (uint32_t) (file->offset % bytes_per_cluster);
        uint32_t available_in_cluster = bytes_per_cluster - offset_in_cluster;
        size_t to_read = count;
        if ((unsigned long long) to_read > available_in_cluster) {
            to_read = available_in_cluster;
        }

        long cluster_offset = cluster_to_offset(fs, cluster);
        if (fseek(fs->fp, cluster_offset + offset_in_cluster, SEEK_SET) != 0) {
            break;
        }

        if (fread(buf + total_read, 1, to_read, fs->fp) != to_read) {
            break;
        }

        total_read += to_read;
        file->offset += to_read;
        count -= to_read;
    }

    buf[total_read] = '\0';
    fwrite(buf, 1, total_read, stdout);
    printf("\n");

    free(buf);
    return 0;
}

/* ========== HELPER FUNCTIONS ========== */

/* Update file size in directory entry */
static int update_file_size(const FAT32 *fs, uint32_t parent_cluster, 
                            const char *filename, uint32_t new_size)
{
    uint32_t cluster = parent_cluster;
    unsigned char entry[32];

    while (cluster >= 2U && cluster < 0x0FFFFFF8U) {
        long offset = cluster_to_offset(fs, cluster);
        uint32_t bytes_per_cluster = fs->bytes_per_sector * fs->sectors_per_cluster;
        uint32_t pos = 0;

        if (fseek(fs->fp, offset, SEEK_SET) != 0) {
            return -1;
        }

        while (pos < bytes_per_cluster) {
            long entry_offset = ftell(fs->fp);
            
            if (fread(entry, 1, 32, fs->fp) != 32) {
                return -1;
            }

            if (entry[0] == 0x00) {
                return -1;
            }

            if (entry[0] == 0xE5 || entry[11] == 0x0F) {
                pos += 32;
                continue;
            }

            char name[16];
            get_short_name(entry, name);

            if (name[0] != '\0' && names_equal(name, filename)) {
                /* Update size field */
                entry[28] = (unsigned char)(new_size & 0xFFU);
                entry[29] = (unsigned char)((new_size >> 8) & 0xFFU);
                entry[30] = (unsigned char)((new_size >> 16) & 0xFFU);
                entry[31] = (unsigned char)((new_size >> 24) & 0xFFU);

                /* Write back */
                if (fseek(fs->fp, entry_offset, SEEK_SET) != 0) {
                    return -1;
                }
                if (fwrite(entry, 1, 32, fs->fp) != 32) {
                    return -1;
                }
                return 0;
            }

            pos += 32;
        }

        cluster = read_fat_entry(fs, cluster);
    }

    return -1;
}

/* Get last cluster in chain */
static uint32_t get_last_cluster(const FAT32 *fs, uint32_t start_cluster)
{
    uint32_t cluster = start_cluster;
    uint32_t prev = cluster;

    while (cluster >= 2U && cluster < 0x0FFFFFF8U) {
        prev = cluster;
        cluster = read_fat_entry(fs, cluster);
    }

    return prev;
}

/* Extend cluster chain by adding new clusters */
static int extend_cluster_chain(const FAT32 *fs, uint32_t last_cluster, 
                                uint32_t clusters_needed)
{
    uint32_t prev = last_cluster;
    uint32_t i;

    for (i = 0; i < clusters_needed; ++i) {
        uint32_t new_cluster = find_free_cluster(fs);
        if (new_cluster == 0) {
            return -1;
        }

        /* Link previous cluster to new cluster */
        if (write_fat_entry(fs, prev, new_cluster) != 0) {
            return -1;
        }

        /* Mark new cluster as end of chain */
        if (write_fat_entry(fs, new_cluster, 0x0FFFFFF8U) != 0) {
            return -1;
        }

        prev = new_cluster;
    }

    return 0;
}

/* Delete directory entry by marking it as deleted */
static int delete_dir_entry(const FAT32 *fs, uint32_t parent_cluster, 
                            const char *name)
{
    uint32_t cluster = parent_cluster;
    unsigned char entry[32];

    while (cluster >= 2U && cluster < 0x0FFFFFF8U) {
        long offset = cluster_to_offset(fs, cluster);
        uint32_t bytes_per_cluster = fs->bytes_per_sector * fs->sectors_per_cluster;
        uint32_t pos = 0;

        if (fseek(fs->fp, offset, SEEK_SET) != 0) {
            return -1;
        }

        while (pos < bytes_per_cluster) {
            long entry_offset = ftell(fs->fp);
            
            if (fread(entry, 1, 32, fs->fp) != 32) {
                return -1;
            }

            if (entry[0] == 0x00) {
                return -1;
            }

            if (entry[0] == 0xE5 || entry[11] == 0x0F) {
                pos += 32;
                continue;
            }

            char entry_name[16];
            get_short_name(entry, entry_name);

            if (entry_name[0] != '\0' && names_equal(entry_name, name)) {
                /* Mark as deleted */
                entry[0] = 0xE5;

                if (fseek(fs->fp, entry_offset, SEEK_SET) != 0) {
                    return -1;
                }
                if (fwrite(entry, 1, 32, fs->fp) != 32) {
                    return -1;
                }
                return 0;
            }

            pos += 32;
        }

        cluster = read_fat_entry(fs, cluster);
    }

    return -1;
}

/* Free cluster chain */
static int free_cluster_chain(const FAT32 *fs, uint32_t start_cluster)
{
    uint32_t cluster = start_cluster;

    while (cluster >= 2U && cluster < 0x0FFFFFF8U) {
        uint32_t next = read_fat_entry(fs, cluster);
        
        if (write_fat_entry(fs, cluster, 0) != 0) {
            return -1;
        }

        cluster = next;
    }

    return 0;
}

/* Check if directory is empty (only . and ..) */
static int is_directory_empty(const FAT32 *fs, uint32_t dir_cluster)
{
    uint32_t cluster = dir_cluster;
    unsigned char entry[32];
    int entry_count = 0;

    while (cluster >= 2U && cluster < 0x0FFFFFF8U) {
        long offset = cluster_to_offset(fs, cluster);
        uint32_t bytes_per_cluster = fs->bytes_per_sector * fs->sectors_per_cluster;
        uint32_t pos = 0;

        if (fseek(fs->fp, offset, SEEK_SET) != 0) {
            return 0;
        }

        while (pos < bytes_per_cluster) {
            if (fread(entry, 1, 32, fs->fp) != 32) {
                return 0;
            }

            if (entry[0] == 0x00) {
                /* Only . and .. should exist */
                return entry_count == 2;
            }

            if (entry[0] != 0xE5 && entry[11] != 0x0F) {
                ++entry_count;
            }

            pos += 32;
        }

        cluster = read_fat_entry(fs, cluster);
    }

    return entry_count == 2;
}

/* Check if file is open in directory */
static int is_file_open_in_dir(const FAT32 *fs, uint32_t dir_cluster)
{
    int i;
    
    for (i = 0; i < 32; ++i) {
        if (fs->open_files[i].is_open) {
            /* Would need to track directory for each open file */
            /* For simplicity, we'll check by name comparison */
            return 1; /* Conservative approach */
        }
    }
    return 0;
}

/* Find open file by name */
static OpenFile* find_open_file(FAT32 *fs, const char *filename)
{
    int i;
    for (i = 0; i < 32; ++i) {
        if (fs->open_files[i].is_open && 
            names_equal(fs->open_files[i].name, filename)) {
            return &fs->open_files[i];
        }
    }
    return NULL;
}

/* ========== PART 5: UPDATE OPERATIONS ========== */

int fat32_write(FAT32 *fs, const char *filename, const char *data)
{
    OpenFile *file;
    size_t data_len;
    uint32_t bytes_per_cluster;
    size_t written = 0;
    
    /* Find open file */
    file = find_open_file(fs, filename);
    if (file == NULL) {
        fprintf(stderr, "Error: file '%s' is not open\n", filename);
        return -1;
    }

    /* Check write permission */
    if (strcmp(file->mode, "-r") == 0) {
        fprintf(stderr, "Error: file '%s' not opened for writing\n", filename);
        return -1;
    }

    data_len = strlen(data);
    bytes_per_cluster = fs->bytes_per_sector * fs->sectors_per_cluster;

    /* Check if we need to extend the file */
    if (file->offset + data_len > file->size) {
        uint32_t new_size = (uint32_t)(file->offset + data_len);
        uint32_t clusters_needed = (new_size + bytes_per_cluster - 1) / bytes_per_cluster;
        uint32_t clusters_have = (file->size + bytes_per_cluster - 1) / bytes_per_cluster;

        if (clusters_have == 0) {
            clusters_have = 1;
        }

        if (clusters_needed > clusters_have) {
            uint32_t last_cluster = get_last_cluster(fs, file->cluster);
            if (extend_cluster_chain(fs, last_cluster, 
                                    clusters_needed - clusters_have) != 0) {
                fprintf(stderr, "Error: could not extend file\n");
                return -1;
            }
        }

        /* Update file size in directory entry */
        if (update_file_size(fs, fs->current_cluster, filename, new_size) != 0) {
            fprintf(stderr, "Error: could not update file size\n");
            return -1;
        }

        file->size = new_size;
    }

    /* Write data */
    while (written < data_len) {
        uint32_t cluster = cluster_at_offset(fs, file->cluster, file->offset);
        if (cluster < 2U || cluster >= 0x0FFFFFF8U) {
            fprintf(stderr, "Error: invalid cluster\n");
            break;
        }

        uint32_t offset_in_cluster = (uint32_t)(file->offset % bytes_per_cluster);
        uint32_t available = bytes_per_cluster - offset_in_cluster;
        size_t to_write = data_len - written;
        
        if (to_write > available) {
            to_write = available;
        }

        long cluster_offset = cluster_to_offset(fs, cluster);
        if (fseek(fs->fp, cluster_offset + offset_in_cluster, SEEK_SET) != 0) {
            fprintf(stderr, "Error: seek failed\n");
            break;
        }

        if (fwrite(data + written, 1, to_write, fs->fp) != to_write) {
            fprintf(stderr, "Error: write failed\n");
            break;
        }

        written += to_write;
        file->offset += to_write;
    }

    if (fflush(fs->fp) != 0) {
        fprintf(stderr, "Error: flush failed\n");
        return -1;
    }

    return 0;
}

int fat32_mv(FAT32 *fs, const char *source, const char *dest)
{
    unsigned char attr;
    uint32_t source_cluster;
    uint32_t dest_cluster;
    unsigned char dest_attr;
    OpenFile *file;

    /* Check if source exists */
    if (find_dir_entry(fs, fs->current_cluster, source, &attr, &source_cluster) != 0) {
        fprintf(stderr, "Error: '%s' does not exist\n", source);
        return -1;
    }

    /* Check if file is open */
    file = find_open_file(fs, source);
    if (file != NULL) {
        fprintf(stderr, "Error: file must be closed\n");
        return -1;
    }

    /* Check if dest exists */
    if (find_dir_entry(fs, fs->current_cluster, dest, &dest_attr, &dest_cluster) == 0) {
        /* Dest exists - check if it's a directory */
        if ((dest_attr & 0x10U) == 0U) {
            fprintf(stderr, "Error: '%s' is not a directory\n", dest);
            return -1;
        }

        /* Move into directory - would need to implement cross-directory move */
        fprintf(stderr, "Error: moving to different directory not implemented\n");
        return -1;
    } else {
        /* Dest doesn't exist - rename */
        unsigned char entry[32];
        uint32_t cluster = fs->current_cluster;

        /* Find and update entry */
        while (cluster >= 2U && cluster < 0x0FFFFFF8U) {
            long offset = cluster_to_offset(fs, cluster);
            uint32_t bytes_per_cluster = fs->bytes_per_sector * fs->sectors_per_cluster;
            uint32_t pos = 0;

            if (fseek(fs->fp, offset, SEEK_SET) != 0) {
                return -1;
            }

            while (pos < bytes_per_cluster) {
                long entry_offset = ftell(fs->fp);
                
                if (fread(entry, 1, 32, fs->fp) != 32) {
                    return -1;
                }

                if (entry[0] == 0x00) {
                    break;
                }

                if (entry[0] == 0xE5 || entry[11] == 0x0F) {
                    pos += 32;
                    continue;
                }

                char name[16];
                get_short_name(entry, name);

                if (name[0] != '\0' && names_equal(name, source)) {
                    /* Update name */
                    char new_name[9];
                    char new_ext[4];
                    int i;

                    format_short_name(dest, new_name, new_ext);

                    for (i = 0; i < 8; ++i) {
                        entry[i] = (unsigned char)new_name[i];
                    }
                    for (i = 0; i < 3; ++i) {
                        entry[8 + i] = (unsigned char)new_ext[i];
                    }

                    /* Write back */
                    if (fseek(fs->fp, entry_offset, SEEK_SET) != 0) {
                        return -1;
                    }
                    if (fwrite(entry, 1, 32, fs->fp) != 32) {
                        return -1;
                    }

                    return 0;
                }

                pos += 32;
            }

            cluster = read_fat_entry(fs, cluster);
        }
    }

    return -1;
}

/* ========== PART 6: DELETE OPERATIONS ========== */

int fat32_rm(FAT32 *fs, const char *filename)
{
    unsigned char attr;
    uint32_t file_cluster;
    OpenFile *file;

    /* Check if file exists */
    if (find_dir_entry(fs, fs->current_cluster, filename, &attr, &file_cluster) != 0) {
        fprintf(stderr, "Error: '%s' does not exist\n", filename);
        return -1;
    }

    /* Check if it's a directory */
    if ((attr & 0x10U) != 0U) {
        fprintf(stderr, "Error: '%s' is a directory\n", filename);
        return -1;
    }

    /* Check if file is open */
    file = find_open_file(fs, filename);
    if (file != NULL) {
        fprintf(stderr, "Error: file is open\n");
        return -1;
    }

    /* Delete directory entry */
    if (delete_dir_entry(fs, fs->current_cluster, filename) != 0) {
        fprintf(stderr, "Error: could not delete directory entry\n");
        return -1;
    }

    /* Free cluster chain */
    if (file_cluster >= 2U && file_cluster < 0x0FFFFFF8U) {
        if (free_cluster_chain(fs, file_cluster) != 0) {
            fprintf(stderr, "Error: could not free clusters\n");
            return -1;
        }
    }

    return 0;
}

int fat32_rmdir(FAT32 *fs, const char *dirname)
{
    unsigned char attr;
    uint32_t dir_cluster;

    /* Check if directory exists */
    if (find_dir_entry(fs, fs->current_cluster, dirname, &attr, &dir_cluster) != 0) {
        fprintf(stderr, "Error: '%s' does not exist\n", dirname);
        return -1;
    }

    /* Check if it's a directory */
    if ((attr & 0x10U) == 0U) {
        fprintf(stderr, "Error: '%s' is not a directory\n", dirname);
        return -1;
    }

    /* Check if directory is empty */
    if (!is_directory_empty(fs, dir_cluster)) {
        fprintf(stderr, "Error: directory is not empty\n");
        return -1;
    }

    /* Check if any files in directory are open */
    if (is_file_open_in_dir(fs, dir_cluster)) {
        fprintf(stderr, "Error: a file in directory is open\n");
        return -1;
    }

    /* Delete directory entry */
    if (delete_dir_entry(fs, fs->current_cluster, dirname) != 0) {
        fprintf(stderr, "Error: could not delete directory entry\n");
        return -1;
    }

    /* Free cluster chain */
    if (dir_cluster >= 2U && dir_cluster < 0x0FFFFFF8U) {
        if (free_cluster_chain(fs, dir_cluster) != 0) {
            fprintf(stderr, "Error: could not free clusters\n");
            return -1;
        }
    }

    return 0;
}