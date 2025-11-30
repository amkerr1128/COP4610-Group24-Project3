#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/shell.h"
#include "../include/fat32.h"

static void trim_newline(char *s)
{
    char *p = strchr(s, '\n');
    if (p != NULL) {
        *p = '\0';
    }
}

void run_shell(FAT32 *fs)
{
    char line[256];

    while (1) {
        if (fs->current_path[0] == '\0') {
            printf("%s/> ", fs->image_name);
        } else {
            printf("%s/%s/> ", fs->image_name, fs->current_path);
        }

        if (fgets(line, sizeof(line), stdin) == NULL) {
            printf("\n");
            break;
        }

        trim_newline(line);

        char *cmd = strtok(line, " \t");
        if (cmd == NULL) {
            continue;
        }

        if (strcmp(cmd, "exit") == 0) {
            break;
        } else if (strcmp(cmd, "info") == 0) {
            fat32_print_info(fs);
        } else if (strcmp(cmd, "cd") == 0) {
            char *arg = strtok(NULL, " \t");
            if (arg == NULL) {
                fprintf(stderr, "Error: cd requires a directory name\n");
            } else if (fat32_cd(fs, arg) != 0) {
                fprintf(stderr,
                        "Error: directory '%s' does not exist or is not a "
                        "directory\n",
                        arg);
            }
        } else if (strcmp(cmd, "ls") == 0) {
            if (fat32_ls(fs) != 0) {
                fprintf(stderr, "Error: could not list current directory\n");
            }
        } else if (strcmp(cmd, "mkdir") == 0) {
            char *arg = strtok(NULL, " \t");
            if (arg == NULL) {
                fprintf(stderr, "Error: mkdir requires a directory name\n");
            } else if (fat32_mkdir(fs, arg) != 0) {
                fprintf(stderr,
                        "Error: could not create directory '%s' (may already exist)\n",
                        arg);
            }
        } else if (strcmp(cmd, "creat") == 0) {
            char *arg = strtok(NULL, " \t");
            if (arg == NULL) {
                fprintf(stderr, "Error: creat requires a file name\n");
            } else if (fat32_creat(fs, arg) != 0) {
                fprintf(stderr,
                        "Error: could not create file '%s' (may already exist)\n",
                        arg);
            }
        } else if (strcmp(cmd, "open") == 0) {
            char *arg = strtok(NULL, " \t");
            if (arg == NULL) {
                fprintf(stderr, "Error: open requires a file name\n");
            } else {
                int fd;
                if (fat32_open(fs, arg, &fd) != 0) {
                    fprintf(stderr,
                            "Error: could not open file '%s'\n",
                            arg);
                } else {
                    printf("Opened file '%s' with fd: %d\n", arg, fd);
                }
            }
        } else if (strcmp(cmd, "close") == 0) {
            char *arg = strtok(NULL, " \t");
            if (arg == NULL) {
                fprintf(stderr, "Error: close requires a file descriptor\n");
            } else {
                int fd = (int) strtol(arg, NULL, 10);
                if (fat32_close(fs, fd) != 0) {
                    fprintf(stderr,
                            "Error: could not close file descriptor %d\n",
                            fd);
                }
            }
        } else if (strcmp(cmd, "lsof") == 0) {
            if (fat32_lsof(fs) == 0) {
                printf("No open files\n");
            }
        } else if (strcmp(cmd, "lseek") == 0) {
            char *arg1 = strtok(NULL, " \t");
            char *arg2 = strtok(NULL, " \t");
            if (arg1 == NULL || arg2 == NULL) {
                fprintf(stderr, "Error: lseek requires a file descriptor and offset\n");
            } else {
                int fd = (int) strtol(arg1, NULL, 10);
                unsigned long long offset = (unsigned long long) strtoull(arg2, NULL, 10);
                if (fat32_lseek(fs, fd, offset) != 0) {
                    fprintf(stderr,
                            "Error: could not seek in file descriptor %d\n",
                            fd);
                }
            }
        } else if (strcmp(cmd, "read") == 0) {
            char *arg1 = strtok(NULL, " \t");
            char *arg2 = strtok(NULL, " \t");
            if (arg1 == NULL || arg2 == NULL) {
                fprintf(stderr, "Error: read requires a file descriptor and byte count\n");
            } else {
                int fd = (int) strtol(arg1, NULL, 10);
                size_t count = (size_t) strtoull(arg2, NULL, 10);
                char *buf = malloc(count + 1);
                size_t bytes_read = 0;

                if (buf == NULL) {
                    fprintf(stderr, "Error: could not allocate memory\n");
                } else if (fat32_read(fs, fd, buf, count, &bytes_read) != 0) {
                    fprintf(stderr,
                            "Error: could not read from file descriptor %d\n",
                            fd);
                } else {
                    buf[bytes_read] = '\0';
                    fwrite(buf, 1, bytes_read, stdout);
                    printf("\n");
                }
                free(buf);
            }
        } else {
            fprintf(stderr, "Error: unknown command '%s'\n", cmd);
        }
    }
}
