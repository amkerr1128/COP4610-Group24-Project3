#include <stdio.h>
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
        } else {
            fprintf(stderr, "Error: unknown command '%s'\n", cmd);
        }
    }
}
