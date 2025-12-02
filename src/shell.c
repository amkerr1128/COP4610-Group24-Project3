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

        /* Part 1: Mounting commands */
        if (strcmp(cmd, "exit") == 0) {
            break;
        } else if (strcmp(cmd, "info") == 0) {
            fat32_print_info(fs);
        }
        
        /* Part 2: Navigation commands */
        else if (strcmp(cmd, "cd") == 0) {
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
        }
        
        /* Part 3: Create commands */
        else if (strcmp(cmd, "mkdir") == 0) {
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
        }
        
        /* Part 4: Read commands */
        else if (strcmp(cmd, "open") == 0) {
            char *filename = strtok(NULL, " \t");
            char *mode = strtok(NULL, " \t");
            
            if (filename == NULL || mode == NULL) {
                fprintf(stderr, "Error: open requires filename and mode\n");
            } else {
                int fd;
                if (fat32_open(fs, filename, mode, &fd) != 0) {
                    fprintf(stderr, "Error: could not open file '%s'\n", filename);
                } else {
                    printf("Opened file '%s' with mode %s\n", filename, mode);
                }
            }
        } else if (strcmp(cmd, "close") == 0) {
            char *filename = strtok(NULL, " \t");
            
            if (filename == NULL) {
                fprintf(stderr, "Error: close requires a filename\n");
            } else if (fat32_close(fs, filename) != 0) {
                fprintf(stderr, "Error: could not close file '%s'\n", filename);
            }
        } else if (strcmp(cmd, "lsof") == 0) {
            if (fat32_lsof(fs) == 0) {
                printf("No open files\n");
            }
        } else if (strcmp(cmd, "lseek") == 0) {
            char *filename = strtok(NULL, " \t");
            char *offset_str = strtok(NULL, " \t");
            
            if (filename == NULL || offset_str == NULL) {
                fprintf(stderr, "Error: lseek requires filename and offset\n");
            } else {
                unsigned long long offset = (unsigned long long) strtoull(offset_str, NULL, 10);
                if (fat32_lseek(fs, filename, offset) != 0) {
                    fprintf(stderr, "Error: could not seek in file '%s'\n", filename);
                }
            }
        } else if (strcmp(cmd, "read") == 0) {
            char *filename = strtok(NULL, " \t");
            char *size_str = strtok(NULL, " \t");
            
            if (filename == NULL || size_str == NULL) {
                fprintf(stderr, "Error: read requires filename and size\n");
            } else {
                size_t count = (size_t) strtoull(size_str, NULL, 10);
                if (fat32_read(fs, filename, count) != 0) {
                    fprintf(stderr, "Error: could not read from file '%s'\n", filename);
                }
            }
        }
        
        /* Part 5: Update commands */
        else if (strcmp(cmd, "write") == 0) {
            char *filename = strtok(NULL, " \t");
            char *rest = strtok(NULL, "");  /* Get rest of line */
            
            if (filename == NULL || rest == NULL) {
                fprintf(stderr, "Error: write requires filename and string\n");
            } else {
                /* Extract string between quotes */
                char *start = strchr(rest, '"');
                char *end = NULL;
                
                if (start != NULL) {
                    start++; /* Skip opening quote */
                    end = strchr(start, '"');
                }
                
                if (start == NULL || end == NULL) {
                    fprintf(stderr, "Error: string must be enclosed in quotes\n");
                } else {
                    *end = '\0'; /* Terminate string at closing quote */
                    
                    if (fat32_write(fs, filename, start) != 0) {
                        fprintf(stderr, "Error: could not write to file '%s'\n", filename);
                    }
                }
            }
        } else if (strcmp(cmd, "mv") == 0) {
            char *source = strtok(NULL, " \t");
            char *dest = strtok(NULL, " \t");
            
            if (source == NULL || dest == NULL) {
                fprintf(stderr, "Error: mv requires source and destination\n");
            } else if (fat32_mv(fs, source, dest) != 0) {
                fprintf(stderr, "Error: could not move '%s' to '%s'\n", source, dest);
            }
        }
        
        /* Part 6: Delete commands */
        else if (strcmp(cmd, "rm") == 0) {
            char *filename = strtok(NULL, " \t");
            
            if (filename == NULL) {
                fprintf(stderr, "Error: rm requires a filename\n");
            } else if (fat32_rm(fs, filename) != 0) {
                fprintf(stderr, "Error: could not remove file '%s'\n", filename);
            }
        } else if (strcmp(cmd, "rmdir") == 0) {
            char *dirname = strtok(NULL, " \t");
            
            if (dirname == NULL) {
                fprintf(stderr, "Error: rmdir requires a directory name\n");
            } else if (fat32_rmdir(fs, dirname) != 0) {
                fprintf(stderr, "Error: could not remove directory '%s'\n", dirname);
            }
        }
        
        /* Unknown command */
        else {
            fprintf(stderr, "Error: unknown command '%s'\n", cmd);
        }
    }
}

