#include <stdio.h>
#include <stdlib.h>

#include "../include/fat32.h"
#include "../include/shell.h"

int main(int argc, char *argv[])
{
    FAT32 fs;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <fat32_image>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (fat32_mount(&fs, argv[1]) != 0) {
        fprintf(stderr, "Error: could not open image '%s'\n", argv[1]);
        return EXIT_FAILURE;
    }

    run_shell(&fs);

    fat32_unmount(&fs);
    return EXIT_SUCCESS;
}
