# FAT32 File System

User-space shell utility for interpreting and manipulating a FAT32 file system image.

## Group Members
- Austin Kerr: amk21u@fsu.edu
- [Teammate 2]: [fsu_login2]@fsu.edu
- [Teammate 3]: [fsu_login3]@fsu.edu

## Division of Labor

### Part 1: Mounting the Image File & Info
- **Responsibilities**: Implement `filesys` startup, mount FAT32 image from `argv[1]`, parse boot sector, compute core FAT32 layout values, and implement the `info` command.
- **Assigned to**: Austin Kerr

### Part 2: Navigation
- **Responsibilities**: Maintain current working directory state; implement the interactive prompt (`[IMAGE_NAME]/[PATH_IN_IMAGE]/>`); implement `cd` and `ls` on the FAT32 image.
- **Assigned to**: Austin Kerr

### Part 3: Create
- **Responsibilities**: Implement `mkdir` and `creat` for the current working directory, including directory entry allocation, error handling when names already exist, and updating the underlying clusters.
- **Assigned to**: [Teammate 2]

### Part 4: Read
- **Responsibilities**: Implement open-file data structure and operations: `open`, `close`, `lsof`, `lseek`, and `read`, with correct offset management and permissions checks.
- **Assigned to**: [Teammate 3]

### Part 5: Update
- **Responsibilities**: Implement `write` and `mv`, including extending files when needed, updating directory entries and clusters, and enforcing that files are closed or in a valid mode.
- **Assigned to**: [Teammate 3]

### Part 6: Delete
- **Responsibilities**: Implement `rm` and `rmdir`, reclaiming file data, enforcing empty-directory requirement for `rmdir`, and ensuring opened files/directories cannot be removed.
- **Assigned to**: [Teammate 2]

## File Listing
```text
filesys/
├── Makefile
├── src/
│   ├── main.c
│   ├── fat32.c
│   └── shell.c
├── include/
│   ├── fat32.h
│   └── shell.h
├── bin/
└── README.md
How to Compile & Execute
Requirements
Compiler: gcc with C11 support

Environment: Linux (e.g., linprog) with standard C library

Part 1: Mounting the Image File & Info
Compilation
bash
Copy code
make
This will build the filesys executable in bin/.

Execution
bash
Copy code
./bin/filesys path/to/image.img
On startup, the program:

Opens the given FAT32 image.

Parses the boot sector and stores:

position of root cluster (cluster #)

bytes per sector

sectors per cluster

total number of clusters in data region

number of entries in one FAT

size of image in bytes

The info command prints these fields, one per line.

Part 2: Navigation
Commands
ls
Prints the names of directories and files within the current working directory, including . and ... Each entry is printed on a separate line. Long-name entries are skipped.

cd [DIRNAME]
Changes the current working directory to DIRNAME if it exists and is a directory. Supports . and ... Prints an error if the target does not exist or is not a directory.

exit
Safely closes the program, frees resources, and exits the shell.

Example Session
text
Copy code
image.img/> info
image.img/> ls
image.img/> cd SUBDIR
image.img/SUBDIR/> ls
image.img/SUBDIR/> cd ..
image.img/> exit
Development Log
Each member records their contributions here.

Austin Kerr
Date	Work Completed / Notes
YYYY-MM-DD	Created repository, base src/ and include/ layout.
YYYY-MM-DD	Implemented FAT32 mount logic and info command.
YYYY-MM-DD	Implemented shell loop, prompt, cd, and ls.

[Teammate 2]
Date	Work Completed / Notes
YYYY-MM-DD	
YYYY-MM-DD	
YYYY-MM-DD	

[Teammate 3]
Date	Work Completed / Notes
YYYY-MM-DD	
YYYY-MM-DD	
YYYY-MM-DD	

Meetings
Document in-person or online meetings, their purpose, and what was discussed.

Date	Attendees	Topics Discussed	Outcomes / Decisions
YYYY-MM-DD	Austin, [Teammate 2], [Teammate 3]	Repository setup, reading project description	Agreed on division of labor for Parts 1–6.
YYYY-MM-DD	Austin, [Teammate 2], [Teammate 3]	Integration & testing plan	Chose test images and set intermediate goals.

Bugs
Bug 1: TODO – describe any known issues with cd / ls or root handling.

Bug 2: TODO – describe.

Bug 3: TODO – describe.

Considerations
Only standard C library functions are used to ensure compatibility with linprog.

Image is opened read/write but all commands should preserve image integrity.

Long directory names are not supported; entries marked as long-name are skipped.

Assumes file and directory names have no spaces and use the short 8.3 format.