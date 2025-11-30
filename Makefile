CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
INCLUDES = -Iinclude

SRCDIR = src
BINDIR = bin

OBJS = $(SRCDIR)/main.o $(SRCDIR)/fat32.o $(SRCDIR)/shell.o

all: $(BINDIR)/filesys

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/filesys: $(BINDIR) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

test: $(BINDIR)/test_parts3_4

$(BINDIR)/test_parts3_4: test_parts3_4.c $(SRCDIR)/fat32.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(SRCDIR)/fat32.o

clean:
	rm -f $(SRCDIR)/*.o
	rm -f $(BINDIR)/filesys
	rm -f $(BINDIR)/test_parts3_4

.PHONY: all clean test
