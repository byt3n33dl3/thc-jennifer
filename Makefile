CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
TARGET = jennifer
SRC = jennifer.c
OBJ = $(SRC:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJ) $(TARGET)

install: $(TARGET)
	mkdir -p $(DESTDIR)/usr/local/bin
	mkdir -p $(DESTDIR)/usr/local/share/jennifer/src
	cp $(TARGET) $(DESTDIR)/usr/local/bin/
	cp src/wordlists.txt $(DESTDIR)/usr/local/share/jennifer/src/