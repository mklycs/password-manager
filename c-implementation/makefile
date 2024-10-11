CC = gcc
CFLAGS = -Wall -Wextra
TARGET = passwordmanager
SRCS = main.c
OBJS = $(SRCS:.c)

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) -lsqlcipher -lcrypto

clean:
	rm -f $(TARGET)

.PHONY: all clean