CXX = g++
CFLAGS = -std=c++11
LIBRARY = -lelf -lcapstone
SOURCE = sdb.cpp elftool.c
TARGET = sdb

.PHONY: all clean

all:
	$(CXX) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBRARY)
clean:
	rm -rf sdb
