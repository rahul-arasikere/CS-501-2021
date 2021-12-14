CC=x86_64-w64-mingw32-gcc 
CXX=x86_64-w64-mingw32-g++
CFLAGS=-municode
LDFLAGS=-lWinmm
DLL=-shared

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else
	RM=rm
endif


all: rdi 

rdi: 	
	$(CXX)  peloader.cpp rdll.cpp   $(DLL) $(CFLAGS) -o rdll.dll 