OBJS	= tclstudio.o
SOURCE	= tclstudio.c
HEADER	= 
OUT	= tclstudio
CC	 = gcc
FLAGS	 = -g -c -Wall -O2
LFLAGS	 = -s

all: $(OBJS)
	$(CC) -g $(OBJS) -o $(OUT) $(LFLAGS)

tclstudio.o: tclstudio.c
	$(CC) $(FLAGS) tclstudio.c -std=c99


clean:
	rm -f $(OBJS) $(OUT)