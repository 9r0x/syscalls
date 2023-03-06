SHELL		= /bin/sh

TARGET		= libfilter.so
OFILES		= filter.o queue.o

EXECS		= test.o
CC			= cc

CFLAGS		= -g -Wall -fPIC -pthread
IFLAGS		=
LFLAGS		= -L. -Wl,--rpath,.
LIBS		= -ldl

.PHONY: all cscope clean print

all: cscope $(TARGET) $(EXECS)
	for exec in $(EXECS); do \
		$(CC) $(CFLAGS) $(LFLAGS) -o bin/`basename $$exec .o` $$exec -lfilter; \
	done \

$(TARGET): $(OFILES)
	$(CC) -g -shared $(LFLAGS) -o $(TARGET) $(OFILES) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(IFLAGS) -c $< -o $@

print:
	$(CC) -g simple_printf.c -o bin/simple_printf

clean:
	rm -f $(TARGET) *.o
	for exec in $(EXECS) ; do \
		if [ -f `basename $$exec .o` ] ; then \
			rm `basename $$exec .o` ; \
		fi \
	done