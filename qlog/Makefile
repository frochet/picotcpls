CLANG = clang-10


BPFCODE = qlog_kern

SRCDIRS  = /home/kate/kernel-src
INCLUDEDIR = /home/kate/kernel-src

BPFTOOLS = $(SRCDIRS)/samples/bpf
BPFLOADER = $(BPFTOOLS)/bpf_load


LOADINCLUDE += -I$(INCLUDEDIR)/samples/bpf
LOADINCLUDE += -I$(INCLUDEDIR)/tools/lib
LOADINCLUDE += -I$(INCLUDEDIR)/tools/perf
LOADINCLUDE += -I$(INCLUDEDIR)/tools/include
LIBRARY_PATH = -L/usr/local/lib64
BPFSO = -lbpf



.PHONY: clean $(CLANG) bpfload build qlog_kern qlog

clean:
	rm -f *.o *.so $(EXECABLE)

qlog_kern: ${BPFCODE.c}
	$(CLANG) -O2 -target bpf -c $(BPFCODE:=.c)  -o ${BPFCODE:=.o}

bpfload:
	$(CLANG) $(CFLAGS) -c -fPIC -o bpf_load.o $(LOADINCLUDE)  $(BPFLOADER:=.c)
qlog: qlog.c
	$(CLANG) $(CFLAGS) -c -fPIC -o qlog.o   $(LOADINCLUDE)  qlog.c

build: qlog_kern qlog bpfload
	gcc -shared bpf_load.o qlog.o -o libqlog.so
	cp libqlog.so ..

.DEFAULT_GOAL := build
