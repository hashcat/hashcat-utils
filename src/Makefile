##
##  Makefile
##

CFLAGS = -Wall -W -pipe -O2

all: clean release

release: linux windows osx
	$(STRIP_LINUX)   *.bin
	$(STRIP_WINDOWS) *.exe
	$(STRIP_OSX)     *.app

clean:
	rm -f core *.bin *.exe *.app

##
## LINUX
##

CC_LINUX       = gcc
STRIP_LINUX    = strip
CFLAGS_LINUX   = $(CFLAGS) -D_LINUX

linux:
	${CC_LINUX} ${CFLAGS_LINUX} -o cleanup-rules.bin cleanup-rules.c
	${CC_LINUX} ${CFLAGS_LINUX} -o combinator.bin combinator.c
	${CC_LINUX} ${CFLAGS_LINUX} -o combinator3.bin combinator3.c
	${CC_LINUX} ${CFLAGS_LINUX} -o combipow.bin combipow.c
	${CC_LINUX} ${CFLAGS_LINUX} -o cutb.bin cutb.c
	${CC_LINUX} ${CFLAGS_LINUX} -o expander.bin expander.c
	${CC_LINUX} ${CFLAGS_LINUX} -o gate.bin gate.c
	${CC_LINUX} ${CFLAGS_LINUX} -o generate-rules.bin generate-rules.c
	${CC_LINUX} ${CFLAGS_LINUX} -o hcstatgen.bin hcstatgen.c -lm
	${CC_LINUX} ${CFLAGS_LINUX} -o keyspace.bin keyspace.c
	${CC_LINUX} ${CFLAGS_LINUX} -o len.bin len.c
	${CC_LINUX} ${CFLAGS_LINUX} -o mli2.bin mli2.c
	${CC_LINUX} ${CFLAGS_LINUX} -o morph.bin morph.c
	${CC_LINUX} ${CFLAGS_LINUX} -o permute.bin permute.c
	${CC_LINUX} ${CFLAGS_LINUX} -o permute_exist.bin permute_exist.c
	${CC_LINUX} ${CFLAGS_LINUX} -o prepare.bin prepare.c
	${CC_LINUX} ${CFLAGS_LINUX} -o req-include.bin req-include.c
	${CC_LINUX} ${CFLAGS_LINUX} -o req-exclude.bin req-exclude.c
	${CC_LINUX} ${CFLAGS_LINUX} -o rli.bin rli.c
	${CC_LINUX} ${CFLAGS_LINUX} -o rli2.bin rli2.c
	${CC_LINUX} ${CFLAGS_LINUX} -o splitlen.bin splitlen.c
	${CC_LINUX} ${CFLAGS_LINUX} -o strip-bsr.bin strip-bsr.c
	${CC_LINUX} ${CFLAGS_LINUX} -o strip-bsn.bin strip-bsn.c

##
## WINDOWS
##

CC_WINDOWS     = x86_64-w64-mingw32-gcc
STRIP_WINDOWS  = x86_64-w64-mingw32-strip
CFLAGS_WINDOWS = $(CFLAGS) -D_WINDOWS
GLOB_WINDOWS   = /usr/x86_64-w64-mingw32/lib/CRT_glob.o

windows:
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o cleanup-rules.exe cleanup-rules.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o combinator.exe combinator.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o combinator3.exe combinator3.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o combipow.exe combipow.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o cutb.exe cutb.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o expander.exe expander.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o gate.exe gate.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o generate-rules.exe generate-rules.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o hcstatgen.exe hcstatgen.c  -lm
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o keyspace.exe keyspace.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o len.exe len.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o mli2.exe mli2.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o morph.exe morph.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o permute.exe permute.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o permute_exist.exe permute_exist.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o prepare.exe prepare.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o req-include.exe req-include.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o req-exclude.exe req-exclude.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o rli.exe rli.c ${GLOB_WINDOWS}
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o rli2.exe rli2.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o splitlen.exe splitlen.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o strip-bsr.exe strip-bsr.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o strip-bsn.exe strip-bsn.c

##
## OSX
##

CC_OSX     = i686-apple-darwin10-gcc
STRIP_OSX  = i686-apple-darwin10-strip
CFLAGS_OSX = $(CFLAGS) -D_OSX

osx:
	${CC_OSX} ${CFLAGS_OSX} -o cleanup-rules.app cleanup-rules.c
	${CC_OSX} ${CFLAGS_OSX} -o combinator.app combinator.c
	${CC_OSX} ${CFLAGS_OSX} -o combinator3.app combinator3.c
	${CC_OSX} ${CFLAGS_OSX} -o combipow.app combipow.c
	${CC_OSX} ${CFLAGS_OSX} -o cutb.app cutb.c
	${CC_OSX} ${CFLAGS_OSX} -o expander.app expander.c
	${CC_OSX} ${CFLAGS_OSX} -o gate.app gate.c
	${CC_OSX} ${CFLAGS_OSX} -o generate-rules.app generate-rules.c
	${CC_OSX} ${CFLAGS_OSX} -o hcstatgen.app hcstatgen.c -lm
	${CC_OSX} ${CFLAGS_OSX} -o keyspace.app keyspace.c
	${CC_OSX} ${CFLAGS_OSX} -o len.app len.c
	${CC_OSX} ${CFLAGS_OSX} -o mli2.app mli2.c
	${CC_OSX} ${CFLAGS_OSX} -o morph.app morph.c
	${CC_OSX} ${CFLAGS_OSX} -o permute.app permute.c
	${CC_OSX} ${CFLAGS_OSX} -o permute_exist.app permute_exist.c
	${CC_OSX} ${CFLAGS_OSX} -o prepare.app prepare.c
	${CC_OSX} ${CFLAGS_OSX} -o req-include.app req-include.c
	${CC_OSX} ${CFLAGS_OSX} -o req-exclude.app req-exclude.c
	${CC_OSX} ${CFLAGS_OSX} -o rli.app rli.c
	${CC_OSX} ${CFLAGS_OSX} -o rli2.app rli2.c
	${CC_OSX} ${CFLAGS_OSX} -o splitlen.app splitlen.c
	${CC_OSX} ${CFLAGS_OSX} -o strip-bsr.app strip-bsr.c
	${CC_OSX} ${CFLAGS_OSX} -o strip-bsn.app strip-bsn.c
