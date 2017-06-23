##
##  Makefile
##

CFLAGS += -Wall -W -pipe -O2 -std=gnu99

all: clean native

release: native windows
	$(STRIP_NATIVE) *.bin
	$(STRIP_WINDOWS) *.exe
	mv *.bin ../bin
	mv *.exe ../bin
	cp -a *.pl ../bin

clean:
	rm -f ../bin/*
	rm -f *.bin *.exe

##
## native
##

CC            ?= gcc
CC_NATIVE      = $(CC)
STRIP_NATIVE   = strip
CFLAGS_NATIVE  = $(CFLAGS)
LDFLAGS_NATIVE = $(LDFLAGS)

native:
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o cap2hccapx.bin cap2hccapx.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o cleanup-rules.bin cleanup-rules.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o combinator.bin combinator.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o combinator3.bin combinator3.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o combipow.bin combipow.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o ct3_to_ntlm.bin ct3_to_ntlm.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o cutb.bin cutb.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o expander.bin expander.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o gate.bin gate.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o generate-rules.bin generate-rules.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o hcstatgen.bin hcstatgen.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o hcstat2gen.bin hcstat2gen.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o keyspace.bin keyspace.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o len.bin len.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o mli2.bin mli2.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o morph.bin morph.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o permute.bin permute.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o permute_exist.bin permute_exist.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o prepare.bin prepare.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o req-include.bin req-include.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o req-exclude.bin req-exclude.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o rli.bin rli.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o rli2.bin rli2.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o rules_optimize.bin rules_optimize.c cpu_rules.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o splitlen.bin splitlen.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o strip-bsr.bin strip-bsr.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o strip-bsn.bin strip-bsn.c

##
## WINDOWS
##

CC_WINDOWS     = x86_64-w64-mingw32-gcc
STRIP_WINDOWS  = x86_64-w64-mingw32-strip
CFLAGS_WINDOWS = $(CFLAGS) -D_WINDOWS
GLOB_WINDOWS   = /usr/x86_64-w64-mingw32/lib/CRT_glob.o

windows:
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o cap2hccapx.exe cap2hccapx.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o cleanup-rules.exe cleanup-rules.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o combinator.exe combinator.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o combinator3.exe combinator3.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o combipow.exe combipow.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o ct3_to_ntlm.exe ct3_to_ntlm.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o cutb.exe cutb.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o expander.exe expander.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o gate.exe gate.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o generate-rules.exe generate-rules.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o hcstatgen.exe hcstatgen.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o hcstat2gen.exe hcstat2gen.c
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
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o rules_optimize.exe rules_optimize.c cpu_rules.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o splitlen.exe splitlen.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o strip-bsr.exe strip-bsr.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o strip-bsn.exe strip-bsn.c
