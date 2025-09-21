##
##  Makefile
##

DEBUG                   := 0
MAINTAINER_MODE         ?= 0

BUILD_MODE              := native

ifneq ($(filter windows release,$(MAKECMDGOALS)),)
  BUILD_MODE := cross
endif

##
## Detect Operating System
##

UNAME                   := $(shell uname -s)

# we need to strip the windows version number to be able to build hashcat on cygwin hosts
UNAME                   := $(patsubst CYGWIN_NT-%,CYGWIN,$(UNAME))

# same for msys
UNAME                   := $(patsubst MSYS_NT-%,MSYS2,$(UNAME))
UNAME                   := $(patsubst MINGW32_NT-%,MSYS2,$(UNAME))
UNAME                   := $(patsubst MINGW64_NT-%,MSYS2,$(UNAME))

ifneq ($(BUILD_MODE),native)
ifeq ($(UNAME),Darwin)
BREW_MINGW_PREFIX       := $(shell brew --prefix mingw-w64)
endif
endif

ifneq ($(DEBUG),0)
$(info "## Detected Operating System : $(UNAME)")
$(info "## Detected Build Mode: $(BUILD_MODE)")
$(info "## Detected CC : $(CC)")
ifneq ($(BUILD_MODE),native)
$(info "## Detected CC_WINDOWS : $(CC_WINDOWS)")
ifeq ($(UNAME),Darwin)
$(info "## Detected Brew MinGW Prefix: $(BREW_MINGW_PREFIX)")
endif
endif
endif

##
## General compiler and linker options
##

CFLAGS                  += -W -Wall -Wextra -pipe -std=gnu99

ifeq ($(MAINTAINER_MODE),0)
ifeq ($(BUILD_MODE),native)
CFLAGS                  += -march=native
endif
endif

COMBINATOR_LEN_MAX      := 512

ifeq ($(DEBUG),0)
CFLAGS                  += -O2
ifneq ($(UNAME),Darwin)
LFLAGS                  += -s
endif
else
ifeq ($(DEBUG),1)
ifneq ($(UNAME),Darwin)
CFLAGS                  += -DDEBUG -Og -ggdb
else
CFLAGS                  += -DDEBUG -O0 -ggdb
endif
else
ifeq ($(DEBUG),2)
ifneq ($(UNAME),Darwin)
CFLAGS                  += -DDEBUG -Og -ggdb
else
CFLAGS                  += -DDEBUG -O0 -ggdb
endif
CFLAGS                  += -fsanitize=address -fno-omit-frame-pointer
endif
endif
endif

all: clean native

release: native windows
	$(STRIP_NATIVE) bin/*.bin
	$(STRIP_WINDOWS) bin/*.exe
	cp -a src/*.pl bin
	cp -a src/*.py bin

clean:
	rm -f bin/*

##
## native
##

CC                      ?= gcc
CC_NATIVE               := $(CC)
STRIP_NATIVE            := strip
CFLAGS_NATIVE           := $(CFLAGS)
LDFLAGS_NATIVE          := $(LDFLAGS)

native: cap2hccapx.bin cleanup-rules.bin combinator.bin combinator3.bin combinatorX.bin combipow.bin ct3_to_ntlm.bin cutb.bin expander.bin gate.bin generate-rules.bin hcstatgen.bin hcstat2gen.bin keyspace.bin len.bin mli2.bin morph.bin ngramX.bin permute.bin permute_exist.bin prepare.bin req-include.bin req-exclude.bin rli.bin rli2.bin rules_optimize.bin splitlen.bin strip-bsr.bin strip-bsn.bin

cap2hccapx.bin: src/cap2hccapx.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

cleanup-rules.bin: src/cleanup-rules.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

combinator.bin: src/combinator.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $< -DLEN_MAX=$(COMBINATOR_LEN_MAX)

combinator3.bin: src/combinator3.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $< -DLEN_MAX=$(COMBINATOR_LEN_MAX)

combinatorX.bin: src/combinatorX.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $< -DLEN_MAX=$(COMBINATOR_LEN_MAX)

combipow.bin: src/combipow.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

ct3_to_ntlm.bin: src/ct3_to_ntlm.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

cutb.bin: src/cutb.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

expander.bin: src/expander.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

gate.bin: src/gate.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

generate-rules.bin: src/generate-rules.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

hcstatgen.bin: src/hcstatgen.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

hcstat2gen.bin: src/hcstat2gen.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

keyspace.bin: src/keyspace.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

len.bin: src/len.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

mli2.bin: src/mli2.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

morph.bin: src/morph.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

ngramX.bin: src/ngramX.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

permute.bin: src/permute.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

permute_exist.bin: src/permute_exist.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

prepare.bin: src/prepare.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

req-include.bin: src/req-include.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

req-exclude.bin: src/req-exclude.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

rli.bin: src/rli.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

rli2.bin: src/rli2.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

rules_optimize.bin: src/rules_optimize.c src/cpu_rules.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ src/rules_optimize.c src/cpu_rules.c

splitlen.bin: src/splitlen.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

strip-bsr.bin: src/strip-bsr.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

strip-bsn.bin: src/strip-bsn.c
	${CC_NATIVE} ${CFLAGS_NATIVE} ${LDFLAGS_NATIVE} -o bin/$@ $<

##
## WINDOWS
##

CC_WINDOWS              ?= x86_64-w64-mingw32-gcc
STRIP_WINDOWS           ?= x86_64-w64-mingw32-strip

ifeq (,$(findstring clang, $(CC_WINDOWS)))
CFLAGS_WINDOWS          := $(CFLAGS) -D_WINDOWS
else
CFLAGS_WINDOWS          := --target=x86_64-w64-mingw32
ifeq ($(UNAME),Darwin)
CFLAGS_WINDOWS          += --sysroot=$(BREW_MINGW_PREFIX)/toolchain-x86_64
endif
CFLAGS_WINDOWS          += $(CFLAGS) -D_WINDOWS
endif

ifeq ($(UNAME),Darwin)
GLOB_WINDOWS            := $(BREW_MINGW_PREFIX)/toolchain-x86_64/x86_64-w64-mingw32/lib/CRT_glob.o
else
GLOB_WINDOWS            := /usr/x86_64-w64-mingw32/lib/CRT_glob.o
endif

windows: cap2hccapx.exe cleanup-rules.exe combinator.exe combinator3.exe combinatorX.exe combipow.exe ct3_to_ntlm.exe cutb.exe expander.exe gate.exe generate-rules.exe hcstatgen.exe hcstat2gen.exe keyspace.exe len.exe mli2.exe morph.exe ngramX.exe permute.exe permute_exist.exe prepare.exe req-include.exe req-exclude.exe rli.exe rli2.exe rules_optimize.exe splitlen.exe strip-bsr.exe strip-bsn.exe

cap2hccapx.exe: src/cap2hccapx.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

cleanup-rules.exe: src/cleanup-rules.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

combinator.exe: src/combinator.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $< -DLEN_MAX=$(COMBINATOR_LEN_MAX)

combinator3.exe: src/combinator3.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $< -DLEN_MAX=$(COMBINATOR_LEN_MAX)

combinatorX.exe: src/combinatorX.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $< -DLEN_MAX=$(COMBINATOR_LEN_MAX)

combipow.exe: src/combipow.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

ct3_to_ntlm.exe: src/ct3_to_ntlm.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

cutb.exe: src/cutb.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

expander.exe: src/expander.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

gate.exe: src/gate.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

generate-rules.exe: src/generate-rules.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

hcstatgen.exe: src/hcstatgen.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

hcstat2gen.exe: src/hcstat2gen.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

keyspace.exe: src/keyspace.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

len.exe: src/len.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

mli2.exe: src/mli2.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

morph.exe: src/morph.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

ngramX.exe: src/ngramX.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

permute.exe: src/permute.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

permute_exist.exe: src/permute_exist.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

prepare.exe: src/prepare.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

req-include.exe: src/req-include.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

req-exclude.exe: src/req-exclude.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

rli.exe: src/rli.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $< ${GLOB_WINDOWS}

rli2.exe: src/rli2.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

rules_optimize.exe: src/rules_optimize.c src/cpu_rules.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ src/rules_optimize.c src/cpu_rules.c

splitlen.exe: src/splitlen.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

strip-bsr.exe: src/strip-bsr.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<

strip-bsn.exe: src/strip-bsn.c
	${CC_WINDOWS} ${CFLAGS_WINDOWS} -o bin/$@ $<
