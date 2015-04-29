export CC=gcc
export CFLAGS=-m32 -fPIE -ggdb3

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

SUBDIRS=elf blake present
.PHONY: $(SUBDIRS)

all: oplzkwp 

oplzkwp: oplzkwp-naked encrypt
	./encrypt

oplzkwp-naked: $(SUBDIRS) loader.o payload.o encrypt
	gcc -m32 -o oplzkwp -pie blake/blake224.o present/decrypt.o elf/elf_raw.o loader.o payload.o 
	setfattr -n "user.pax.flags" -v "m" oplzkwp 

encrypt: 
	gcc -m32 -o encrypt encrypt.c elf/elf_raw.o present/encrypt.o blake/blake224.o

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	$(MAKE) -C present clean
	$(MAKE) -C blake clean
	rm *.o
	rm encrypt
	rm oplzkwp
