export CC=gcc
export CFLAGS=-m32 -fPIE

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

SUBDIRS=elf blake present
.PHONY: $(SUBDIRS)

all: oplzkwp 

oplzkwp: oplzkwp-naked encrypt
	./encrypt
	strip -K second_stage -K third_stage oplzkwp
	setfattr -n "user.pax.flags" -v "m" oplzkwp 

oplzkwp-naked: $(SUBDIRS) loader.o payload.o encrypt
	gcc -m32 -o oplzkwp -pie blake/blake224.o present/decrypt.o elf/elf_raw.o loader.o payload.o 
	setfattr -n "user.pax.flags" -v "m" oplzkwp 

encrypt: 
	gcc -m32 -o encrypt encrypt.c elf/elf_raw.o present/encrypt.o blake/blake224.o

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	-for d in $(SUBDIRS); do (cd $$d; $(MAKE) clean ); done
	rm *.o
	rm encrypt
	rm oplzkwp
