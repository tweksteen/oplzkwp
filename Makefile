export EXEC=oplzkwp
export ANDROID_PLATFORM=android-19
export CC=gcc
export CFLAGS=-m32 -fpic -Wall -std=gnu99 -DEXEC_NAME=\"${EXEC}\" -DDEBUG

# [!] loader.o must be first, payload.o must be last
EXEC_OBJ=loader.o elf/elf_raw.o blake/blake224.o present/present.o payload.o
ENCRYPT_OBJ=elf/elf_raw.o present/present.o blake/blake224.o encrypt.o
SUBDIRS=elf blake present

.PHONY: $(SUBDIRS)
.SILENT: clean

all: $(EXEC)

$(EXEC): $(EXEC)-naked encrypt
	./encrypt
	strip -w -K _e_* $(EXEC)
	setfattr -n "user.pax.flags" -v "m" $(EXEC)

$(EXEC)-naked: $(SUBDIRS) $(EXEC_OBJ)
	$(CC) -m32 -o $(EXEC) -pie $(EXEC_OBJ)

encrypt: $(SUBDIRS) encrypt.o
	$(CC) -m32 -o encrypt $(ENCRYPT_OBJ)

$(SUBDIRS):
	@$(MAKE) -C $@

clean:
	@for d in $(SUBDIRS); do (cd $$d; $(MAKE) clean ); done
	rm -f *.o
	rm -f encrypt
	rm -f $(EXEC)
	rm -rf obj
	rm -rf libs

android: encrypt
	ndk-build NDK_PROJECT_PATH=$(CURDIR) \
					 	APP_BUILD_SCRIPT=$(CURDIR)/Android.mk \
						APP_PLATFORM=$(ANDROID_PLATFORM)
	./encrypt ./libs/armeabi/$(EXEC)
