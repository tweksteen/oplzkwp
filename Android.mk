LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_CFLAGS += -Wall
LOCAL_MODULE := oplzkwp
LOCAL_SRC_FILES:= loader.c \
									blake/blake224.c \
								  present/present.c \
									elf/elf_raw.c \
                  payload.c

# Hack to keep _e_* symbols when stripping executable
TARGET_STRIP += -w -K _e_*

include $(BUILD_EXECUTABLE)
