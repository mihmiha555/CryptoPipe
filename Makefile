CURRENT = $(shell uname -r)
KDIR = /lib/modules/$(CURRENT)/build
TARGET1 = CryptoPipe
OBJS = \
	pipe.o \
	blowfish.o \
	
$(TARGET1)-objs := $(OBJS)
obj-m := $(TARGET1).o
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
