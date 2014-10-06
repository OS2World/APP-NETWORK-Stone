
SSL_FLAGS=	-DUSE_SSL -I/usr/local/ssl/include
SSL_LIBS=	-L/usr/local/ssl/lib -lssl -lcrypto

all:
	@echo "run make with one of the following arguments"
	@echo "linux     ; for Linux"
	@echo "bsd       ; for FreeBSD or BSD/OS"
	@echo "sun       ; for SunOS 4.x with gcc"
	@echo "solaris   ; for Solaris with gcc"
	@echo "hp        ; for HP-UX with gcc"
	@echo "win       ; for Windows 95/NT with VC++"
	@echo "emx       ; for OS/2 with EMX"
	@echo "using SSLeay, add '-ssl' (example: linux-ssl)"

clean:
	rm -f stone stone.exe stone.obj

stone: stone.c
	$(CC) $(CFLAGS) $(FLAGS) -o $@ $? $(LIBS)

ssl_stone:
	$(MAKE) FLAGS="$(SSL_FLAGS)" LIBS="$(SSL_LIBS)" $(TARGET)

stone.exe: stone.c
	$(CC) $(FLAGS) $? $(LIBS)

ssl_stone.exe:
	$(MAKE) FLAGS=-DUSE_SSL LIBS="ssleay32.lib libeay32.lib" $(TARGET)
#	$(MAKE) FLAGS=-DUSE_SSL LIBS="ssl32.lib crypt32.lib" $(TARGET)

linux:
	$(MAKE) FLAGS="-DINET_ADDR $(FLAGS)" stone

linux-ssl:
	$(MAKE) TARGET=linux ssl_stone

bsd:
	$(MAKE) stone

bsd-ssl:
	$(MAKE) TARGET=bsd ssl_stone

sun:
	$(MAKE) CC=gcc FLAGS="-DINET_ADDR -DNO_SNPRINTF -DIGN_SIGTERM $(FLAGS)" stone

sun-ssl:
	$(MAKE) TARGET=sun ssl_stone

solaris:
	$(MAKE) CC=gcc FLAGS="-DNO_SNPRINTF $(FLAGS)" LIBS="-lnsl -lsocket $(LIBS)" stone

solaris-ssl:
	$(MAKE) TARGET=solaris ssl_stone

hp:
	$(MAKE) CC=gcc FLAGS="-DNO_SNPRINTF -DH_ERRNO $(FLAGS)" stone

hp-ssl:
	$(MAKE) TARGET=hp ssl_stone

win:
	$(MAKE) FLAGS="-DWINDOWS $(FLAGS)" LIBS="/MT wsock32.lib $(LIBS)" stone.exe

win-ssl:
	$(MAKE) TARGET=win ssl_stone.exe

emx:
	$(MAKE) CC=gcc FLAGS="-DOS2 -Zmts -Zbsd-signals" LIBS="-lsocket" stone.exe
