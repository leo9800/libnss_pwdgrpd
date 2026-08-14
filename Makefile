CC = gcc
CFLAGS += -Wall -Werror -Wformat -Wformat-security -std=c99
#LDFLAGS += -rdynamic -Wl,--as-needed -Wl,-z,defs -Wl,-z,now -Wl,-z,relro

LIBNSS_PWDGRPD_HTTPS_ONLY ?= true

.PHONY: clean

all: libnss_pwdgrpd.so.2

libnss_pwdgrpd.so.2: nss-pwdgrpd.c
	$(CC) -shared -fPIC $(CFLAGS) $(LDFLAGS) \
		$(shell pkg-config --cflags json-c libcurl inih) \
		$(shell pkg-config --libs json-c libcurl inih) -lc \
		-DLIBNSS_PWDGRPD_HTTPS_ONLY=$(LIBNSS_PWDGRPD_HTTPS_ONLY) \
		-o $@ $<

utils: bin/getpwnam.out bin/getpwuid.out bin/getpwall.out bin/getgrnam.out bin/getgrgid.out bin/getgrall.out bin/initgroups.out

bin/%.out: bin/%.c libnss_pwdgrpd.so.2 nss-pwdgrpd.h
	$(CC) -I. $(CFLAGS) $(LDFLAGS) -lc libnss_pwdgrpd.so.2 -o $@ $<
# 	if you want LD_LIBRARY_PATH to be omitted ...
# 	$(CC) -I. $(CFLAGS) $(LDFLAGS) -lc -Wl,-rpath=../ libnss_pwdgrpd.so.2 -o $@ $<

clean:
	rm -rf libnss_pwdgrpd.so.2
	rm -rf bin/*.out
