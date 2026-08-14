CC = gcc
LIBS += -lc $(shell pkg-config --libs json-c libcurl inih)
CFLAGS += $(shell pkg-config --cflags json-c libcurl inih)
CFLAGS += -Wall -Werror -Wformat -Wformat-security -std=c99
#LDFLAGS += -rdynamic -Wl,--as-needed -Wl,-z,defs -Wl,-z,now -Wl,-z,relro

LIBNSS_PWDGRPD_HTTPS_ONLY ?= true

.PHONY: clean

all: libnss_pwdgrpd.so.2

libnss_pwdgrpd.so.2: nss-pwdgrpd.c
	$(CC) -shared -fPIC $(CFLAGS) $(LDFLAGS) $(LIBS) -DLIBNSS_PWDGRPD_HTTPS_ONLY=$(LIBNSS_PWDGRPD_HTTPS_ONLY) -o $@ $<

clean:
	rm -rf libnss_pwdgrpd.so.2
