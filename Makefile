# Copyright (C) 2016-2017  RedTeam Pentesting GmbH
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

include version.gmk
CFLAGS?=
LDFLAGS?=
SONAME=libnvcrypt.so.1
PREFIX?=/usr
LIBDIR?=$(PREFIX)/lib
TARBALL=libnvcrypt-$(VERSION).tar.gz
DEBIANTARBALL=libnvcrypt_$(VERSION).orig.tar.gz

.PHONY: all clean

all: $(SONAME) libnvcrypt.so

$(SONAME): libnvcrypt.o tpm_nvram.o
	$(CC) -shared -std=gnu99 -fvisibility=hidden $(CFLAGS) -ltspi $(LDFLAGS) -Wl,-soname,$(SONAME) -o $@ $^

libnvcrypt.so: $(SONAME)
	ln -sf $^ $@

%.o: %.c %.h
	$(CC) -fPIC -c -std=gnu99 -fvisibility=hidden $(CFLAGS) -o $@ $<

clean:
	rm -f main *.o libnvcrypt.so $(SONAME) *.a $(TARBALL) $(DEBIANTARBALL)

install: all
	install -D -t $(DESTDIR)$(LIBDIR) $(SONAME)
	install -D -t $(DESTDIR)/usr/include libnvcrypt.h
	ln -s $(SONAME) $(DESTDIR)$(LIBDIR)/libnvcrypt.so

dist: libnvcrypt_$(VERSION).orig.tar.gz

$(TARBALL):
	git archive --format=tar.gz --prefix=libnvcrypt-$(VERSION)/ HEAD > $@

$(DEBIANTARBALL): $(TARBALL)
	cp $^ $@
