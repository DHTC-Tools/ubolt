-include mk/$(shell uname -s).mk

project = ubolt

prefix = /
libdir = $(prefix)/lib
lib64dir = $(prefix)/lib64
mandir = $(prefix)/usr/share/man/man3

nss_targets = nss_identity nss_filter
pam_targets = pam_provision

targets = $(nss_targets) $(pam_targets)

# If compiled with -DDEBUG, then applications will print debugging
# information to stdout when NSSDEBUG is set in the environment.
#CFLAGS	+= -DDEBUG -g

# -fPIC is not required on all platforms, but is on some; and it doesn't
# appear to hurt.
CFLAGS += -fPIC

all: $(targets)

$(nss_targets):
	@ $(MAKE) nsslink manual name=$@

$(pam_targets):
	@ $(MAKE) pamlink manual name=$@

$(patsubst %,%.c,$(targets)): version.h

.PHONY: nsslink pamlink install clean release

nsslink: $(name).o
	gcc $(CFLAGS) -shared -Wl,-soname,lib$(name).so.2 -o lib$(name).so.2 $(name).o

pamlink: $(name).o
	$(SO_LD) -o $@ $(name).o $(PAM_LIBS)

manual: doc/$(name).txt
	-rst2man doc/$(name).txt >doc/$(name).3.tmp
	mv -f doc/$(name).3.tmp doc/$(name).3

version.h:
	hg parents --template='#define VERSION "{rev} {node|short} ({latesttag}+{latesttagdistance})"\n' >version.h

install:
	arch=`uname -m`; \
	if [ "$$arch" = "x86_64" ]; then \
		mkdir -p $(lib64dir); \
		cp -f $(patsubst %,lib%.so.2,$(targets)) $(lib64dir); \
	else \
		mkdir -p $(libdir); \
		cp -f $(patsubst %,lib%.so.2,$(targets)) $(libdir); \
	fi
	mkdir -p $(mandir)
	cp -f $(patsubst %,doc/%.3,$(targets)) $(mandir)

clean:
	rm -f $(patsubst %,%.o,$(targets)) $(patsubst %,lib%.so.2,$(targets)) \
		$(patsubst %,doc/%.3,$(targets)) version.h \
		$(patsubst %,doc/%.3,$(targets))

release:
	rev=`hg parents --template '{rev}'`; \
	dir=$(project)-$${rev}; \
	rm -rf "$$dir"; \
	hg archive "$$dir"; \
	(cd "$$dir"; make version.h); \
	tar czf "$$dir.tar.gz" "$$dir"; \
	rm -rf "$$dir"
