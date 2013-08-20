-include mk/$(shell uname -s).mk

project = ubolt

prefix = /
libdir = $(prefix)/lib
lib64dir = $(prefix)/lib64
pamdir = $(prefix)/lib/security
mandir = $(prefix)/usr/share/man/man3

nss_targets = nss_identity nss_filter
pam_targets = pam_provision pam_globus

targets = $(nss_targets) $(pam_targets)

# If compiled with -DDEBUG, then applications will print debugging
# information to stdout when NSSDEBUG is set in the environment.
#CFLAGS	+= -DDEBUG -g

# -fPIC is not required on all platforms, but is on some; and it doesn't
# appear to hurt.
CFLAGS += -fPIC $(cflags)

all: $(targets)

$(nss_targets):
	@ $(MAKE) nsslink manual name=$@

pam_provision:
	@ $(MAKE) pamlink manual name=$@

pam_globus: globus.o
	@ $(MAKE) pamlink manual name=$@ PAM_LIBS="globus.o -lcurl"

$(patsubst %,%.c,$(targets)): version.o

.PHONY: nsslink pamlink install clean release

nsslink: $(name).o util.o version.o
	$(SO_LD) -o lib$(name).so.2 $(name).o version.o

pamlink: $(name).o util.o version.o
	$(SO_LD) -o $(name).so $(name).o version.o util.o $(PAM_LIBS)

manual: doc/$(name).txt
	-rst2man doc/$(name).txt >doc/$(name).3.tmp
	mv -f doc/$(name).3.tmp doc/$(name).3

version.c:
	hg parents --template='static char version[] = "ubolt version {rev} {node|short} ({latesttag}+{latesttagdistance})";\n' >version.c

version.o: version.c
util.o: util.c

install:
	arch=`uname -m`; \
	if [ "$$arch" = "x86_64" ]; then \
		mkdir -p $(lib64dir) $(pamdir); \
		cp -f $(patsubst %,lib%.so.2,$(nss_targets)) $(lib64dir); \
		cp -f $(patsubst %,%.so,$(pam_targets)) $(pamdir); \
	else \
		mkdir -p $(libdir) $(pamdir); \
		cp -f $(patsubst %,lib%.so.2,$(targets)) $(libdir); \
		cp -f $(patsubst %,%.so,$(pam_targets)) $(pamdir); \
	fi
	mkdir -p $(mandir)
	cp -f $(patsubst %,doc/%.3,$(targets)) $(mandir)

clean:
	rm -f $(patsubst %,%.o,$(targets)) \
		$(patsubst %,lib%.so.2,$(nss_targets)) \
		$(patsubst %,%.so,$(pam_targets)) \
		$(patsubst %,doc/%.3,$(targets)) \
		$(patsubst %,doc/%.3,$(targets)) \
		globus.o util.o version.c version.o

release:
	rev=`hg parents --template '{rev}'`; \
	dir=$(project)-$${rev}; \
	rm -rf "$$dir"; \
	hg archive "$$dir"; \
	(cd "$$dir"; make version.c); \
	tar czf "$$dir.tar.gz" "$$dir"; \
	rm -rf "$$dir"
