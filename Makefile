
targets = nss_identity nss_filter

# If compiled with -DDEBUG, then applications will print debugging
# information to stdout when NSSDEBUG is set in the environment.
#CFLAGS	+= -DDEBUG

# For Linux x86_64, -fPIC is required
CFLAGS += $(shell [ "`uname -sm`" = "Linux x86_64" ] && echo -fPIC)

all: $(targets)

$(targets):
	@ $(MAKE) nsslink manual name=$@

$(patsubst %,%.c,$(targets)):
	@ $(MAKE) nsscc name=$@

.PHONY: nsslink nsscc

nsslink: $(name).o
	gcc -shared -Wl,-soname,lib$(name).so.2 -o lib$(name).so.2 $(name).o

manual: doc/$(name).txt
	-rst2man doc/$(name).txt >doc/$(name).3

nsscc: $(name).c
	if [ $$(arch) = i386 ]; then \
		gcc -c -shared $(name).c; \
	else \
		gcc -fPIC -c -shared $(name).c; \
	fi

clean:
	rm -f $(patsubst %,%.o,$(targets)) $(patsubst %,lib%.so.2,$(targets)) \
	$(patsubst %,doc/%.3,$(targets))
