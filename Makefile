
targets = nss_identity nss_filter

CFLAGS	= -DDEBUG

all: $(targets)

$(targets):
	@ $(MAKE) nsslink name=$@

$(patsubst %,%.c,$(targets)):
	@ $(MAKE) nsscc name=$@

.PHONY: nsslink nsscc

nsslink: $(name).o
	gcc -shared -Wl,-soname,lib$(name).so.2 -o lib$(name).so.2 $(name).o

nsscc: $(name).c
	if [ $$(arch) = i386 ]; then \
		gcc -c -shared $(name).c; \
	else \
		gcc -fPIC -c -shared $(name).c; \
	fi

clean:
	rm -f $(patsubst %,%.o,$(targets)) $(patsubst %,lib%.so.2,$(targets))
