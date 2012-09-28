
target = libnss_identity.so.2

all: $(target)

$(target): nss_identity.o
	gcc -shared -Wl,-soname,$(target) -o $(target) nss_identity.o

nss_identity.o: nss_identity.c
	if [ $$(arch) = i386 ]; then \
		gcc -c -shared nss_identity.c; \
	else \
		gcc -fPIC -c -shared nss_identity.c; \
	fi

clean:
	rm -f nss_identity.o $(target)
