all: libnss_identity.so

libnss_identity.so: nss_identity.o
	ld -G -o libnss_identity.so nss_identity.o

nss_identity.o: nss_identity.c
	gcc -c -shared nss_identity.c 
