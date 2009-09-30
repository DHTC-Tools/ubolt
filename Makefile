MODULE = pam_provision

all: $(MODULE).so

CFLAGS = -Wall -shared

$(MODULE).so: $(MODULE).o
	ld -G -o $@ $(MODULE).o -lsocket -lnsl

clean:
	rm *.o *.so
