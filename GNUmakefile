MODULE = pam_provision

-include mk/$(shell uname -s).mk

all: $(MODULE).so

$(MODULE).so: $(MODULE).o
	ld -G -o $@ $(MODULE).o $(LIBS)

clean:
	rm *.o *.so
