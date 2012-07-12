MODULE = pam_provision

-include mk/$(shell uname -s).mk

all: $(MODULE).so

$(MODULE).so: $(MODULE).o
	$(SO_LD) -o $@ $(MODULE).o $(LIBS)

clean:
	rm *.o *.so
