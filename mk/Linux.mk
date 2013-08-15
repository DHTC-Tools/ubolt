CFLAGS = -Wall -shared -fPIC -DPAM_CONST=const
SO_LD = gcc $(CFLAGS) -shared -Wl,-soname,lib$(name).so.2
PAM_LIBS = 
