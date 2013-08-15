CFLAGS += -Wall -shared -fPIC -DPAM_CONST=const
SO_LD = libtool -dynamic -flat_namespace
PAM_LIBS = -lc -lpam
