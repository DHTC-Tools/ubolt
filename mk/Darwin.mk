CFLAGS = -Wall -shared -fPIC -DPAM_CONST=const
LIBS = -lc -lpam
SO_LD = libtool -dynamic -flat_namespace
