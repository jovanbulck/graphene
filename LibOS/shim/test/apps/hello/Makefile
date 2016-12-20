
manifests = helloworld.manifest

target = helloworld
exec_target = $(manifests)

extra_rules = \
	-e 's:\$$(PAL):../pal_loader:g'

level = ../../
include ../../Makefile

helloworld: helloworld.o
	@echo "[ now linking.. ]"
	@# link through the compiler to avoid linking errors
	$(CC) $(LDFLAGS) $^ -o $@

%.o : %.c
	@echo [ $< ]
	$(CC) $(CFLAGS) -c $< -o $@

distclean: clean
	rm -f *.o *.manifest.sgx *.sig *.token
