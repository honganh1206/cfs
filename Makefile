CC := gcc
CFLAGS := -Wall -Werror
LDLIBS := -lcap -lseccomp

OBJS := contained.o child.o cgroups.o mounts.o namespaces.o security.o

contained: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

.PHONY: clean
clean:
	rm -f contained $(OBJS)
