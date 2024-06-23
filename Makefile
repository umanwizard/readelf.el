CC		= gcc
LD		= gcc
CFLAGS = -ggdb -O3
CAPSTONE_LDFLAGS = `pkg-config --libs capstone`
CAPSTONE_CFLAGS = `pkg-config --cflags capstone`

capstone-core.so: capstone-core.o
	$(LD) -shared $(LDFLAGS) $(CAPSTONE_LDFLAGS) -o $@ $^ -lcapstone

capstone-core.o: src/capstone-core.c
	$(CC) $(CFLAGS) $(CAPSTONE_CFLAGS) -fPIC -c -o $@ $^

clean:
	-rm -f capstone-core.o capstone-core.so
