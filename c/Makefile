CFLAGS := -Iinclude -W -Wall -Wextra -Werror

HEADERS := include/cx.h $(wildcard include/cx/*.h)

all : src/drbg.o src/generator.o

src/%.o : src/%.c $(HEADERS) Makefile
	$(CC) $(CFLAGS) -o $@ -c $<

clean :
	$(RM) src/*.o
