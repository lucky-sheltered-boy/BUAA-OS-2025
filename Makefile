all: check
	gcc -I./src/include  ./src/main.c ./src/output.c -o main
	mv main ./out

check: check.c
	gcc -c check.c -o check.o

run: all
	./out/main

.PHONY: clean
clean: 
	rm check.o
	./out/main
