all: ./code/fibo.o ./code/main.o
	gcc ./code/fibo.o ./code/main.o -o fibo
./code/fibo.o ./code/main.o:
	$(MAKE) -C code
clean:
	rm ./code/fibo.o
	rm ./code/main.o
