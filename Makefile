all:
	gcc -m32 -o decrypt.o -fPIE -c decrypt.c
	gcc -m32 -o payload.o -fPIE -c payload.c
	gcc -m32 -o past -pie decrypt.o payload.o
	gcc -m32 -o encrypt encrypt.c

clean:
	rm *.o
	rm encrypt
	rm past

