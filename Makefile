default: enin
install: enin
	cp enin /usr/bin
enin:	enin.c
	gcc enin.c -o enin -O2

