a.out: myshell
	gcc main.c

myshell:
	gcc main.c -o myshell

clean:
	rm a.out myshell
