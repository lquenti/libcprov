all: first_exec first_exec_child1 second_exec second_exec_child1

first_exec: first_exec.c
	gcc -o first_exec first_exec.c

first_exec_child1: first_exec_child1.c
	gcc -o first_exec_child1 first_exec_child1.c

first_exec_child2: first_exec_child2.c
	gcc -m32 -o first_exec_child2 first_exec_child2.c

second_exec: second_exec.c
	gcc -o second_exec second_exec.c

second_exec_child1: second_exec_child1.c
	gcc -o second_exec_child1 second_exec_child1.c
