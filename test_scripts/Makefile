all: first_exec first_exec_child1 second_exec second_exec_child1 test_hooks_synthetic test_hooks_synthetic_clang test_hooks_synthetic_go test_fork_execv test_multithreading

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

test_hooks_synthetic: test_hooks_synthetic.c
	gcc -o test_hooks_synthetic test_hooks_synthetic.c

test_hooks_synthetic_clang: test_hooks_synthetic.c
	clang -o test_hooks_synthetic_clang test_hooks_synthetic.c

test_hooks_synthetic_go: test_hooks_synthetic.go
	go build -o test_hooks_synthetic_go test_hooks_synthetic.go

test_fork_execv: test_fork_execv.c
	gcc -o test_fork_execv test_fork_execv.c

test_multithreading: test_multithreading.c
	gcc -O2 -pthread -fopenmp -o test_multithreading test_multithreading.c
