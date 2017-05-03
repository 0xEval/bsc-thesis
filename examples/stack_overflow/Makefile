DIRS += simple_overflow
DIRS += calling_arguments
DIRS += chaining_functions

all:
	for dir in $(DIRS) ; do (cd $$dir; make $1 || exit 1) || exit 1; done

clean:
	for dir in $(DIRS) ; do (cd $$dir; make clean); done
