# Makefile for the CS:APP Shell Lab

DRIVER = ./sdriver.pl
TSH = ./tsh
TSHREF = ./tshref
TSHARGS = "-p"
CC = gcc
CFLAGS = -Werror -Wall -Wextra -O2 -g
MYPROGS = ./myspin ./mysplit ./mystop ./myint
ALLPROGS = $(TSH) $(MYPROGS)

all: $(ALLPROGS)

##################
# Regression tests
##################

# Run tests using the student's shell program
%.test: %.txt $(ALLPROGS)
	$(DRIVER) -t $< -s $(TSH) -a $(TSHARGS)

# Run the tests using the reference shell program
%.rtest: %.txt $(MYPROGS)
	$(DRIVER) -t $< -s $(TSHREF) -a $(TSHARGS)

format:
	clang-format -i -style=file *.c

# clean up
clean:
	$(RM) $(ALLPROGS) *.o *~ core.[1-9]*

.PHONY: all format clean
.PHONY: test01 test02 test03 test04 test05 test06 test07 test08 test09
.PHONY: test10 test11 test12
.PHONY: rtest01 rtest02 rtest03 rtest04 rtest05 rtest06 rtest07 rtest08 rtest09
.PHONY: rtest10 rtest11 rtest12
