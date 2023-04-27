LDLIBS += -lnetfilter_queue

all: netfilter-test

netfilter-test: netfilter-test.cpp

clean:
	rm -f netfilter-test *.o
