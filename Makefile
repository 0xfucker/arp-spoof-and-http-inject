all: arp-poison.out http-inject.out

%.out: %.c
	gcc $^ -lnetfilter_queue -o $@

clean:
	rm -f *.out
