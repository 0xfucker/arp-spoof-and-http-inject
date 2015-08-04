all: arp-poison.out my_http_filter.out

%.out: %.c
	gcc $^ -lnetfilter_queue -o $@

clean:
	rm -f *.out
