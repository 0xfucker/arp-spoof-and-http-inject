#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>  /* for NF_ACCEPT / NF_DROP */
#include <errno.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <string.h> // find substring

static void my_print_ip_hdr(struct iphdr *iph)
{
	// display IP HEADERS : ip.h line 45
	fprintf(stdout, "IP{v=%u; ihl=%u; tos=%u; tot_len=%u; id=%u; ttl=%u; protocol=%u; ",
	                 iph->version, iph->ihl * 4, iph->tos, ntohs(iph->tot_len), 
	                 ntohs(iph->id), iph->ttl, iph->protocol);

	char *saddr = inet_ntoa(*(struct in_addr *)&iph->saddr);
	fprintf(stdout,"saddr=%s; ",saddr);

	char *daddr = inet_ntoa(*(struct in_addr *)&iph->daddr);
	fprintf(stdout,"daddr=%s}\n",daddr);
}

static void my_print_tcp_hdr(struct tcphdr *tcp)
{
	fprintf(stdout, "TCP{sport=%u; dport=%u; seq=%u; ack_seq=%u; flags=u%ua%up%ur%us%uf%u;"
	        " window=%u; urg=%u, header_len=%u}\n",
	        ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq),
	        tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin, 
	        ntohs(tcp->window), tcp->urg_ptr, tcp->doff * 4);
}

int my_print_non_0_http(unsigned char *data, int data_len)
{
	struct iphdr * iph = (struct iphdr *)data;	
	if (iph->protocol = IPPROTO_TCP) { 
		/* Skip the size of the IP Header. iph->ihl contains the number of 32 bit
		   words that represent the header size. Therfore to get the number of bytes
		   multiple this number by 4 */
		struct tcphdr *tcp = ((struct tcphdr *) (data + (iph->ihl << 2)));

		char *http = ((char *)tcp + (tcp->doff << 2));
		int http_payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - tcp->doff * 4; 

		if (http_payload_len == 0)
			return 0;

		if (data_len != ntohs(iph->tot_len)) {
			printf("<<<<<<<<<<<<<<\n");
			printf("bad!\n");
			printf(">>>>>>>>>>>>>>\n");
			return 0;
		}
		printf("total len: reported:%d / header:%d \n", data_len, ntohs(iph->tot_len));
		my_print_ip_hdr(iph);
		my_print_tcp_hdr(tcp);
		printf("payload (len=%d):\n", http_payload_len);
		int i;
		for (i = 0; i < http_payload_len; i++) {
			if (http[i] == '\r')
				printf("\\r");
			else
				printf("%c", http[i]);
		}
		printf("\n");

		return data_len - http_payload_len;
	}
	return 0;
}

char *my_http_copy(unsigned char *data, int data_len, int offset)
{
	char *http = (char *)data + offset;
	int http_payload_len = data_len - offset; 

	char *http_copy = malloc(http_payload_len + 1);
	int i;
	for (i = 0; i < http_payload_len; i++) {
		http_copy[i] = http[i];
	}
	http_copy[i] = '\0';
	return http_copy;
}

static int my_http_filter(unsigned char *data, int data_len)
{
	int offset = my_print_non_0_http(data, data_len);
	char *http_copy;

	if (offset > 0) { 
		// printf("http copy:\n%s--------\n", http_copy);
		http_copy = my_http_copy(data, data_len, offset);

		int res = 0;
	
		/* block all .png file requests */
		if (strstr(http_copy, ".png HTTP/1.1")) {
			printf("[blocked]\n");
			res = 1;
		/* modify all .css file requests */
		} else if (strstr(http_copy, ".css HTTP/1.1")) {
			char *http = (char *)data + offset;
			char *p = strstr(http, ".css HTTP/1.1");
			p[1] = 'e';
			p[2] = 'x';
			p[3] = 'e';
			printf("[modified]\n");
		/* accept other requests */
		} else {
			printf("[accepted]\n");
		}

		free(http_copy);
		return res;
	}

	return 0;
}

/* returns packet id */
static uint32_t my_get_packet_id(struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	return id;
}
	

static int my_callbk(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *d)
{
	unsigned char *data;
	int data_len;
	data_len = nfq_get_payload(nfa, &data);	
	uint32_t id = my_get_packet_id(nfa);
	if (my_http_filter(data, data_len))
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else {
		return nfq_set_verdict(qh, id, NF_ACCEPT, data_len, data);
	}
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096];

	if (argc == 2) {
		queue = atoi(argv[1]);
		if (queue > 65535) {
			fprintf(stderr, "Usage: %s [<0-65535>]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &my_callbk, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue\n");
	nfq_destroy_queue(qh);

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
