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

static int my_http_filter(unsigned char *data, int data_len)
{
	struct iphdr * iph = (struct iphdr *)data;	
	int i;

	if (iph->protocol = IPPROTO_TCP) { 
		/* Skip the size of the IP Header. iph->ihl contains the number of 32 bit
		   words that represent the header size. Therfore to get the number of bytes
		   multiple this number by 4 */
		struct tcphdr *tcp = ((struct tcphdr *) (data + (iph->ihl << 2)));

		char *http = ((char *)tcp + (tcp->doff << 2));
		int http_payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - tcp->doff * 4; 
		char *http_copy = malloc(http_payload_len + 1);

		if (http_payload_len == 0)
			return 0;

		my_print_ip_hdr(iph);
		my_print_tcp_hdr(tcp);
		printf("payload (len=%d / %d):\n", http_payload_len, data_len);

		for (i = 0; i < http_payload_len; i++) {
			if (http[i] == '\r')
				printf("\\r");
			else
				printf("%c", http[i]);
			
			http_copy[i] = http[i];
		}
		http_copy[i] = '\n';
		printf("\n");

		/* block all .png file requests */
		if (strstr(http_copy, ".png HTTP/1.1") == NULL) {
			printf("[accept]\n");
			return 0;
		} else {
			printf("[bloking]\n");
			return 1;
		}
	}

	return 0;
}

/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb)
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
		//printf("hw_protocol=0x%04x hook=%u id=%u ",
		//	ntohs(ph->hw_protocol), ph->hook, id);
	}

//	hwph = nfq_get_packet_hw(tb);
//	if (hwph) {
//		int i, hlen = ntohs(hwph->hw_addrlen);
//
//		printf("hw_src_addr=");
//		for (i = 0; i < hlen-1; i++)
//			printf("%02x:", hwph->hw_addr[i]);
//		printf("%02x ", hwph->hw_addr[hlen-1]);
//	}
//
//	mark = nfq_get_nfmark(tb);
//	if (mark)
//		printf("mark=%u ", mark);
//
//	ifi = nfq_get_indev(tb);
//	if (ifi)
//		printf("indev=%u ", ifi);
//
//	ifi = nfq_get_outdev(tb);
//	if (ifi)
//		printf("outdev=%u ", ifi);
//	ifi = nfq_get_physindev(tb);
//	if (ifi)
//		printf("physindev=%u ", ifi);
//
//	ifi = nfq_get_physoutdev(tb);
//	if (ifi)
//		printf("physoutdev=%u ", ifi);
//
//	ret = nfq_get_payload(tb, &data);
//	if (ret >= 0)
//		printf("payload_len=%d ", ret);
//
//	fputc('\n', stdout);

	return id;
}
	

static int my_callbk(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *d)
{
	unsigned char *data;
	int data_len;
	data_len = nfq_get_payload(nfa, &data);	
	uint32_t id = print_pkt(nfa);
	if (my_http_filter(data, data_len))
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else
		return nfq_set_verdict(qh, id, NF_ACCEPT, data_len, data);
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

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
