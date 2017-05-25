#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <string.h>
#include <time.h>

#define COLOR_RST     "\033[0m" /* Color Reset */
#define COLOR_RED     "\033[1m\033[31m" /* Red */

#define REPLACE_PATTERN "function play68_init()"

struct data {
	unsigned char *data;
	int data_len;
};

uint16_t cksum(uint32_t sum, uint16_t *buf, int size)
{
	while (size > 1) {
		sum += *(buf++);
		size -= sizeof(uint16_t);
	}
	if (size) {
		sum += *(uint8_t *)buf;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (uint16_t)(~sum);
}

uint16_t cksum_tcp(struct iphdr *iph)
{
	uint32_t sum = 0;
	uint32_t iph_len = iph->ihl * 4;
	uint32_t len = ntohs(iph->tot_len) - iph_len;
	uint8_t *payload = (uint8_t *)iph + iph_len;

	sum += (iph->saddr >> 16) & 0xFFFF;
	sum += (iph->saddr) & 0xFFFF;
	sum += (iph->daddr >> 16) & 0xFFFF;
	sum += (iph->daddr) & 0xFFFF;
	sum += htons(IPPROTO_TCP);
	sum += htons(len);

	return cksum(sum, (uint16_t *)payload, len);
}

char *http_time() 
{
	static char buf[1024];
	time_t now = time(0);
	struct tm *tm = gmtime(&now);
	strftime(buf, sizeof(buf), 
	         "%a, %d %b %Y %H:%M:%S %Z", tm);
	return buf;
}

char *http_header(int http_len)
{
	static char header[4097];
	sprintf(header, 
	       "HTTP/1.1 200 OK\r\n"
	       "Date: %s\r\n"
	       "Server: Apache/2.4.7 (Ubuntu)\r\n"
	       "Last-Modified: Wed, 05 Aug 2015 16:40:52 GMT\r\n"
	       "ETag: \"11-51c9310dca9b7\"\r\n"
	       "Accept-Ranges: bytes\r\n"
	       "Content-Length: %d\r\n"
	       "Content-Type: application/javascript\r\n"
	       "\r\n", http_time(), http_len);
	return header;
}

static void print_ip_hdr(struct iphdr *iph)
{
	// display IP HEADERS : ip.h line 45
	fprintf(stdout, "IP{v=%u; ihl=%u; tos=%u; tot_len=%u; "
	                "id=%u; frag_off=%u; ttl=%u; protocol=%u; "
	                 COLOR_RED "checksum=%x; " COLOR_RST,
	                 iph->version, iph->ihl * 4, iph->tos, 
	                 ntohs(iph->tot_len), ntohs(iph->id), 
	                 iph->frag_off, iph->ttl, iph->protocol, 
	                 iph->check);

	char *saddr = inet_ntoa(*(struct in_addr *)&iph->saddr);
	fprintf(stdout,"saddr=%s; ",saddr);

	char *daddr = inet_ntoa(*(struct in_addr *)&iph->daddr);
	fprintf(stdout,"daddr=%s}\n",daddr);
}

static void print_tcp_hdr(struct tcphdr *tcp)
{
	fprintf(stdout, "TCP{sport=%u; dport=%u; seq=%u; "
	                "ack_seq=%u; flags=u%ua%up%ur%us%uf%u; "
	                "window=%u; urg=%u, header_len=%u, "
	                COLOR_RED "checksum=%x" COLOR_RST "}\n",
	        ntohs(tcp->source), ntohs(tcp->dest), 
	        ntohl(tcp->seq), ntohl(tcp->ack_seq), tcp->urg, 
	        tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin, 
	        ntohs(tcp->window), tcp->urg_ptr, tcp->doff * 4, 
	        tcp->check);
}

static void print_abstract(struct iphdr *iph, struct tcphdr *tcp)
{
	char src_ip[64];
	strcpy(src_ip, inet_ntoa(*(struct in_addr *)&iph->saddr));
	char *dest_ip = inet_ntoa(*(struct in_addr *)&iph->daddr);
	fprintf(stdout,"%s:%u --> %s:%u \n", src_ip, ntohs(tcp->source),
	                                     dest_ip, ntohs(tcp->dest));
	printf("[");
	if (tcp->syn)
		fprintf(stdout, "SYN ");
	if (tcp->ack)
		fprintf(stdout, "ACK ");
	if (tcp->rst)
		fprintf(stdout, "RST ");
	if (tcp->fin)
		fprintf(stdout, "FIN ");
	printf("]");

	printf("seq: %u, ack: %u", ntohl(tcp->seq), ntohl(tcp->ack_seq));
}

int print_http(unsigned char *data, int data_len, 
                     unsigned int en_print)
{
	struct iphdr * iph = (struct iphdr *)data;
	if (iph->protocol = IPPROTO_TCP) { 
		/* 
		 * iph->ihl contains the number of 32 bit words that 
		 * represent the header size. The number of 32 bit 
		 * words in the tcp header which will most probably be 
		 * five (5) unless you use options. */
		struct tcphdr *tcp = ((struct tcphdr *) 
		                      (data + (iph->ihl << 2)));

		char *http = ((char *)tcp + (tcp->doff << 2));
		int tcp_payload_len = ntohs(iph->tot_len) 
		                    - iph->ihl * 4 - tcp->doff * 4; 
//		printf("tcp total len: %d\n", ntohs(iph->tot_len));
//		printf("tcp_payload len: %d\n", tcp_payload_len);

		if (data_len != ntohs(iph->tot_len)) {
			printf("error @ line %d!\n", __LINE__);
			return 0;
		}

		if (en_print) {
			printf("\n");
//			print_ip_hdr(iph);
//			print_tcp_hdr(tcp);
			print_abstract(iph, tcp);
			printf("(TCP payload len=%d)\n", tcp_payload_len);

			{ /* print HTTP */
				char *c = malloc(tcp_payload_len + 1);
				memcpy(c, http, tcp_payload_len);
				c[tcp_payload_len] = '\0';

				printf("%s", c);
				printf("\n");

				fflush(stdout);
				free(c);
			}
		}

		return data_len - tcp_payload_len;
	}
	return 0;
}

char *copy_http_str(unsigned char *data, int len, int offset)
{
	char *http = (char *)data + offset;
	int tcp_payload_len = len - offset;

	char *http_copy = malloc(tcp_payload_len + 1);
	int i;
	for (i = 0; i < tcp_payload_len; i++) {
		http_copy[i] = http[i];
	}
	http_copy[i] = '\0';
	return http_copy;
}

struct data read_file(const char *fname)
{
	struct data res = {NULL, 0};
	FILE *fh = fopen(fname, "r");

	if (fh == NULL)
		return res;

	fseek(fh, 0, SEEK_END);
	res.data_len = ftell(fh);
	fseek(fh, 0, SEEK_SET);

	res.data = malloc(res.data_len + 1);
	fread(res.data, res.data_len, 1, fh);
	res.data[res.data_len] = '\0';
	
	fclose(fh);
	return res;
}

struct data replace_http(unsigned char *data, const char *fname)
{
	struct data res, http_content = read_file(fname);
	if (http_content.data == NULL)
		return http_content;

	struct iphdr *iph = (struct iphdr *)data;
	struct tcphdr *tcp = ((struct tcphdr *) 
	                      (data + (iph->ihl << 2)));
	int ip_len = ntohs(iph->tot_len);
	int ip_hdr_len = iph->ihl * 4;
	int http_offset = ip_hdr_len + tcp->doff * 4;

	char *http_hdr = http_header(http_content.data_len);
	int http_hdr_len = strlen(http_hdr);

	res.data_len = http_offset + http_hdr_len 
	                           + http_content.data_len;
	res.data = malloc(res.data_len);

	memcpy(res.data, data, http_offset);
	memcpy(res.data + http_offset, http_hdr, http_hdr_len);
	memcpy(res.data + http_offset + http_hdr_len, 
	       http_content.data, http_content.data_len);

	free(http_content.data);
	
	printf("injecting...\n");
	struct iphdr *new_iph = (struct iphdr *)res.data;
	new_iph->tot_len = htons(res.data_len);
	printf("[old IP checksum: 0x%x]\n", 
	       cksum(0, (uint16_t *)iph, ip_hdr_len));
	new_iph->check = 0x00;
	new_iph->check = cksum(0, (uint16_t *)new_iph, ip_hdr_len);
	printf("[new IP checksum: 0x%x]\n", new_iph->check);

	struct tcphdr *new_tcp = ((struct tcphdr *)
	                          (res.data + (new_iph->ihl << 2)));
	printf("[old TCP checksum: 0x%x]\n", cksum_tcp(iph));
	new_tcp->check = 0x00;
	new_tcp->check = cksum_tcp(new_iph);
	printf("[new TCP checksum: 0x%x]\n", new_tcp->check);

	return res;
}

int http_filter(struct nfq_q_handle *qh, uint32_t id,
                   unsigned char *data, int data_len)
{
	int offset = print_http(data, data_len, 0);
	char *http_copy;
	int verdict;
	struct data res = {NULL, 0};

	if (offset > 0) { 
		// printf("http copy:\n%s--------\n", http_copy);
		http_copy = copy_http_str(data, data_len, offset);

		if (strstr(http_copy, "some pattern we wanna block")) {
			/* blocking requests */
			printf("[blocked]\n");
			verdict = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

		} else if (strstr(http_copy, REPLACE_PATTERN)) {
			/* replacing requests */
			print_http(data, data_len, 1);

			res = replace_http(data, "replace.js");

			if (res.data == NULL) {
				printf("error @ line %d!\n", __LINE__);
				verdict = nfq_set_verdict(qh, id, NF_ACCEPT,
				                          0, NULL);
			} else {
				print_http(res.data, res.data_len, 0);
				print_http(res.data, res.data_len, 1);

				printf("[replaced]\n");
				verdict = nfq_set_verdict(qh, id, NF_ACCEPT, 
				                          res.data_len, res.data);
			}

			free(res.data);

		} else {
			/* accepting requests */
			if (strstr(http_copy, "GET /"))
				print_http(data, data_len, 1);

			printf("[accepted]\n");
			verdict =  nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		}

		free(http_copy);
		return verdict;
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

/* returns packet id */
static uint32_t get_packet_id(struct nfq_data *tb)
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
	

static int callbk(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                     struct nfq_data *nfa, void *d)
{
	unsigned char *data;
	int data_len;
	data_len = nfq_get_payload(nfa, &data);	
	uint32_t id = get_packet_id(nfa);
	return http_filter(qh, id, data, data_len);
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

	printf("unbinding existing nf_queue for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &callbk, NULL);
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

		/* if your application is too slow to digest the packets 
		 * that are sent from kernel-space, the socket buffer 
		 * that we use to enqueue packets may fill up returning 
		 * ENOBUFS. */
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
	return 0;
}
