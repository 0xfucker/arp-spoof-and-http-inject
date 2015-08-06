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

#include <string.h>
#include <time.h>

struct my_data {
	unsigned char *data;
	int data_len;
};

char *http_time() 
{
	static char buf[1024];
	time_t now = time(0);
	struct tm *tm = gmtime(&now);
	strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %Z", tm);
	return buf;
}

char *http_header(int http_len)
{
	static char header[4097];
	sprintf(header, 
	       "HTTP/1.1 200 OK\r\n"
	       "Date: %s\r\n"
	       "Server: Apache/2.4.7 (Ubuntu)\r\n"
	       "Content-Length: %d\r\n"
	       "Content-Type: application/javascript\r\n"
	       "\r\n", http_time(), http_len);
	return header;
}

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
		// The number of 32 bit words in the tcp header which will most probably be 
		// five (5) unless you use options.
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
		printf("\n~~END~~\n");

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

struct my_data my_read_file(const char *fname)
{
	struct my_data res = {NULL, 0};
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

struct my_data my_replace_http(unsigned char *data, const char *fname)
{
	struct my_data res, http_content = my_read_file(fname);
	if (http_content.data == NULL)
		return http_content;

	struct iphdr *iph = (struct iphdr *)data;
	struct tcphdr *tcp = ((struct tcphdr *) (data + (iph->ihl << 2)));
	int ip_len = ntohs(iph->tot_len);
	int ip_hdr_len = iph->ihl * 4;
	int http_offset = ip_hdr_len + tcp->doff * 4;

	char *http_hdr = http_header(http_content.data_len);
	int http_hdr_len = strlen(http_hdr);

	res.data_len = http_offset + http_hdr_len + http_content.data_len;
	res.data = malloc(res.data_len);

	memcpy(res.data, data, http_offset);
	memcpy(res.data + http_offset, http_hdr, http_hdr_len);
	memcpy(res.data + http_offset + http_hdr_len, 
	       http_content.data, http_content.data_len);

	free(http_content.data);
	
	struct iphdr *new_iph = (struct iphdr *)res.data;
	new_iph->tot_len = htons(res.data_len);
	new_iph->check = 0xdeaf;

	struct tcphdr *new_tcp = ((struct tcphdr *)(res.data + (new_iph->ihl << 2)));
	new_tcp->check = 0xbad1;

	return res;
}

int my_http_filter(struct nfq_q_handle *qh, uint32_t id,
                   unsigned char *data, int data_len)
{
	int offset = my_print_non_0_http(data, data_len);
	char *http_copy;
	int verdict;

	if (offset > 0) { 
		// printf("http copy:\n%s--------\n", http_copy);
		http_copy = my_http_copy(data, data_len, offset);
	
		/* block all .png file requests */
		if (strstr(http_copy, ".png HTTP/1.1")) {
			printf("[blocked]\n");
			verdict = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		/* modify all .css file requests */
		} else if (strstr(http_copy, "application/javascript")) {
			struct my_data res = {NULL, 0};
			res = my_replace_http(data, "replace.js");
			if (res.data == NULL) {
				printf("[modification failed]\n");
				verdict =  nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
			} else {
#if 1
				printf("[modifying]\n");
				my_print_non_0_http(res.data, res.data_len);
				printf("[modified]\n");
				verdict = nfq_set_verdict(qh, id, NF_ACCEPT, 
				                          res.data_len, res.data);
#else
				printf("[accepted]\n");
				verdict =  nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
#endif
				free(res.data);
			}
		/* accept other requests */
		} else {
			printf("[accepted]\n");
			verdict =  nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		}

		free(http_copy);
		return verdict;
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
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
	return my_http_filter(qh, id, data, data_len);
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

int _main()
{
//	struct my_data res;
//	res = my_read_file("replace.js");
//
//	if (res.data == NULL) {
//		printf("NULL!\n");
//	} else {
//		printf("%s", res.data);
//	}
//
//	free(res.data);

	printf("%s\n", http_header(123));
	return 0;
}
