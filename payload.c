#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

#define BUF_SIZE 500
#define HOST "localhost"
#define PORT "5151"

int sfd;
extern decrypt_and_call(void *);

void third_stage(void) __attribute__((aligned(0x1000)));
void second_stage(void) __attribute__((aligned(0x1000)));

void third_stage(void)
{
  size_t len;
  char buf[BUF_SIZE];
  ssize_t n;

  n = write(sfd, "GET / HTTP/1.0\r\n\r\n", 18);
  if (n != 18) {
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

void second_stage(void)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int s, j;

  /* Obtain address(es) matching host/port */

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
  hints.ai_flags = 0;
  hints.ai_protocol = 0;          /* Any protocol */

  s = getaddrinfo(HOST, PORT, &hints, &result);
  if (s != 0) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
      exit(EXIT_FAILURE);
  }

  /* getaddrinfo() returns a list of address structures.
     Try each address until we successfully connect(2).
     If socket(2) (or connect(2)) fails, we (close the socket
     and) try the next address. */

  for (rp = result; rp != NULL; rp = rp->ai_next) {
      sfd = socket(rp->ai_family, rp->ai_socktype,
	rp->ai_protocol);
      if (sfd == -1)
          continue;

      if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
          break;                  /* Success */

      close(sfd);
  }

  if (rp == NULL) {               /* No address succeeded */
      fprintf(stderr, "Could not connect\n");
      exit(EXIT_FAILURE);
  }

  freeaddrinfo(result);           /* No longer needed */
  decrypt_and_call(third_stage);
  return;
}

int main(void)
{
  decrypt_and_call(second_stage);
  return 0;
}
