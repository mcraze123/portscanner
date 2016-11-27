/*
	TCP port scanner
	Written and Maintained by Michael Craze
	
TODO: 
	make it use threads..
	make it check UDP
	make it scan ip address ranges for public use

	ip address ranges for private use:
	Class	Networks
	A	10.0.0.0 through 10.255.255.255
	B	172.16.0.0 through 172.31.0.0
	C	192.168.0.0 through 192.168.255.0
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

typedef struct{
	char *ip;
	int sport;
	int eport;
} Host;

void usage(char *a){
	fprintf(stderr,"Invalid invocation of %s\n",a);
	printf("Usage: %s <ip address> <begin port> <end port>\n",a);
	exit(1);
}

/* Main programs starts*/
int main(int argc, char **argv){
	int sd;
	int port;
	int rval;
	int checkip;
	int pcount = 0;

	/* going to use these ints to iterate 
	   through public IP classes to find all
	   open servers to automate attacks.
	*/
	/* 
	   int A,B,C,D; 
	*/
	
	/*
		char *message="shell";
	*/
	/* 
		char response[1024]; 
	*/
	
	Host *h;
	struct hostent *hostaddr;
	struct sockaddr_in servaddr;

	if (argc < 4 ){
		usage(argv[0]);
	}
	
	h = (Host *)malloc(sizeof(Host));
	if(h == NULL){ 
		fprintf(stderr,"couldn't allocate memory for %s\n",argv[1]);
		exit(1); 
	}
	if(sscanf(argv[1],"%d",&checkip) != 1){
		fprintf(stderr,"%s was not a valid ip address\n",argv[1]);
		usage(argv[0]);
	}
	if(sscanf(argv[2],"%d",&h->sport) != 1){
		fprintf(stderr,"%s was not a valid integer\n",argv[2]);
		usage(argv[0]);
	}
	if(sscanf(argv[3],"%d",&h->eport) != 1){
		fprintf(stderr,"%s was not a valid integer\n",argv[3]);
		usage(argv[0]);
	}
	
	h->ip = strdup(argv[1]);
	printf("Scanning host: %s on ports %d thru %d\n", h->ip,h->sport,h->eport);

	
	/* Start scanning ports */
	for (port = h->sport; port <= h->eport; port++){
		/* creating the tcp socket */
		sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); 
		if (sd == -1){
			perror("Socket()\n");
			return (errno);
		}
		memset( &servaddr, 0, sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_port = htons(port);
		hostaddr = gethostbyname(h->ip);

		memcpy(&servaddr.sin_addr, hostaddr->h_addr, hostaddr->h_length);

		/* below connects to the specified ip in hostaddr */
		rval = connect(sd, (struct sockaddr *) &servaddr, sizeof(servaddr));
		
		if(rval != -1){
			printf("  %-7d %-10s\n",port,"is open");
			pcount++;
		}
		close(sd);
	}
	if(pcount == 0){
		printf("No ports in range %d-%d are open on host %s\n",h->sport,h->eport,h->ip);
	}
	else{
		printf("%d ports in range %d-%d are open on host %s\n",pcount,h->sport,h->eport,h->ip);
	}

	free(h);
	return 0;
}

