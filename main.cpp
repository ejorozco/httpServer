#include <string.h>     /* Strings */
#include <stdio.h>      /* printf, scanf, NULL */
#include <stdlib.h>     /* malloc, free, rand */
#include <unistd.h>     /* for close() */
#include <sys/types.h>	/* pthread  ssize_t */
#include <sys/socket.h> /* sockets, recv() and send()*/
#include <arpa/inet.h>	/* inet_pton  */
#include <netdb.h>
#include <iostream>
#include <errno.h>
#include <limits.h>
#include "httpd.h"
/*
 * ./httpd 8080 /var/lib/www/htdocs
 * program port doc_root
 *
 * Create a TCp server socket, arrange so that thread is spawned when a new
 * conections comes in
 *
 * Two key operations must be performed to build web server
 * 1-seperating out apllication level messages by determineing when one message starts and another ends
 * 2-processing individual messages to understand their meaning. Must seperate steps
 *
 * request path from client to server, reads client socket which produces HTTPMessage
 * Parse HTTPMessage into an HTTPRequest
 *
 * Reposnse side: Server to client, initialize and fill HTTPResponse struct, then raming code will
 * convert into HTTPMessage, then send socket to client
 *
 */
/*
	main.cpp is our client
*/
using namespace std;

void usage(char * argv0)
{
	cerr << "Usage: " << argv0 << " listen_port docroot_dir" << endl;
}
int main(int argc, char *argv[])
{
	//Check for 3 user inputs
	if (argc != 3) {
		usage(argv[0]);
		return 1;
	}
	//Changing strings to a long int type and grab the doc_root
	long int port = strtol(argv[1], NULL, 10);
	string doc_root = argv[2];

	//Check User input for errors
	if (errno == EINVAL || errno == ERANGE) {
		usage(argv[0]);
		return 2;
	}
	if (port <= 0 || port > USHRT_MAX) {
		cerr << "Invalid port: " << port << endl;
		return 3;
	}

	// Begin httpd process
	start_httpd(port, doc_root);

	return 0;
}
