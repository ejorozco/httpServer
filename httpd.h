#ifndef HTTPD_H
#define HTTPD_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <string>
#include <map>

#define TIMEOUTAMOUNT 5	//Timeout of 5 sec if client doesnt send
#define MAXSTRINGLENGTH 128
#define BUFSIZE 512
#define MAXPENDING 5 // Maximum outstanding connection requests
#define MAXBUFFER 8192

using namespace std;

struct HTTPRequest{
    string method;
    string uri;
    string version;
    map<string, string> keyPairs;
};
struct HTTPResponse{
    string startLine;
    string server;
    string lastModified;
    string contentType;
    int contentLength;
};
struct ThreadArgs {
  // Structure of arguments to pass to client thread
  int clntSock; // Socket descriptor for client,
};

// This is the server fucntion for project 1
void start_httpd(unsigned short port, string doc_root);

// Create, bind, and listen a new TCP server socket, returns server socket
int create_Server(unsigned short port);

// Accept a new TCP connection on a server socket
int AcceptTCPConnection(int servSock);

// Handle new TCP client
void HandleTCPClient(int clntSocket);

//Recievs client bytes until CRFL is found
ssize_t recvTillCRLF(int clntSocket, char* buffer, ssize_t buf_size);

//Splits up the header string values
struct HTTPRequest parseRequest(char *buffer);

//Checks to see if the file doc_root is valid
string getValidPath(string uri);

//Check to see if file can open and readable, if so read content
string getContent(string filePath);

//Get file information
struct HTTPResponse getFileInfo(string filePath);

//build the response message
string buildResponse(struct HTTPResponse, string fileContent);

//Sends the data to client
void sendRequest(int clntSocket, char* buffer, ssize_t len);

// Main program of a thread
void *ThreadMain(void *arg);

//Checks HTP access for clients
void checkHTTPAccess();

#endif // HTTPD_H
