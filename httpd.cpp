#include <iostream>
#include <stdio.h>      /* for printf() and fprintf() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h> /* for socket(), bind(), and connect() */
#include <netinet/in.h>
#include <netdb.h>			/* *getaddrinfo */
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <time.h>		/* time_t, struct tm, time, gmtime */
#include <unistd.h>     /* close() */
#include <errno.h>      /* Err numbers */
#include <dirent.h>		/* S_IFDIR */
#include <fstream>
#include <pthread.h>
#include "httpd.h"
#include <sstream>
#include <algorithm>	/* replace */
#include <iterator>
#include <vector>
#include <limits.h> /* PATH_MAX */
#include <iterator>

using namespace std;

//autograder
//client ~cs124w/public/project1/bin/cse124HttpdTester localhost 2500
//server  ./httpd 2059 ~cs124w/public/project1/htdocs

//Global variables to use for all functions
string docRoot;								//doc_root
int statusCode = 0;
int statusCode403 = 0;
std::vector<int> errorCodes;
std::map<string, string> allowDenyPairs;
string clntAdrName;

int create_Server(unsigned short port){
	int servSock = 0;
	struct sockaddr_in servAddr; /* Local address  */
	servSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (servSock < 0)
		cerr << "socket() failed" << endl;

	memset(&servAddr, 0, sizeof(servAddr));         // Zero out structure
	servAddr.sin_family = AF_INET;                  // IPv4 address family
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);   // Any incoming interface
	servAddr.sin_port = htons(port);                // Local port

	if (bind(servSock, (struct sockaddr*) &servAddr, sizeof(servAddr)) < 0)
		cerr << "bind() failed" << endl;

	if (listen(servSock, MAXPENDING) < 0)
		cerr << "listen() failed" << endl;

	return servSock;
}
int AcceptTCPConnection(int servSock) {
    struct sockaddr_in clntAddr; // Client address
    // Set length of client address structure (in-out parameter)
    socklen_t clntAddrLen = sizeof(clntAddr);

    // Wait for a client to connect
    int clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
    if (clntSock < 0)
        cerr << "accept() failed" << endl;

    // clntSock is connected to a client!
	cout << "Handling to: " << clntAddr.sin_addr.s_addr << endl;
	cout << "Handling from: " <<  inet_ntoa(clntAddr.sin_addr) << endl;

	string client_ip (inet_ntoa(clntAddr.sin_addr));

	char clntName[INET_ADDRSTRLEN]; // String to contain client address
   	if (inet_ntop(AF_INET, &clntAddr.sin_addr.s_addr, clntName,
											sizeof(clntName)) != NULL)
		printf("Handling client %s/%d\n", clntName, ntohs(clntAddr.sin_port));
   	else
	 	puts("Unable to get client address");

		/*
		struct addrinfo hint, *addr_in;
		char buf[BUFSIZE];
		string trueIP;

		memset(&hint, 0, sizeof hint);
		hint.ai_family = AF_INET;
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_protocol = IPPROTO_TCP;

		if (getaddrinfo(IP.c_str(), NULL, &hint, &addr_in) == 0) {
	  	inet_ntop(AF_INET, &( (struct sockaddr_in *) addr_in->ai_addr)->sin_addr,
																buf, sizeof(buf));
	    trueIP = string(buf);
		*/
	//string name(clntName);
	string string(clntName);


	clntAdrName = string;
	cout << clntAdrName << endl;

  return clntSock;
}
ssize_t recvTillCRLF(int clntSocket, char* buffer, ssize_t buf_size) {
    ssize_t recv_cnt = 0;
    printf("Prepare to recv.\n");
    while(true) {
        ssize_t numBytesRcvd = recv(clntSocket, buffer + recv_cnt, buf_size - recv_cnt, 0);
        if(numBytesRcvd <= 0)
						break;
            //cerr << "recv() failed miserably" << endl;
				recv_cnt += numBytesRcvd;
        // return when CRFL return line feed is found, strsr finds CRFL
        char *pos = strstr(buffer, "\r\n\r\n");
        if(pos != NULL)
            return recv_cnt;
    }
    return -1;
}
void sendRequest(int clntSocket, char *buffer, ssize_t len) {
  ssize_t sent_cnt = 0;
  while (sent_cnt < len) {
    ssize_t numBytesSent = send(clntSocket, buffer + sent_cnt, len - sent_cnt, 0);
    printf("Sent %d bytes.\n", (int)numBytesSent);
    if (numBytesSent < 0)
      cerr << "send() failed" << endl;
    else if (numBytesSent == 0)
      cerr << "send() failed to send anything"<< endl;

		sent_cnt += numBytesSent;
  }
}
void HandleTCPClient(int clntSocket) {
	while(true){
		statusCode = 0;
		statusCode403 = 0;
  		errorCodes.clear();
		char buffer[BUFSIZE];
		//memset(&buffer, 0, sizeof(buffer));

	  // Receive message from client
	  ssize_t numBytesRcvd = recvTillCRLF(clntSocket, buffer, BUFSIZE);
		//cout << "Number of read bytes: " << numBytesRcvd << endl;
	  if(numBytesRcvd < 0)
		{
	  		cout << "recv() failed" << endl;
				return;
		}
	  // Replace \r with ' '
		for( unsigned int i = 0 ; i < strlen(buffer) ; i ++ )
			if(buffer[i] == '\r') buffer[i] = ' ';

		//Struct to hold header key pair values
		//Parse request and save data to struct
		struct HTTPRequest request = parseRequest(buffer);

		cout << clntAdrName << endl;

		bool endPiplining = 0;
		for(std::map<string,string>::iterator it=request.keyPairs.begin();
											it !=request.keyPairs.end();it++)
		{
			//cout << it->first << "," << it->second <<endl;
			if(it->first == "Connection:" && it->second == "close " ){
				endPiplining = 1;
				//cout << "here" << endl;
			}
		}

		//establich socket timeout
		struct timeval timeout;
		timeout.tv_sec = TIMEOUTAMOUNT;
		timeout.tv_usec = 0;
		int fail = setsockopt(clntSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
		if(fail == -1)
			cerr << "setsockopt failed" << endl;

		//Check to see if the file is good and return ABSOLUTE PATH
		//Else 404 code is sent, does not exist
		string filePath = getValidPath(request.uri);
		cout << filePath << endl;


		//Check to see if the file is accessable, 403 code if cannot read
		string fileContent = getContent(filePath);



		//Will hold file content
		struct HTTPResponse response;



		//realpath found, able to open, and able to read
		if(filePath != "" || filePath != "")
			response = getFileInfo(filePath);  //read content and save to stuct

		//for (std::vector<int>::const_iterator i = errorCodes.begin(); i != errorCodes.end(); ++i)
			//std::cout << *i << ' ';

			//EXTENSION 2 Http access
			//checkHTTPAccess();

		//buildResponse
		string str = buildResponse(response, fileContent);
		char *a = new char[str.size()];
		//a[str.size()] = 0;
		memcpy(a,str.c_str(),str.size());



		sendRequest(clntSocket, a, str.size());

		delete [] a;

		//statusCode = 0; //Proper Code sent so reset for next loop iteration
		if(endPiplining == 1)
		{
			close(clntSocket);
			break;
		}
		cout << "Done\n\n";
	}
	//cout << "Done with HandleTCPClient" << endl;q
	//close(clntSocket);
}
string buildResponse(struct HTTPResponse response, string fileContent){
	string CRLF = "\r\n";
	stringstream ss;
	//if(statusCode403 == 403)
	//	statusCode = statusCode403;
	//else
	statusCode = errorCodes.front();
	switch(statusCode)
	{
		case 200: //Success
			ss << response.startLine << CRLF;
			ss << "Server: " << response.server << CRLF;
			ss << response.lastModified << CRLF;
			ss << "Content-Type: " << response.contentType << CRLF;
			ss << "Content-Length: " << response.contentLength << CRLF << CRLF;
			ss << fileContent;
			break;
		case 400: //Client error, malformed/invalid request, no understand
			ss << "HTTP/1.1" << " 400 " << "Client Error" << CRLF;
			ss << "Server: " << "TritonHTTP" << CRLF << CRLF;
			break;
		case 403: //The request not served, client wasn’t allowed access to content
			ss << "HTTP/1.1" << " 403 " << "Forbidden" << CRLF;
			ss << "Server: " << "TritonHTTP" << CRLF << CRLF;
			break;
		case 404: //The requested content wasn’t there
			ss << "HTTP/1.1" << " 404 " << "Not Found" << CRLF;
			ss << "Server: " << "TritonHTTP" << CRLF << CRLF;
			break;
		case 500: //Server error
			break;
	}
	return ss.str();
}
struct HTTPRequest parseRequest(char *buffer){

	struct HTTPRequest request;

	char *temp = buffer;
	string method(strtok(temp, " "));
	if(method != "GET")
		//statusCode = 400;
		errorCodes.push_back(400);

	string uri(strtok(NULL, " "));
	if(uri[0] != '/')
		//statusCode = 400;
		errorCodes.push_back(400);

	string version(strtok(NULL, "\n"));  //has extra whitespace
	if(version != "HTTP/1.1 ")
		//statusCode = 400;
		errorCodes.push_back(400);

	request.method = method;
	request.uri = uri;
	request.version = version;

	//Read and save all key pair values
	while(true){
		char *readKey = strtok(NULL," ");
		char *readValue = strtok(NULL,"\n"); //has extra whitespace
		if(readKey == NULL || readValue == NULL)
			break;
		string key(readKey);
		string value(readValue);
		request.keyPairs[key] = value;
	}
	//cout << "done parsing saving structs" << endl;
	return request;
}
string getValidPath(string uri){
	printf("Getting the valid Path\n");
	string url = docRoot + uri;
	char buf[PATH_MAX + 1];
  char *res = realpath(url.c_str(), buf);
	string falsePath = "";
  if (res){
		string realPath(buf); //file found
		return realPath;
	} else if(errno == EACCES){
		//statusCode = 403;
		//Read or search permission was denied for a component of the path prefix
		errorCodes.push_back(403);
		return falsePath;
	}
	else if(errno == ENOENT){
		//statusCode = 404; //Not Found
		errorCodes.push_back(404);
		return falsePath;
	}
	else
	{
		//statusCode = 404; //Not Found
		errorCodes.push_back(404);
		return falsePath;
	}

}
string getContent(string realPath){
	ifstream ifs(realPath.c_str());
	if(ifs.good())
	{
		cout << "File is found" << endl;

		struct stat fileStat;
		// Get UID and GID of the file.
		if (stat(realPath.c_str(), &fileStat) < 0)
			cerr << "Cannot get permission obatained from the file" << endl;
		if( fileStat.st_mode & S_IFDIR )  {// S_ISDIR() doesn't exist on my windows
	    //printf( "%s is not a directory\n", realPath );
			errorCodes.push_back(403);
				ifs.close();
			return "";
		}
		// Check whether the file is world readable.
		if (!(fileStat.st_mode & S_IROTH)) {
			ifs.close();
			cout << "file is not world readable" << endl;
			//statusCode = 403;
			errorCodes.push_back(403);
				ifs.close();
			return "";
		}

		//File is good so lets get the file content
		string fileContent;
		ifs.seekg(0, ifstream::end);	//Move pointer to end of stream
		size_t size = ifs.tellg();		//Get index to set size
		ifs.seekg(0, ifstream::beg);	//move pointer to begining

		char* buf = new char[size];		//Set up char buffer for writing
		memset(buf, '\0', size);		//set all to null

		ifs.read(buf, size);	//Save file contents

		fileContent.append(buf, size);
		//statusCode = 200;
		errorCodes.push_back(200);

		cout << "DONE GETTING CONTENT" << endl;
		delete [] buf;
		ifs.close();
		return fileContent;

	}else{
		cout << "No file found" << endl;
		ifs.close();
		//statusCode = 404;
		errorCodes.push_back(404);
			ifs.close();
		return "";
	}
}
struct HTTPResponse getFileInfo(string filePath){
	//Create Response Body
	struct HTTPResponse response;

	//Holds file stats obtained using realpath
 	struct stat fileStat;
	if (stat(filePath.c_str(), &fileStat) < 0)
    	cerr << "No permission obatained from the file" << endl;
 	if(stat(filePath.c_str(), &fileStat) == 0)
 	{
		//Get the file info and save to struct
		response.startLine = "HTTP/1.1 200 OK";
		response.server = "TritonHTTP";

		//Get Last modified
		char buffer[BUFSIZE];
    	struct tm *gmt;
    	gmt = gmtime(&fileStat.st_mtime);
    	strftime(buffer, BUFSIZE, "Last-Modified: %a, %d %b %Y %X %Z", gmt);
		response.lastModified = string(buffer);

		string type = filePath.substr(filePath.find('.'));
		if(type == ".jpg") response.contentType = "image/jpeg";
		else if(type == ".png") response.contentType = "image/png";
		else if(type == ".html") response.contentType = "text/html";
		response.contentLength = (int)fileStat.st_size;
 	}
	return response;
}
void *ThreadMain(void *threadArgs) {
  // Guarantees that thread resources are deallocated upon return
  pthread_detach(pthread_self());

  // Extract socket file descriptor from argument
  int clntSock = ((struct ThreadArgs *) threadArgs)->clntSock;
  free(threadArgs); // Deallocate memory for argument

  HandleTCPClient(clntSock);

  return (NULL);
}
string getIP(string IP){
	//Determine whether a IP is number or a string address
	/*char *temp = new char[IP.size()];
	temp[IP.size()] = 0;
	memcpy(temp,IP.c_str(),IP.size());

	for( unsigned int i = 0 ; i < strlen(temp) ; i ++ ){

		//String is already ion IP form
		if( !((temp[i] >= '0' &&  temp[i] <= '9') || temp[i] == '.' || temp[i] == '/'))
		{
			return IP;
		}
	}*/
	//IP is in word form
	//cout << "IP in word form" << endl;
	string trueIP;
	struct addrinfo hint, *addr_in;
	char buf[BUFSIZE];

	memset(&hint, 0, sizeof hint);
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;

	if (getaddrinfo(IP.c_str(), NULL, &hint, &addr_in) == 0) {
  	inet_ntop(AF_INET, &( (struct sockaddr_in *) addr_in->ai_addr)->sin_addr,
															buf, sizeof(buf));
    trueIP = string(buf);
	cout << "++++++" << trueIP << endl;
		return trueIP;
  }
  else
  	cout << "HI"<< IP << endl;
  	return IP;
		//delete [] buf;
		//delete [] temp;

}
void checkHTTPAccess(){
	//Get realpath
	string url = docRoot + ".htaccess";
	//string url = ".htaccess";
	char buf[PATH_MAX + 1];
	char *res = realpath(url.c_str(), buf);
	if (res){
		cout << ".htaccess found" << endl;
	} else{
		return;
	}

	string realPath(buf);		// Holds abs path
	string access, from, IP;	// variables for reading .htaccess
	ifstream ifs;
	ifs.open (realPath.c_str());

	//ifs.open(".htaccess", ifstream::in);
	if ( !ifs.is_open() )
	{
	  cout << "htaccess not found" << endl;
	  	ifs.close();
		return;
    }


	while( ifs.good() )
	{
	  ifs >> access >> from >> IP;
	  //allowDenyPairs[getIP(IP)] = access;
	  allowDenyPairs[getIP(IP)] = access;
	  //cout << "XXXXX" << access << " : " << IP << endl;
	}



	for(std::map<string,string>::iterator it=allowDenyPairs.begin();
										it !=allowDenyPairs.end();it++)
	{
		cout << it->first << "-" << it->second << endl;
		string ipAddr;
		int mask = 0;
		if (it->first.find('/') != string::npos) {
        	ipAddr = it->first.substr(0, it->first.find('/'));
        	mask = atoi(   (it->first.substr(it->first.find('/') +1 )).c_str()  );
			//if("0.0.0.0/0" == ipAddr)
				//if(it->second == "allow")
					//return;
				//else if((it->second == "deny"))
					//errorCodes.push_back(403);
					cout << "mask: " << mask << endl;
        }
		else {
            ipAddr = it->first;
        }

		string tempClntAdrName = clntAdrName;
		int amountIPCheck = mask/8;

  		replace( ipAddr.begin(), ipAddr.end(), '.', ' ' );
		replace( tempClntAdrName.begin(), tempClntAdrName.end(), '.', ' ' );


		vector<string> ipTokens;
		vector<string> clntTokens;

		string word;
		std::istringstream iss(tempClntAdrName);
		while(iss >> word)
		{
			cout << word << endl;
			ipTokens.push_back(word);
		}

		cout << "DONEEEE" << endl;

		std::istringstream isss(ipAddr);
		while(isss >> word)
		{
			cout << word << endl;
			clntTokens.push_back(word);
			//statusCode403 = 403;
		}


		int flag = 0;
		for(int i = 0; i < amountIPCheck; i++)
		{
			//cout << ipTokens[i] << " : " << clntTokens[i] << endl;
			if(ipTokens[i] == clntTokens[i])
				continue;
			else
				flag = 1; //not the same addresses

		}

		if(flag == 0)
			continue;

		else if (it->second == "allow")
			continue;
		else if(it->second == "deny")
		{
			//errorCodes.push_back(403);
			cout << "NOT ALLOWED" << endl;
			//statusCode403 = 403;
			errorCodes.push_back(403);


		}

	}
	ifs.close();

}
void start_httpd(unsigned short port, string doc_root){
	cerr << "Starting server (port: " << port <<
			", doc_root: " << doc_root << ")" << endl;
	/* Begin Server setup */
  	docRoot = doc_root; /* Make doc_root global */
  	int servSock = create_Server(port);

	for (;;)
	{
    	//Socket descriptor for client
		int clntSock = AcceptTCPConnection(servSock);


		HandleTCPClient(clntSock);
		//cout << "start new" << endl;
		/*
		// Create separate memory for client argument
    	struct ThreadArgs *threadArgs = (struct ThreadArgs *) malloc(
        sizeof(struct ThreadArgs));
    	if (threadArgs == NULL)
      		cerr << "malloc() failed"<< endl;

			threadArgs->clntSock = clntSock;

	    // Create client thread
	    pthread_t threadID;
	    int returnValue = pthread_create(&threadID, NULL, ThreadMain, threadArgs);
	    if (returnValue != 0)
	      cerr << "pthread_create() failed: " << strerror(returnValue) << endl;
	    printf("with thread %ld\n", (long int) threadID);*/
			//close(clntSock);
	}
	// END OF PROGRAM
}
