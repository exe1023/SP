#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define ERR_EXIT(a) { perror(a); exit(1); }

typedef struct {
    char hostname[512];  // server's hostname
    unsigned short port;  // port to listen
    int listen_fd;  // fd to wait for a new connection
} server;

typedef struct {
    char host[512];  // client's host
    int conn_fd;  // fd to talk with client
    char buf[512];  // data sent by/to client
    size_t buf_len;  // bytes used by buf
    // you don't need to change this.
	int item;
    int wait_for_write;  // used by handle_read to know if the header is read or not.
} request;

typedef struct {
    int id;
    int amount;
    int price;
} Item;
    
server svr;  // server
request* requestP = NULL;  // point to a list of requests
int maxfd;  // size of open file descriptor table, size of request list

const char* accept_write_header = "ACCEPT_FROM_WRITE";
const char* list_file = "./item_list";

// Forwards

static void init_server(unsigned short port);
// initailize a server, exit for error

static void init_request(request* reqP);
// initailize a request instance

static void free_request(request* reqP);
// free resources used by a request instance

static int handle_read(request* reqP);
// return 0: socket ended, request done.
// return 1: success, message (without header) got this time is in reqP->buf with reqP->buf_len bytes. read more until got <= 0.
// It's guaranteed that the header would be correctly set after the first read.
// error code:
// -1: client connection error

static inline off_t seek_item(int listfd, int item_id) {
    return lseek(listfd, sizeof(Item) * (item_id - 1), SEEK_SET);
}

int main(int argc, char** argv) {
    int i, ret;

    struct sockaddr_in cliaddr;  // used by accept()
    int clilen;

    int conn_fd;  // fd for a new connection with client
    int file_fd;  // fd for file that we open for reading
    char buf[512];

    // Parse args.
    if (argc != 2) {
        fprintf(stderr, "usage: %s [port]\n", argv[0]);
        exit(1);
    }

    // Initialize server
    init_server((unsigned short) atoi(argv[1]));

    // Get file descripter table size and initize request table
    maxfd = getdtablesize();
    requestP = (request*) malloc(sizeof(request) * maxfd);
    if (requestP == NULL) {
        ERR_EXIT("out of memory allocating all requests");
    }
    for (i = 0; i < maxfd; i++) {
        init_request(&requestP[i]);
    }
    requestP[svr.listen_fd].conn_fd = svr.listen_fd;
    strcpy(requestP[svr.listen_fd].host, svr.hostname);

    // Loop for handling connections
    fprintf(stderr, "\nstarting on %.80s, port %d, fd %d, maxconn %d...\n", svr.hostname, svr.port, svr.listen_fd, maxfd);

    fd_set master_set, working_set;
    struct timeval timeout = {1, 0};

    FD_ZERO(&master_set);
    FD_SET(svr.listen_fd, &master_set);

    while (1) {
        memcpy(&working_set, &master_set, sizeof(master_set));
        int ready_count = select(maxfd, &working_set, NULL, NULL, &timeout);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        if(ready_count > 0) {
            int conn;
            for(conn = 3; conn < maxfd; ++conn) {
                if(ready_count <= 0) break;
                if(FD_ISSET(conn, &working_set)) {
                    --ready_count;
                    if(conn == svr.listen_fd) {
                        // Check new connection
                        clilen = sizeof(cliaddr);
                        conn_fd = accept(svr.listen_fd, (struct sockaddr*)&cliaddr, (socklen_t*)&clilen);
                        if (conn_fd < 0) {
                            if (errno == EINTR || errno == EAGAIN) continue;  // try again
                            if (errno == ENFILE) {
                                (void) fprintf(stderr, "out of file descriptor table ... (maxconn %d)\n", maxfd);
                                continue;
                            }
                            ERR_EXIT("accept")
                        }
                        requestP[conn_fd].conn_fd = conn_fd;
                        strcpy(requestP[conn_fd].host, inet_ntoa(cliaddr.sin_addr));
                        fprintf(stderr, "getting a new request... fd %d from %s\n", conn_fd, requestP[conn_fd].host);
                        FD_SET(conn_fd, &master_set);
                    }
                    else {
                        // handle and close the request
                        ret = handle_read(&requestP[conn]); //parse data from client to requestP[conn].buf
                        if(ret < 0) {
                            fprintf(stderr, "bad request from %s\n", requestP[conn].host);
                            continue;
                        }
                        Item target_item;
#ifdef READ_SERVER
                        file_fd = open(list_file, O_RDONLY);
                        seek_item(file_fd, atoi(requestP[conn].buf));
                        read(file_fd, &target_item, sizeof(Item));
                        sprintf(buf, "item%d $%d remain: %d\n", target_item.id, target_item.price, target_item.amount);
                        write(requestP[conn].conn_fd, buf, strlen(buf));
#else
                        file_fd = open(list_file, O_RDWR);
                        seek_item(file_fd, atoi(requestP[conn].buf));
                        read(file_fd, &target_item, sizeof(Item));
                        seek_item(file_fd, atoi(requestP[conn].buf));
                        sprintf(buf, "item%d $%d reamin: %d\n", target_item.id, target_item.price, target_item.amount);
                        write(requestP[conn].conn_fd, buf, strlen(buf));

                        printf("reading next request\n");
                        ret = handle_read(&requestP[conn]);
                        if(ret < 0) {
                            fprintf(stderr, "bad request from %s\n", requestP[conn].host);
                            continue;
                        }

                        char op[8];
                        int quant;
                        sscanf(requestP[conn].buf, "%s %d", op, &quant);
                        if(!strcmp(op, "sell")) {
                            target_item.amount += quant;
                            write(file_fd, &target_item, sizeof(Item));
                        }
                        else if(!strcmp(op, "buy")) {
                            if(quant > target_item.amount) {
                                sprintf(buf, "Operation failed\n");
                                write(requestP[conn].conn_fd, buf, strlen(buf));
                            }
                            else {
                                target_item.amount -= quant;
                                write(file_fd, &target_item, sizeof(Item));
                            }
                        }
                        else if(!strcmp(op, "price")) {
                            if(quant < 0) {
                                sprintf(buf, "Operation failed\n");
                                write(requestP[conn].conn_fd, buf, strlen(buf));
                            }
                            else {
                                printf("modifying price\n");
                                target_item.price = quant;
                                write(file_fd, &target_item, sizeof(Item));
                            }
                        } 
#endif
                        close(file_fd);
                        close(requestP[conn].conn_fd);
                        free_request(&requestP[conn]);
                        FD_CLR(conn, &master_set);
                    }
                }
            }
        }
        else if(ready_count == -1) {
            fprintf(stderr, "SELECT ERROR\n");
            //handle error;
        }
    }
    free(requestP);
    return 0;
}


// ======================================================================================================
// You don't need to know how the following codes are working
#include <fcntl.h>

static void* e_malloc(size_t size);


static void init_request(request* reqP) {
    reqP->conn_fd = -1;
    reqP->buf_len = 0;
    reqP->item = 0;
    reqP->wait_for_write = 0;
}

static void free_request(request* reqP) {
    /*if (reqP->filename != NULL) {
        free(reqP->filename);
        reqP->filename = NULL;
    }*/
    init_request(reqP);
}

// return 0: socket ended, request done.
// return 1: success, message (without header) got this time is in reqP->buf with reqP->buf_len bytes. read more until got <= 0.
// It's guaranteed that the header would be correctly set after the first read.
// error code:
// -1: client connection error
static int handle_read(request* reqP) {
    int r;
    char buf[512];

    // Read in request from client
    r = read(reqP->conn_fd, buf, sizeof(buf));
    if (r < 0) return -1;
    if (r == 0) return 0;
	char* p1 = strstr(buf, "\015\012");
	int newline_len = 2;
	// be careful that in Windows, line ends with \015\012
	if (p1 == NULL) {
		p1 = strstr(buf, "\012");
		newline_len = 1;
		if (p1 == NULL) {
			ERR_EXIT("this really should not happen...");
		}
	}
	size_t len = p1 - buf + 1;
	memmove(reqP->buf, buf, len);
	reqP->buf[len - 1] = '\0';
	reqP->buf_len = len-1;
    return 1;
}

static void init_server(unsigned short port) {
    struct sockaddr_in servaddr;
    int tmp;

    gethostname(svr.hostname, sizeof(svr.hostname));
    svr.port = port;

    svr.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (svr.listen_fd < 0) ERR_EXIT("socket");

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    tmp = 1;
    if (setsockopt(svr.listen_fd, SOL_SOCKET, SO_REUSEADDR, (void*)&tmp, sizeof(tmp)) < 0) {
        ERR_EXIT("setsockopt");
    }
    if (bind(svr.listen_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        ERR_EXIT("bind");
    }
    if (listen(svr.listen_fd, 1024) < 0) {
        ERR_EXIT("listen");
    }
}

static void* e_malloc(size_t size) {
    void* ptr;

    ptr = malloc(size);
    if (ptr == NULL) ERR_EXIT("out of memory");
    return ptr;
}

