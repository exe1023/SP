#include "csiebox_server.h"

#include "csiebox_common.h"
#include "connect.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#define __USE_GNU
#include <pthread.h>

int threadNum;
pthread_mutex_t request_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
pthread_cond_t  got_request   = PTHREAD_COND_INITIALIZER;
int num_requests = 0;
int thread_count = 0;
uint32_t active_thread = 0;
struct request {
    int fd;       /* number of the request   */
    struct request* next;   /* pointer to next request, NULL if none. */
};

struct request* requests = NULL;     /* head of linked list of requests. */
struct request* last_request = NULL; /* pointer to last request.         */

fd_set master;
short fdcondition[100000];

int fifo_fd = -1;
char fifopath[PATH_MAX];

int logfd;

static int parse_arg(csiebox_server* server, int argc, char** argv);
static int handle_request(csiebox_server* server, int conn_fd);
static int get_account_info(csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static void sync_file(csiebox_server* server, int conn_fd, csiebox_protocol_meta* meta);
static char* get_user_homedir(csiebox_server* server, csiebox_client_info* info);
static void rm_file(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm);
static void busy_return(csiebox_server *server , int conn_fd);

void csiebox_server_init(csiebox_server** server, int argc, char** argv) {
  csiebox_server* tmp = (csiebox_server*)malloc(sizeof(csiebox_server));
  if (!tmp) {
    fprintf(stderr, "server malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_server));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file] [-d]\n", argv[0]);
    free(tmp);
    return;
  }

  int fd = server_start();
  if (fd < 0) {
    fprintf(stderr, "server fail\n");
    free(tmp);
    return;
  }
  tmp->client = (csiebox_client_info**)malloc(sizeof(csiebox_client_info*) * getdtablesize());
  if (!tmp->client) {
    fprintf(stderr, "client list malloc fail\n");
    close(fd);
    free(tmp);
    return;
  }
  memset(tmp->client, 0, sizeof(csiebox_client_info*) * getdtablesize());
  tmp->listen_fd = fd;
  *server = tmp;
}

void writethread(int nsiag)
{
  //if(fifo_fd < 0)
  //{
    fifo_fd = open(fifopath , O_WRONLY);
    if(fifo_fd < 0)
      fprintf(stderr , "open fifo %s err\n" , fifopath);
    else
      fprintf(stderr , "open succ fifofd = %d\n" , fifo_fd);
  //}

  fprintf(stderr , "recv signal , act thread = %d\n" , active_thread);
  uint32_t temp = htonl(active_thread);
  if(write(fifo_fd , &temp , sizeof(uint32_t)) < 0)
    fprintf(stderr , "write_fifo fail\n");
  close(fifo_fd);
}

void
add_request(int request_fd,
      pthread_mutex_t* p_mutex,
      pthread_cond_t*  p_cond_var)
{
    int rc;                     /* return code of pthreads functions.  */
    struct request* a_request;      /* pointer to newly added request.     */

    /* create structure with new request */
    a_request = (struct request*)malloc(sizeof(struct request));
    if (!a_request) { /* malloc failed?? */
      fprintf(stderr, "add_request: out of memory\n");
      exit(1);
    }
    a_request->fd = request_fd;
    a_request->next = NULL;

    /* lock the mutex, to assure exclusive access to the list */
    rc = pthread_mutex_lock(p_mutex);

    /* add new request to the end of the list, updating list */
    /* pointers as required */
    if (num_requests == 0) { /* special case - list is empty */
      requests = a_request;
      last_request = a_request;
    }
    else {
      last_request->next = a_request;
      last_request = a_request;
    }

    /* increase total number of pending requests by one. */
    num_requests++;

    fprintf(stderr , "add_request: added request with id '%d'\n", a_request->fd);
    fflush(stderr);

    /* unlock mutex */
    rc = pthread_mutex_unlock(p_mutex);

    /* signal the condition variable - there's a new request to handle */
    rc = pthread_cond_signal(p_cond_var);
}

struct request*
get_request(pthread_mutex_t* p_mutex)
{
    int rc;                     /* return code of pthreads functions.  */
    struct request* a_request;      /* pointer to request.                 */

    if (num_requests > 0) {
      a_request = requests;
      requests = a_request->next;
      if (requests == NULL) { /* this was the last request on the list */
        last_request = NULL;
      }
  /* decrease the total number of pending requests */
      num_requests--;
    }
    else { /* requests list is empty */
      a_request = NULL;
    }

    /* unlock mutex */
    rc = pthread_mutex_unlock(p_mutex);

    /* return the request to the caller. */
    return a_request;
}


void*
handle_requests_loop(void* data)
{
    int rc;                     /* return code of pthreads functions.  */
    struct request* a_request;      /* pointer to a request.               */
    csiebox_server *server = (csiebox_server *)data;
    fprintf(stderr , "Starting thread\n");
    fflush(stderr);

    int thread_id = thread_count; /* for debug */
    /* lock the mutex, to access the requests list exclusively. */
    rc = pthread_mutex_lock(&request_mutex);

    /* do forever.... */
    while (1) {
      thread_count ++;
      rc = pthread_cond_wait(&got_request, &request_mutex);

      fprintf(stderr , "thread '%d', num_requests =  %d\n", thread_id, num_requests);
      fflush(stderr);
      if (num_requests > 0) { /* a request is pending */
        a_request = get_request(&request_mutex);
        if (a_request) { /* got a request - handle it and free it */
          active_thread ++;
          if(handle_request(server , a_request->fd) == 0)
          {
            fprintf(stderr , "user %d logout\n" , a_request->fd);
            FD_CLR(a_request->fd , &master);
          }
          active_thread --;
          fprintf(stderr , "finish task of %d\n" , a_request->fd);
          fdcondition[a_request->fd] = 0;
          free(a_request);
          pthread_mutex_lock(&request_mutex);
        }
      }
    }
}

void closeserver(int nsig)
{
  fprintf(stderr , "recv sig %d ,close server\n" , nsig);
  if(unlink(fifopath) < 0)
    fprintf(stderr , "remove fifo fail\n");

  exit(0);
}

void daemonize(csiebox_server *server)
{
  pid_t process_id = 0;
  pid_t sid = 0;
  process_id = fork();
  if(process_id < 0)
  {
    fprintf(stderr , "fork failed\n");
    return;
  }
  if(process_id > 0)
  {
    fprintf(stderr , "terminate parent process\n");
    exit(0);
  }

  umask(0);

  char logpath[PATH_MAX];
  strcpy(logpath , server->arg.run_path);
  strcat(logpath , "/log");
  logfd = open(logpath , O_CREAT | O_WRONLY , REG_S_FLAG);
  if(dup2(logfd , 1) < 0)
  {
    fprintf(stderr , "dup %d fail\n" , logfd);
    exit(1);
  }
  dup2(logfd , 2);

  sid = setsid();
  if(sid < 0)
  {
    exit(1);
  }

  char pidpath[PATH_MAX];
  strcpy(pidpath , server->arg.run_path);
  strcat(pidpath , "/csiebox_server.pid");
  FILE *fp = fopen(pidpath , "w");
  int pid = getpid();
  uint32_t tmp = htonl(pid);
  if(fp == NULL)
    fprintf(stderr , "open pidfile err\n");
  else
  {
    //fwrite(&pid , sizeof(int) , 1 , fp);
    fprintf(fp , "%d" , pid);
    fclose(fp);
  }

  return;
}

int csiebox_server_run(csiebox_server* server) {
  if(server->arg.daemonize == 1)
    daemonize(server);

  int conn_fd, conn_len;
  struct sockaddr_in addr;

  struct sigaction act , oldact , tmpact;
  act.sa_handler = writethread;
  act.sa_flags = 0;
  if(sigaction(SIGUSR1 , &act , &oldact) < 0)
    fprintf(stderr , "set sigusr fail\n");
  act.sa_handler = closeserver;
  if(sigaction(SIGINT , &act , &tmpact) < 0)
    fprintf(stderr , "set sigint fail\n");
  sigaction(SIGTERM , &act , &tmpact);
  fprintf(stderr , "set signal end\n");

  int spid = getpid();
  char spbuf[100];
  sprintf(spbuf , "%d" , spid);
  strcpy(fifopath , server->arg.run_path);
  strcat(fifopath , "/fifo.");
  strcat(fifopath , spbuf);
  if(mkfifo(fifopath , 0777) < 0)
    fprintf(stderr , "mkfifo failed\n");
  else
    fprintf(stderr , "mkfifo at %s succ\n" , fifopath);

  int        thr_id[threadNum];      /* thread IDs            */
  pthread_t  p_threads[threadNum];   /* thread's structures   */
  for (int i=0 ; i < threadNum ; i++) {
  thr_id[i] = i;
  pthread_create(&p_threads[i], NULL, handle_requests_loop, (void *)server );
    }

  fd_set read_fds;
  int fdmax;
  FD_ZERO(&master);
  FD_ZERO(&read_fds);
  FD_SET(server->listen_fd , &master);
  fdmax = server->listen_fd;

  memset(fdcondition , 0 , sizeof(short) * 100000);
  while (1) {
    read_fds = master;
    memset(&addr, 0, sizeof(addr));
    conn_len = 0;
    // waiting client connect or data
    if(select(fdmax + 1 , &read_fds , NULL , NULL , NULL) == -1)
    {
      continue;
      //fprintf(stderr , "select wait error\n");
    }
    for(int i = 0 ; i <= fdmax ; i++)
    {
      if( i != fifo_fd && FD_ISSET(i , &read_fds) && fdcondition[i] == 0)
      {
        if(i == server->listen_fd)
        {
          conn_fd = accept(
          server->listen_fd, (struct sockaddr*)&addr, (socklen_t*)&conn_len);
          if (conn_fd < 0) {
            if (errno == ENFILE) {
              fprintf(stderr, "out of file descriptor table\n");
              continue;
            } else if (errno == EAGAIN || errno == EINTR) {
              continue;
            } else {
              fprintf(stderr, "accept err\n");
              fprintf(stderr, "code: %s\n", strerror(errno));
              break;
            }
          }
          else
          {
            FD_SET(conn_fd , &master);
            if(conn_fd > fdmax)
              fdmax = conn_fd;
            fprintf(stderr , "new client %d connect \n" , conn_fd);
          }
        }
        else
        {
          if(thread_count > 0)
          {
            thread_count --;
            fdcondition[i] = 1;
            //fprintf(stderr , "thread left %d\n" , thread_count);
            //fprintf(stderr , "start task of %d\n" , i);
            add_request(i, &request_mutex, &got_request);
          }
          else
          {
            fprintf(stderr ,"Server busy\n");
            fflush(stderr);
            busy_return(server , i);
          }
        }
      }
    }
  }
  return 1;
}

void csiebox_server_destroy(csiebox_server** server) {
  csiebox_server* tmp = *server;
  *server = 0;
  if (!tmp) {
    return;
  }
  close(tmp->listen_fd);
  free(tmp->client);
  free(tmp);
}

static int parse_arg(csiebox_server* server, int argc, char** argv) {
  if (argc < 2) {
    return 0;
  }
  if(argc >= 3 && strcmp("-d" , argv[2]) == 0)
  {
    fprintf(stderr , "daemonize\n" );
    server->arg.daemonize = 1;
  }
  else
  {
    fprintf(stderr , "not daemonize\n");
    server->arg.daemonize = 0;
  }
  FILE* file = fopen(argv[1], "r");
  if (!file) {
    return 0;
  }
  fprintf(stderr, "reading config...\n");
  size_t keysize = 20, valsize = 20;
  char* key = (char*)malloc(sizeof(char) * keysize);
  char* val = (char*)malloc(sizeof(char) * valsize);
  ssize_t keylen, vallen;
  int accept_config_total = 2;
  int accept_config[2] = {0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%zd, %s)=(%zd, %s)\n", keylen, key, vallen, val);
    if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(server->arg.path)) {
        strncpy(server->arg.path, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("account_path", key) == 0) {
      if (vallen <= sizeof(server->arg.account_path)) {
        strncpy(server->arg.account_path, val, vallen);
        accept_config[1] = 1;
      }
    }
    else if (strcmp("thread" , key) == 0){
        threadNum = atoi(val);
        fprintf(stderr , "thread num = %d\n" , threadNum);
    }
    else if (strcmp("run_path" , key) == 0){
        strncpy(server->arg.run_path , val , vallen);
    }
  }
  free(key);
  free(val);
  fclose(file);
  int i, test = 1;
  for (i = 0; i < accept_config_total; ++i) {
    test = test & accept_config[i];
  }
  if (!test) {
    fprintf(stderr, "config error\n");
    return 0;
  }
  return 1;
}

static void busy_return(csiebox_server *server , int conn_fd)
{
  csiebox_protocol_header header;
  int busy = 0;
  memset(&header , 0 , sizeof(header));
  recv_message(conn_fd , &header , sizeof(header));
  char buff[100000];
  complete_message_with_header(conn_fd , &header , buff);
  send_message(conn_fd , &busy , sizeof(int) );
}

static int handle_request(csiebox_server* server, int conn_fd) {

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));

  int ok = 1;
  if (recv_message(conn_fd, &header, sizeof(header)) > 0) {
    if (header.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ)
      return 1;
    switch (header.req.op) {
      case CSIEBOX_PROTOCOL_OP_LOGIN:
        fprintf(stderr, "login\n");
        csiebox_protocol_login req;
        if (complete_message_with_header(conn_fd, &header, &req)) {
          send_message(conn_fd , &ok , sizeof(int));
          login(server, conn_fd, &req);
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_META:
        fprintf(stderr, "sync meta\n");
        csiebox_protocol_meta meta;
        if (complete_message_with_header(conn_fd, &header, &meta)) {
          send_message(conn_fd , &ok , sizeof(int));
          sync_file(server, conn_fd, &meta);
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_END:
        fprintf(stderr, "sync end\n");
        send_message(conn_fd , &ok , sizeof(int));
        break;
      case CSIEBOX_PROTOCOL_OP_RM:
        fprintf(stderr, "rm\n");
        csiebox_protocol_rm rm;
        if (complete_message_with_header(conn_fd, &header, &rm)) {
          send_message(conn_fd , &ok , sizeof(int));
          rm_file(server, conn_fd, &rm);
        }
        break;
      default:
        fprintf(stderr, "unknow op %x\n", header.req.op);
        break;
    }
    return 1;
  }
  else
  {
    fprintf(stderr , "end of connection\n" );
    logout(server , conn_fd);
    return 0;
  }
}
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info) {
  FILE* file = fopen(server->arg.account_path, "r");
  if (!file) {
    return 0;
  }
  size_t buflen = 100;
  char* buf = (char*)malloc(sizeof(char) * buflen);
  memset(buf, 0, buflen);
  ssize_t len;
  int ret = 0;
  int line = 0;
  while ((len = getline(&buf, &buflen, file) - 1) > 0) {
    ++line;
    buf[len] = '\0';
    char* u = strtok(buf, ",");
    if (!u) {
      fprintf(stderr, "ill form in account file, line %d\n", line);
      continue;
    }
    if (strcmp(user, u) == 0) {
      memcpy(info->user, user, strlen(user));
      char* passwd = strtok(NULL, ",");
      if (!passwd) {
        fprintf(stderr, "ill form in account file, line %d\n", line);
        continue;
      }
      md5(passwd, strlen(passwd), info->passwd_hash);
      ret = 1;
      break;
    }
  }
  free(buf);
  fclose(file);
  return ret;
}

static void login(csiebox_server* server, int conn_fd, csiebox_protocol_login* login) {
  int succ = 1;
  csiebox_client_info* info = (csiebox_client_info*)malloc(sizeof(csiebox_client_info));
  memset(info, 0, sizeof(csiebox_client_info));
  if (!get_account_info(server, login->message.body.user, &(info->account))) {
    fprintf(stderr, "cannot find account\n");
    succ = 0;
  }
  if (succ &&
      memcmp(login->message.body.passwd_hash,
             info->account.passwd_hash,
             MD5_DIGEST_LENGTH) != 0) {
    fprintf(stderr, "passwd miss match\n");
    succ = 0;
  }

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_LOGIN;
  header.res.datalen = 0;
  if (succ) {
    if (server->client[conn_fd]) {
      free(server->client[conn_fd]);
    }
    info->conn_fd = conn_fd;
    server->client[conn_fd] = info;
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
    header.res.client_id = info->conn_fd;
    char* homedir = get_user_homedir(server, info);
    mkdir(homedir, DIR_S_FLAG);
    free(homedir);
  } else {
    header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
    free(info);
  }
  send_message(conn_fd, &header, sizeof(header));
}

static void logout(csiebox_server* server, int conn_fd) {
  free(server->client[conn_fd]);
  server->client[conn_fd] = 0;
  close(conn_fd);
}

static void sync_file(csiebox_server* server, int conn_fd, csiebox_protocol_meta* meta) {
  csiebox_client_info* info = server->client[conn_fd];
  char* homedir = get_user_homedir(server, info);
  printf("homedir = %s\n", homedir);
  char buf[PATH_MAX], req_path[PATH_MAX];
  memset(buf, 0, PATH_MAX);
  memset(req_path, 0, PATH_MAX);
  recv_message(conn_fd, buf, meta->message.body.pathlen);
  sprintf(req_path, "%s%s", homedir, buf);
  free(homedir);
  fprintf(stderr, "req_path: %s\n", req_path);

  struct stat stat;
  memset(&stat, 0, sizeof(struct stat));
  int need_data = 0, change = 0;
   int block = 0 , ok = 1;
  if (lstat(req_path, &stat) < 0) {
    need_data = 1;
    change = 1;
    send_message(conn_fd , &ok , sizeof(int));
  } else { 					
    int isfile = 0;
    int lkfd = -1;
    if((meta->message.body.stat.st_mode & S_IFMT) != S_IFDIR)
    {
      isfile = 1;
      lkfd = open(req_path , O_WRONLY);
      struct flock getlk;
      getlk.l_type = F_WRLCK; getlk.l_whence = SEEK_SET;
      getlk.l_start = 0; getlk.l_len = 0; getlk.l_pid = 0;
      if(fcntl(lkfd , F_GETLK , &getlk) < 0)
        fprintf(stderr , "getlock err\n");
      int slp;
      while(getlk.l_type != F_UNLCK)
      {
        send_message(conn_fd , &block , sizeof(int));
        recv_message(conn_fd , &slp , sizeof(int));
        fcntl(lkfd , F_GETLK , &getlk);
      }
      struct flock mtlk;
      mtlk.l_type = F_WRLCK; mtlk.l_whence = SEEK_SET;
      mtlk.l_start = 0; mtlk.l_len = 0; mtlk.l_pid = 0;
      if(fcntl(lkfd , F_SETLK , &mtlk) >= 0)
        fprintf(stderr , "meta lock\n");
    }
    send_message(conn_fd , &ok , sizeof(int));
    if(stat.st_mode != meta->message.body.stat.st_mode) { 
      chmod(req_path, meta->message.body.stat.st_mode);
    }				
    if(stat.st_atime != meta->message.body.stat.st_atime ||
       stat.st_mtime != meta->message.body.stat.st_mtime){
      struct utimbuf* buf = (struct utimbuf*)malloc(sizeof(struct utimbuf));
      buf->actime = meta->message.body.stat.st_atime;
      buf->modtime = meta->message.body.stat.st_mtime;
      if(utime(req_path, buf)!=0){
        printf("time fail\n");
      }
    }
    uint8_t hash[MD5_DIGEST_LENGTH];
    memset(hash, 0, MD5_DIGEST_LENGTH);
    if ((stat.st_mode & S_IFMT) == S_IFDIR) {
    } else {
      md5_file(req_path, hash);
    }
    if(isfile == 1)
    {
      struct flock unlk;
      unlk.l_type = F_UNLCK; unlk.l_whence = SEEK_SET;
      unlk.l_start = 0; unlk.l_len = 0; unlk.l_pid = 0;
      if(fcntl(lkfd , F_SETLK , &unlk) >= 0)
        fprintf(stderr , "meta unlock\n");
      close(lkfd);
    }
    if (memcmp(hash, meta->message.body.hash, MD5_DIGEST_LENGTH) != 0) {
      need_data = 1;
    }
  }

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
  header.res.datalen = 0;
  header.res.client_id = conn_fd;
  if (need_data) {
    header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
  } else {
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
  }
  send_message(conn_fd, &header, sizeof(header));
  
  if (need_data) {
    csiebox_protocol_file file;
    memset(&file, 0, sizeof(file));
    recv_message(conn_fd, &file, sizeof(file));
    fprintf(stderr, "sync file: %zd\n", file.message.body.datalen);
    if ((meta->message.body.stat.st_mode & S_IFMT) == S_IFDIR) {
      fprintf(stderr, "dir\n");
      mkdir(req_path, DIR_S_FLAG);
    } else {
      fprintf(stderr, "regular file\n");
      int fd = open(req_path, O_CREAT | O_WRONLY | O_TRUNC, REG_S_FLAG);

      chmod(req_path , meta->message.body.stat.st_mode);
      struct flock setlk;
      setlk.l_type = F_WRLCK; setlk.l_whence = SEEK_SET;
      setlk.l_start = 0; setlk.l_len = 0; setlk.l_pid = 0;
      if(fcntl(fd , F_SETLK , &setlk) >= 0)
        fprintf(stderr , "file lock\n");

      size_t total = 0, readlen = 0;;
      char buf[4096];
      memset(buf, 0, 4096);
      while (file.message.body.datalen > total) {
        if (file.message.body.datalen - total < 4096) {
          readlen = file.message.body.datalen - total;
        } else {
          readlen = 4096;
        }
        if (!recv_message(conn_fd, buf, readlen)) {
          fprintf(stderr, "file broken\n");
          break;
        }
        total += readlen;
        if (fd > 0) {
          write(fd, buf, readlen);
        }
      }
      if (fd > 0) {
        setlk.l_type = F_UNLCK;
        if(fcntl(fd , F_SETLK , &setlk) >= 0)
          fprintf(stderr , "file unlock\n");
        close(fd);
      }
    }
    if (change) {
      chmod(req_path, meta->message.body.stat.st_mode);
      struct utimbuf* buf = (struct utimbuf*)malloc(sizeof(struct utimbuf));
      buf->actime = meta->message.body.stat.st_atime;
      buf->modtime = meta->message.body.stat.st_mtime;
      utime(req_path, buf);
    }
    header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
    send_message(conn_fd, &header, sizeof(header));
  }
}

static char* get_user_homedir(csiebox_server* server, csiebox_client_info* info) {
  char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
  memset(ret, 0, PATH_MAX);
  sprintf(ret, "%s/%s", server->arg.path, info->account.user);
  return ret;
}

static void rm_file(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm) {
  csiebox_client_info* info = server->client[conn_fd];
  char* homedir = get_user_homedir(server, info);
  char req_path[PATH_MAX], buf[PATH_MAX];
  memset(req_path, 0, PATH_MAX);
  memset(buf, 0, PATH_MAX);
  recv_message(conn_fd, buf, rm->message.body.pathlen);
  sprintf(req_path, "%s%s", homedir, buf);
  free(homedir);
  fprintf(stderr, "rm (%zd, %s)\n", strlen(req_path), req_path);
  struct stat stat;
  memset(&stat, 0, sizeof(stat));
  lstat(req_path, &stat);
  if ((stat.st_mode & S_IFMT) == S_IFDIR) {
    rmdir(req_path);
  } else {
    int lkfd = open(req_path , O_WRONLY);
    int block = 0 , ok = 1;
    struct flock getlk;
    getlk.l_type = F_WRLCK; getlk.l_whence = SEEK_SET;
    getlk.l_start = 0; getlk.l_len = 0; getlk.l_pid = 0;
    if(fcntl(lkfd , F_GETLK , &getlk) < 0)
      fprintf(stderr , "getlock err\n");
    int slp;
    while(getlk.l_type != F_UNLCK)
    {
      send_message(conn_fd , &block , sizeof(int));
      recv_message(conn_fd , &slp , sizeof(int));
      fcntl(lkfd , F_GETLK , &getlk);
    }
    send_message(conn_fd , &ok , sizeof(int));
    unlink(req_path);
  }

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_RM;
  header.res.datalen = 0;
  header.res.client_id = conn_fd;
  header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
  send_message(conn_fd, &header, sizeof(header));
}
