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
#include <utime.h>
#include <netdb.h>
#include <stdlib.h>

static int parse_arg(csiebox_server* server, int argc, char** argv);
static int handle_request(csiebox_server* server, int conn_fd);
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info);
static void syncmeta(
  csiebox_server* server , int conn_fd , csiebox_protocol_meta* meta );
static void syncfile(
  csiebox_server* server , int conn_fd , csiebox_protocol_file *file , char *filepath );
static void hardlink(
  csiebox_server* server , int conn_fd , csiebox_protocol_hardlink *hlink);
static void rmbox(
  csiebox_server *server , int conn_fd , csiebox_protocol_rm *rm);
#define DIR_S_FLAG (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)//permission you can use to create new file
#define REG_S_FLAG (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)//permission you can use to create new directory

char *hmdir[1024] , *temp;

struct stat forsyncfile; // for sync_file

//read config file, and start to listen
void csiebox_server_init(
  csiebox_server** server, int argc, char** argv) {
  csiebox_server* tmp = (csiebox_server*)malloc(sizeof(csiebox_server));
  if (!tmp) {
    fprintf(stderr, "server malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_server));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
    free(tmp);
    return;
  }
  int fd = server_start();
  if (fd < 0) {
    fprintf(stderr, "server fail\n");
    free(tmp);
    return;
  }
  tmp->client = (csiebox_client_info**)
      malloc(sizeof(csiebox_client_info*) * getdtablesize());
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

//wait client to connect and handle requests from connected socket fd
int csiebox_server_run(csiebox_server* server) {
  int conn_fd, conn_len;
  struct sockaddr_in addr;

  temp = (char *)malloc(500);

  fd_set master;
  fd_set read_fds;
  int fdmax;
  FD_ZERO(&master);
  FD_ZERO(&read_fds);
  FD_SET(server->listen_fd , &master);
  fdmax = server->listen_fd;

  while (1) {
    read_fds = master;
    memset(&addr, 0, sizeof(addr));
    conn_len = 0;
    // waiting client connect or data
    if(select(fdmax + 1 , &read_fds , NULL , NULL , NULL) == -1)
      fprintf(stderr , "select wait error\n");
    for(int i = 0 ; i <= fdmax ; i++)
    {
      if(FD_ISSET(i , &read_fds))
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
            fprintf(stderr , "new client connect \n");
          }
        }
        else
        {
          if(handle_request(server, i) == 0)
          {
            fprintf(stderr , "user %d logout\n" , i);
            FD_CLR(i , &master);
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
  int i = getdtablesize() - 1;
  for (; i >= 0; --i) {
    if (tmp->client[i]) {
      free(tmp->client[i]);
    }
  }
  free(tmp->client);
  free(tmp);
}

//read config file
static int parse_arg(csiebox_server* server, int argc, char** argv) {
  if (argc != 2) {
    return 0;
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
    fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
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

//this is where the server handle requests, you should write your code here
static int handle_request(csiebox_server* server, int conn_fd) {
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));

  if (recv_message(conn_fd, &header, sizeof(header)) > 0) {
    if( header.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ)
      return 1;
    fprintf(stderr , "handle request from %d op: "  , conn_fd);
    if(header.req.op != CSIEBOX_PROTOCOL_OP_LOGIN)
       strcpy(temp , hmdir[conn_fd]);
    switch (header.req.op) {
      case CSIEBOX_PROTOCOL_OP_LOGIN:
        fprintf(stderr, "login\n");
        csiebox_protocol_login req;
        if (complete_message_with_header(conn_fd, &header, &req)) {
          login(server, conn_fd, &req);
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_META:
        fprintf(stderr, "sync meta\n");
        csiebox_protocol_meta meta;
        if (complete_message_with_header(conn_fd, &header, &meta)) {
          syncmeta(server , conn_fd , &meta );
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK:
        fprintf(stderr, "sync hardlink\n");
        csiebox_protocol_hardlink hlink;
        if (complete_message_with_header(conn_fd, &header, &hlink)) {
          hardlink(server , conn_fd , &hlink);
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_END:
        fprintf(stderr, "sync end\n");
        break;
      case CSIEBOX_PROTOCOL_OP_RM:
        fprintf(stderr, "rm\n");
        csiebox_protocol_rm rm;
        if (complete_message_with_header(conn_fd, &header, &rm)) {
          rmbox(server , conn_fd , &rm);
        }
        break;
      default:
        fprintf(stderr, "unknown op %x\n", header.req.op);
        break;
    }
    return 1;
  }
  else
  {
    fprintf(stderr, "end of connection\n");
    logout(server, conn_fd);
    return 0;
  }
}

//open account file to get account information
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
      fprintf(stderr, "illegal form in account file, line %d\n", line);
      continue;
    }
    if (strcmp(user, u) == 0) {
      memcpy(info->user, user, strlen(user));
      char* passwd = strtok(NULL, ",");
      if (!passwd) {
        fprintf(stderr, "illegal form in account file, line %d\n", line);
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
static void rmbox(
  csiebox_server *server , int conn_fd , csiebox_protocol_rm *rm)
{
  int succ = 1;
  char *path = (char *)malloc(rm->message.body.pathlen + 1);
  recv_message(conn_fd , path , rm->message.body.pathlen + 1);
  strcpy(&temp[strlen(hmdir[conn_fd])] , path);

  struct stat stat_buf;
  if(lstat(temp , &stat_buf) < 0)
    succ = 0;
  else if(S_ISDIR(stat_buf.st_mode))
  {
    //fprintf(stderr , "remove dir %s\n" , temp);
    rmdir(temp);
  }
  else
  {
    //fprintf(stderr , "remove file %s\n" , temp);
    unlink(temp);
  }

  csiebox_protocol_header header;
  memset(&header , 0 , sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_RM;
  header.res.datalen = 0;
  if(succ == 1)
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
  else
    header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;

  send_message(conn_fd , &header , sizeof(header));
  return;
}

static void hardlink(
  csiebox_server* server , int conn_fd , csiebox_protocol_hardlink *hlink)
{
  int succ = 1;
  char *srcpath = (char *)malloc(hlink->message.body.srclen + 1);
  char *targetpath = (char *)malloc(hlink->message.body.targetlen + 1);
  recv_message(conn_fd , srcpath , hlink->message.body.srclen + 1);
  recv_message(conn_fd , targetpath , hlink->message.body.targetlen + 1);

  char *temp2 = (char *)malloc(500);
  strcpy(temp2 , hmdir[conn_fd]);
  strcpy(&temp[strlen(hmdir[conn_fd])] , srcpath);
  strcpy(&temp2[strlen(hmdir[conn_fd])] , targetpath);

  //fprintf(stderr ,"src : %s target %s\n" , temp , temp2);

  struct stat statbuf1 , statbuf2;
  if(lstat(temp2 , &statbuf2) < 0 )
    succ = 0;
  else if(lstat(temp , &statbuf1) == 0)
    succ = 0;
  else if(S_ISDIR(statbuf2.st_mode) )
    succ = 0;
  else
    link(temp2 , temp);

  csiebox_protocol_header header;
  memset(&header , 0 , sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
  header.res.datalen = 0;
  if(succ == 1)
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
  else
    header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;

  send_message(conn_fd , &header , sizeof(header));
  free(temp2);
  return;
}
static void syncfile(
  csiebox_server* server , int conn_fd , csiebox_protocol_file *file , char *filepath)
{
  int succ = 1;
  char *data = (char *)malloc(file->message.body.datalen);
  recv_message(conn_fd , data , file->message.body.datalen );

  //for(int i = 0 ; i < file->message.body.datalen ; i++)
    //printf("%c" , data[i]);
  FILE *fp = fopen(filepath , "w");
  if(fp == NULL)
  {
    fprintf(stderr , "open %s fail\n" , filepath);
    succ = 0;
  }
  else
  {
    fwrite(data , sizeof(char) , file->message.body.datalen , fp);
    fclose(fp);
  }
  //sync meta again
  if(chmod(filepath , forsyncfile.st_mode) < 0)
    succ = 0;
  struct utimbuf ubuf;
  ubuf.actime = forsyncfile.st_atime;
  ubuf.modtime = forsyncfile.st_mtime;
  if(utime(filepath , &ubuf) < 0)
    succ = 0;
  if(lchown(temp , forsyncfile.st_uid , forsyncfile.st_gid) < 0)
    succ = 0;

  csiebox_protocol_header header;
  memset(&header , 0 , sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
  header.res.datalen = 0;
  if(succ == 1)
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
  else
    header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;

  send_message(conn_fd , &header , sizeof(header));
  return;
}

static void syncmeta(
  csiebox_server* server , int conn_fd , csiebox_protocol_meta* meta )
{
  int succ = 1;
  char *path = (char *)malloc(meta->message.body.pathlen + 1);
  recv_message(conn_fd , path , meta->message.body.pathlen + 1);

  strcpy(&temp[strlen(hmdir[conn_fd])] , path);
  fprintf(stderr ,"syncing :%s\n" ,temp);
  char *filepath = (char *)malloc(500);
  memcpy(filepath , temp , strlen(temp) + 1);

  struct stat statbuf;
  memset(&statbuf , 0 , sizeof(statbuf) );

  int flag = 0;

  if(S_ISLNK(meta->message.body.stat.st_mode))
  {
    //fprintf(stderr , "sync slink:%s\n" , temp);
    flag = 1;
    int slinklen;
    recv_message(conn_fd , &slinklen , sizeof(int));
    char *slinktarget = (char *)malloc(slinklen + 1);
    recv_message(conn_fd , slinktarget , slinklen + 1);
    symlink(slinktarget , temp);
    free(slinktarget);
  }
  if(lstat(temp , &statbuf) < 0)
  {
    //fprintf(stderr ,"create a file\n");
    if(S_ISDIR(meta->message.body.stat.st_mode))
    {
      flag = 1;
      mkdir(temp , DIR_S_FLAG);
    }
    else
    {
      FILE *fp = fopen(temp , "w");
      fclose(fp);
    }
    lstat(temp , &statbuf);
  }
  if(S_ISDIR(statbuf.st_mode) == 1)
    flag = 1;


  if(statbuf.st_mode != meta->message.body.stat.st_mode)
  {
    if(chmod(temp , meta->message.body.stat.st_mode) < 0)
      succ = 0;
  }
  if(statbuf.st_atime != meta->message.body.stat.st_atime
    || statbuf.st_mtime != meta->message.body.stat.st_mtime)
  {
    struct utimbuf ubuf;
    ubuf.actime = meta->message.body.stat.st_atime;
    ubuf.modtime = meta->message.body.stat.st_mtime;
    if(utime(temp , &ubuf) < 0)
      succ = 0;
  }
  if(statbuf.st_uid != meta->message.body.stat.st_uid
    || statbuf.st_gid != meta->message.body.stat.st_gid)
  {
    if(lchown(temp , meta->message.body.stat.st_uid
      , meta->message.body.stat.st_gid) < 0)
      succ = 0;
  }
  lstat(temp , &statbuf);
  memcpy(&forsyncfile , &statbuf , sizeof(struct stat));

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
  header.res.datalen = 0;
  //compare file hash
  if(flag == 0)
  {
    uint8_t dig_buf[MD5_DIGEST_LENGTH];
    md5_file(temp , dig_buf);
    if(strncmp(dig_buf , meta->message.body.hash , MD5_DIGEST_LENGTH) != 0)
      succ = 2;
  }
  if(succ == 2)
    header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
  else if(succ == 1)
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
  else if(succ == 0)
  {
    fprintf(stderr , "sync meta error\n");
    header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
  }
  if(!send_message(conn_fd , &header , sizeof(header)))
    fprintf(stderr , "send error\n");
  if(succ == 2)
  {
    csiebox_protocol_header header;
    memset(&header, 0, sizeof(header));
    recv_message(conn_fd, &header, sizeof(header));
    fprintf(stderr, "sync file\n");
    csiebox_protocol_file file;
    if (complete_message_with_header(conn_fd, &header, &file))
          syncfile(server , conn_fd , &file , filepath);
  }
  free(filepath);
  free(path);
  return;
}

//handle the login request from client
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login) {
  int succ = 1;
  csiebox_client_info* info =
    (csiebox_client_info*)malloc(sizeof(csiebox_client_info));
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

    hmdir[conn_fd] = (char *)malloc(500);
    strcpy(hmdir[conn_fd] ,homedir);
    strcat(hmdir[conn_fd] ,"/");
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

static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info) {
  char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
  memset(ret, 0, PATH_MAX);
  sprintf(ret, "%s/%s", server->arg.path, info->account.user);
  return ret;
}

