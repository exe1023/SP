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

static int parse_arg(csiebox_server* server, int argc, char** argv);
static int handle_request(csiebox_server* server, int conn_fd);
static int get_account_info(csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static void sync_file(csiebox_server* server, int conn_fd, csiebox_protocol_meta* meta , int sa_fd);
static char* get_user_homedir(csiebox_server* server, csiebox_client_info* info);
static void rm_file(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm , int sa_fd);
static void download(csiebox_server *server, int conn_fd , char* path , int hmlen);


// about logintable
typedef struct lo{
  char *loginAccount[10];
  int loginfd[10][3]; // [x][0] means how many users login
  int accountCount;
}Logintable;

Logintable logintable;


int findconnect(char *account , int conn_fd)
{
  for(int i = 0 ; i < logintable.accountCount ; i ++)
  {
    if(strcmp(logintable.loginAccount[i] , account) == 0)
    {
      if(logintable.loginfd[i][1] == conn_fd)
      {
        if(logintable.loginfd[i][0] == 2)
          return logintable.loginfd[i][2];
        else
          return -1;
      }
      else if(logintable.loginfd[i][2] == conn_fd)
        return logintable.loginfd[i][1];
      else
      {
        fprintf(stderr , "This should not happen.....\n");
        return -1;
      }
    }
  }
  fprintf(stderr , "can not happen , WTF\n");
  return -1;
}

void newconnect(char *account , int conn_fd)
{
  for(int i = 0 ; i < logintable.accountCount ; i ++)
  {
    if(strcmp(logintable.loginAccount[i] , account) == 0)
    {
      logintable.loginfd[i][0] ++;
      int j = logintable.loginfd[i][0];
      logintable.loginfd[i][j] = conn_fd;
      return;
    }
  }
  char *tmp = (char *)malloc(sizeof(char) * PATH_MAX);
  strcpy(tmp , account);
  logintable.loginAccount[logintable.accountCount] = tmp;
  logintable.loginfd[logintable.accountCount][0] = 1;
  logintable.loginfd[logintable.accountCount][1] = conn_fd;
  logintable.accountCount ++;
  return;
}


void rmaccount(int i)
{
  free(logintable.loginAccount[i]);
  for(i ; i < logintable.accountCount - 1 ; i++)
  {
    logintable.loginAccount[i] = logintable.loginAccount[i + 1];
    for(int j = 0 ; j < 3 ; j++)
      logintable.loginfd[i][j] = logintable.loginfd[i + 1][j];
  }
  logintable.accountCount -- ;
}

void rmconnect(char *account , int conn_fd)
{
  int i;
  for(i = 0 ; i < logintable.accountCount ; i++)
  {
    if(strcmp(logintable.loginAccount[i] , account) == 0)
    {
      if(logintable.loginfd[i][1] == conn_fd)
        logintable.loginfd[i][1] = logintable.loginfd[i][2];
      logintable.loginfd[i][2] = 0;
      logintable.loginfd[i][0] --;
      if(logintable.loginfd[i][0] == 0)
      {
        rmaccount(i);
      }
      return;
    }
  }
}
// logintable end
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

int csiebox_server_run(csiebox_server* server) { 
  int conn_fd, conn_len;
  struct sockaddr_in addr;

  memset(&logintable , 0 , sizeof(Logintable));
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
            fprintf(stderr , "new client %d connect \n" , conn_fd);
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
  free(tmp->client);
  free(tmp);
}

static int parse_arg(csiebox_server* server, int argc, char** argv) {
  if (argc < 2) {
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

static int handle_request(csiebox_server* server, int conn_fd) {

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  int sa_fd = -1;
  if (recv_message(conn_fd, &header, sizeof(header)) > 0) {
  	if (header.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ)
		  return 1;
    if(header.req.op != CSIEBOX_PROTOCOL_OP_LOGIN)
    {
      csiebox_client_info* info = server->client[conn_fd];
      sa_fd = findconnect(info->account.user , conn_fd);
    }
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
  	      sync_file(server, conn_fd, &meta , sa_fd);
  	    }
  	    break;
  	  case CSIEBOX_PROTOCOL_OP_SYNC_END:
  	    fprintf(stderr, "sync end\n");
  	    break;
  	  case CSIEBOX_PROTOCOL_OP_RM:
  	    fprintf(stderr, "rm\n");
  	    csiebox_protocol_rm rm;
  	    if (complete_message_with_header(conn_fd, &header, &rm)) {
  	      rm_file(server, conn_fd, &rm , sa_fd);
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

static void download_data(
  int conn_fd , char* path) {
  fprintf(stderr, "file_data: %s\n", path);
  struct stat stat;
  memset(&stat, 0, sizeof(stat));
  lstat(path, &stat);
  csiebox_protocol_file file;
  memset(&file, 0, sizeof(file));
  file.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  file.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
  //file.message.header.req.client_id = client->client_id;
  file.message.header.req.datalen = sizeof(file) - sizeof(csiebox_protocol_header);
  if ((stat.st_mode & S_IFMT) == S_IFDIR) {
    file.message.body.datalen = 0;
    fprintf(stderr, "dir datalen: %zu\n", file.message.body.datalen);
    send_message(conn_fd, &file, sizeof(file));
  } else {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "open fail\n");
      file.message.body.datalen = 0;
      send_message(conn_fd, &file, sizeof(file));
    } else {
      file.message.body.datalen = lseek(fd, 0, SEEK_END);
      fprintf(stderr, "else datalen: %zd\n", file.message.body.datalen);
      send_message(conn_fd, &file, sizeof(file));
      lseek(fd, 0, SEEK_SET);
      char buf[4096];
      memset(buf, 0, 4096);
      size_t readlen;
      while ((readlen = read(fd, buf, 4096)) > 0) {
        send_message(conn_fd, buf, readlen);
      }
      close(fd);
    }
  }

  csiebox_protocol_header header;
  recv_message(conn_fd, &header, sizeof(header));
  if (header.res.status != CSIEBOX_PROTOCOL_STATUS_OK) {
    fprintf(stderr, "sync data fail: %s\n", path);
  }
}


static csiebox_protocol_status download_meta(int conn_fd, char* path , int hmlen) {

  char* relative = (char *)malloc(sizeof(char) * PATH_MAX);
  strcpy(relative , &path[hmlen]);

  csiebox_protocol_meta meta;
  memset(&meta, 0, sizeof(meta));
  meta.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  meta.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
  //meta.message.header.req.client_id = client->client_id;
  meta.message.header.req.datalen = sizeof(meta) - sizeof(csiebox_protocol_header);
  meta.message.body.pathlen = strlen(relative);
  lstat(path, &(meta.message.body.stat));
  if ((meta.message.body.stat.st_mode & S_IFMT) == S_IFDIR) {
  } else {
    md5_file(path, meta.message.body.hash);
  }
  send_message(conn_fd, &meta, sizeof(meta));
  send_message(conn_fd, relative, strlen(relative));
  free(relative);
  
  csiebox_protocol_header header;
  recv_message(conn_fd, &header, sizeof(header));
  if (header.res.status == CSIEBOX_PROTOCOL_STATUS_FAIL) {
    fprintf(stderr, "sync meta fail: %s\n", path);
    return CSIEBOX_PROTOCOL_STATUS_FAIL;
  }
  return header.res.status;
}

static void download(csiebox_server *server, int conn_fd , char* path , int hmlen) {

  csiebox_protocol_status status;
  status = download_meta(conn_fd, path , hmlen);
  if (status == CSIEBOX_PROTOCOL_STATUS_MORE) {
    download_data(conn_fd, path);
  }
}

static void traverse_download(csiebox_server *server , int conn_fd , char *fullpath , int hmlen)
{
  char *cwd = (char *)malloc(sizeof(char) * PATH_MAX);
  memset(cwd , 0 , sizeof(char) * PATH_MAX);
  getcwd(cwd , PATH_MAX);
  DIR *dir;
  struct dirent *file;
  struct stat file_stat;
  dir = opendir(".");

  int n = strlen(fullpath);
  fullpath[n++] = '/';
  fullpath[n] = '\0';
  while((file = readdir(dir)) != NULL)
  {
    if(strcmp(file->d_name , ".") == 0 ||
      strcmp(file->d_name , "..") == 0)
      continue;
    lstat(file->d_name , &file_stat);
    strcpy(&fullpath[n] , file->d_name);
    download(server , conn_fd , fullpath , hmlen);
    fprintf(stderr , "traversing , now in :%s\n" , fullpath);
    if((file_stat.st_mode & S_IFMT) == S_IFDIR)
    {
      if(chdir(file->d_name) != 0)
      {
        fprintf(stderr , "bad dir %s\n" , file->d_name);
        continue;
      }
      traverse_download(server , conn_fd , fullpath , hmlen);
      chdir(cwd);
    }
  }
  closedir(dir);
  fullpath[n-1] = '\0';
  free(cwd);
  return;
}

static void prepare_download(csiebox_server* server , int conn_fd , char *hmdir)
{
  char* cwd = (char*)malloc(sizeof(char) * PATH_MAX);
  memset(cwd , 0 , sizeof(char) * PATH_MAX);
  if(getcwd(cwd , PATH_MAX) == 0)
  {
    fprintf(stderr , "getcwd fail\n");
    free(cwd);
    return;
  }
  if(chdir(hmdir) != 0)
  {
    fprintf(stderr , "invalid server path\n");
    free(cwd);
    return;
  }
  char *fullpath = (char *)malloc(sizeof(char) * PATH_MAX);
  strcpy(fullpath , hmdir);
  int hmlen = strlen(hmdir);
  traverse_download(server , conn_fd , fullpath , hmlen);

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_END;
  //header.req.client_id = client->client_id;
  send_message(conn_fd , &header , sizeof(header));
  chdir(cwd);
  free(cwd);
  free(fullpath);
  fprintf(stderr , "download end\n" );
  return;
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

  char *hmdir = (char *)malloc(sizeof(char) * PATH_MAX);

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
    strcpy(hmdir , homedir);
    free(homedir);
  } else {
    header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
    free(info);
  }
  send_message(conn_fd, &header, sizeof(header));

  if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK)
  {
    prepare_download(server , conn_fd , hmdir);
    newconnect(info->account.user , conn_fd);
  }
}

static void logout(csiebox_server* server, int conn_fd) {
  csiebox_client_info* info = server->client[conn_fd];
  rmconnect(info->account.user , conn_fd);

  free(server->client[conn_fd]);
  server->client[conn_fd] = 0;
  close(conn_fd);
}

static void sync_file(csiebox_server* server, int conn_fd, csiebox_protocol_meta* meta , int sa_fd) {
  csiebox_client_info* info = server->client[conn_fd];
  char* homedir = get_user_homedir(server, info);
  printf("homedir = %s\n", homedir);
  char buf[PATH_MAX], req_path[PATH_MAX];
  memset(buf, 0, PATH_MAX);
  memset(req_path, 0, PATH_MAX);
  recv_message(conn_fd, buf, meta->message.body.pathlen);
  sprintf(req_path, "%s%s", homedir, buf);

  char sa_req[PATH_MAX];
  strcpy(sa_req , req_path);
  int hmlen = strlen(homedir);

  free(homedir);
  fprintf(stderr, "req_path: %s\n", req_path);
  struct stat stat;
  memset(&stat, 0, sizeof(struct stat));
  int need_data = 0, change = 0;
  if (lstat(req_path, &stat) < 0) {
    need_data = 1;
    change = 1;
  } else {
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

  if(sa_fd > 0)
  {
    fprintf(stderr , "device:%d start download\n" , sa_fd);

    download(server , sa_fd , sa_req , hmlen );
  }
}

static char* get_user_homedir(csiebox_server* server, csiebox_client_info* info) {
  char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
  memset(ret, 0, PATH_MAX);
  sprintf(ret, "%s/%s", server->arg.path, info->account.user);
  return ret;
}

static void download_rm(int conn_fd, char* path , int hmlen) {
  char* relative = (char *)malloc(sizeof(char) * PATH_MAX);
  strcpy(relative , &path[hmlen]);

  csiebox_protocol_rm rm;
  memset(&rm, 0, sizeof(rm));
  rm.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  rm.message.header.req.op = CSIEBOX_PROTOCOL_OP_RM;
  //rm.message.header.req.client_id = client->client_id;
  rm.message.header.req.datalen = sizeof(rm) - sizeof(csiebox_protocol_header);
  rm.message.body.pathlen = strlen(relative);
  send_message(conn_fd, &rm, sizeof(rm));
  send_message(conn_fd, relative, strlen(relative));
  csiebox_protocol_header header;
  recv_message(conn_fd, &header, sizeof(header));
  if (header.res.status != CSIEBOX_PROTOCOL_STATUS_OK) {
    fprintf(stderr, "rm fail: %s\n", path);
  }
  free(relative);
}

static void rm_file(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm , int sa_fd) {
  csiebox_client_info* info = server->client[conn_fd];
  char* homedir = get_user_homedir(server, info);
  char req_path[PATH_MAX], buf[PATH_MAX];
  memset(req_path, 0, PATH_MAX);
  memset(buf, 0, PATH_MAX);
  recv_message(conn_fd, buf, rm->message.body.pathlen);
  sprintf(req_path, "%s%s", homedir, buf);

  char sa_req[PATH_MAX];
  strcpy(sa_req , req_path);
  int hmlen = strlen(homedir);

  free(homedir);
  fprintf(stderr, "rm (%zd, %s)\n", strlen(req_path), req_path);
  struct stat stat;
  memset(&stat, 0, sizeof(stat));
  lstat(req_path, &stat);
  if ((stat.st_mode & S_IFMT) == S_IFDIR) {
    rmdir(req_path);
  } else {
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

  if(sa_fd > 0)
  {
    fprintf(stderr , "device:%d start download rm\n", sa_fd);
    download_rm(sa_fd , sa_req , hmlen);
  }
}
