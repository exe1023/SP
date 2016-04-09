#include "csiebox_client.h"

#include "csiebox_common.h"
#include "connect.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>
#include <linux/inotify.h> //header for inotify

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

static int parse_arg(csiebox_client* client, int argc, char** argv);
static int login(csiebox_client* client);
static int syncmeta(csiebox_client* client , char *path);
static int syncfile(csiebox_client* client , char *path);
static int syncend(csiebox_client* client);
static int hardlink(csiebox_client *client , char *srcpath , char *targetpath);
static int rmbox(csiebox_client *client , char *path);

//my linked list
typedef struct node{
  struct node *next;
  int wd;
  char *string;
}Node;

void put_into_list(Node *head , int wd , char *path)
{
  Node *newnode = (Node *)malloc(sizeof(Node));
  Node *temp  = head;
  while(temp->next != NULL)
    temp = temp->next;
  newnode->next = NULL;
  newnode->wd = wd;
  newnode->string = path;
  temp->next = newnode;
}
void get_from_list(Node *head , int wd , char *path)
{
  Node *temp = head;
  while(temp != NULL && temp->wd != wd)
    temp = temp->next;
  if(temp == NULL)
  {
    fprintf(stderr , "get list error\n" );
    return;
  }
  strcpy(path , temp->string);
}
int del_from_list(Node *head , char *string)
{
  Node *temp = head->next;
  Node *last = head;
  while(temp != NULL && strcmp(string , temp->string) != 0)
  {
    last = temp;
    temp = temp->next;
  }
  if(temp == NULL)
  {
    fprintf(stderr , "can't find node\n");
    return -1;
  }
  last->next = temp->next;
  int wd = temp->wd;
  free(temp->string);
  free(temp);
  return wd;
}

//traverse cdir
char *file_path[500];
char *dir_path[500];
ino_t file_inode[500];
int file_count = 0 , dir_count = 0 ;
char *fullpath , *temp , *userdir , *hmdir;
void updatepath(int type) // 0 for file , 1 for directory
{
  if(strcmp(fullpath , userdir) == 0)
    return;
 // fprintf(stderr , "%s , type:%d\n" , fullpath , type);
  int i = strlen(userdir);
  i += 1;

  //fprintf(stderr , "modified: %s , type:%d\n" , temp , type);
  if(type == 0)
  {
    file_path[file_count] = (char *)malloc(500);
    strcpy(file_path[file_count] , &fullpath[i]);
    file_count ++;
  }
  else
  {
    dir_path[dir_count] = (char *)malloc(500);
    strcpy(dir_path[dir_count] , &fullpath[i]);
    dir_count ++;
  }
  return;
}

void dopath()
{
  struct stat statbuf;
  struct dirent *dirp;
  DIR *dp;

  //fprintf(stderr ,"%s\n" ,fullpath );
  if(lstat(fullpath , &statbuf) < 0)
    printf("stat error for %s" , fullpath);
  if(S_ISDIR(statbuf.st_mode) == 0)
  {
    //printf("%s\n",fullpath);
    updatepath(0);
    return;
  }

  //fprintf(stderr , "in dir : %s\n" , fullpath);
  updatepath(1);
  int n = strlen(fullpath);
  fullpath[n++] = '/';
  fullpath[n] = '\0';

  if((dp = opendir(fullpath)) == NULL)
    printf("open error");
  while((dirp = readdir(dp)) != NULL)
  {
    if(strcmp(dirp->d_name , ".") == 0 || strcmp(dirp->d_name , "..") == 0)
      continue;
    strcpy(&fullpath[n] , dirp->d_name);
    dopath();
    //fprintf(stderr ,"%s\n",fullpath);
  }
  //fprintf(stderr , "%s\n" ,fullpath );
  fullpath[n-1] = '\0';
  closedir(dp);
  //fprintf(stderr , "return %s\n" , fullpath);
  return;
}

int compare(const void *a , const void *b)
{
  const char *path1 = *(const char **)a;
  const char *path2 = *(const char **)b;
  int count1 = 0 , count2 = 0;
  int len1 = strlen(path1) , len2 = strlen(path2);
  for(int i = 0 ; i < len1 ; i++)
    if(path1[i] == '/')
      count1 ++;
  for(int i =  0 ; i < len2 ; i++)
    if(path2[i] == '/')
      count2 ++;
  return(count1 - count2);
}

void ftw(char *pathname)
{
  fullpath = (char *)malloc(500);
  temp = (char *)malloc(500);
  strcpy(fullpath , pathname);
  dopath();
  //fprintf(stderr ,"traverse end\n");
  qsort(file_path , file_count , sizeof(char *) , compare);
  qsort(dir_path , dir_count , sizeof(char *) , compare);

  /*for(int i = 0 ; i < file_count ; i++)
    fprintf(stderr ,"file :%s\n" , file_path[i]);
  for(int i = 0 ; i < dir_count ; i++)
    fprintf(stderr , "path :%s\n" , dir_path[i]) ;
  */
  return;
}

void sync_all(csiebox_client *client)
{
  for(int i = 0 ; i < dir_count ; i++)
    syncmeta(client , dir_path[i]);
  for(int i = 0 ; i < file_count ; i++)
  {
    int flag = 0;
    struct stat stat_buf;
    strcpy(&temp[strlen(userdir)] , file_path[i]);
    //printf("syncing file :%s\n", temp);
    lstat(temp , &stat_buf);
    for(int j = 0 ; j < i ; j++)
    {
      if(file_inode[j] == stat_buf.st_ino)
      {
        hardlink(client , file_path[i] , file_path[j]);
        flag = 1;
        break;
      }
    }
    if(flag == 0)
      syncmeta(client , file_path[i]);
    file_inode[i] = stat_buf.st_ino;
  }

  syncend(client);

}

//read config file, and connect to server
void csiebox_client_init(
  csiebox_client** client, int argc, char** argv) {
  csiebox_client* tmp = (csiebox_client*)malloc(sizeof(csiebox_client));
  if (!tmp) {
    fprintf(stderr, "client malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_client));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
    free(tmp);
    return;
  }
  int fd = client_start(tmp->arg.name, tmp->arg.server);
  if (fd < 0) {
    fprintf(stderr, "connect fail\n");
    free(tmp);
    return;
  }
  tmp->conn_fd = fd;
  *client = tmp;
}

//this is where client sends request, you sould write your code here
int csiebox_client_run(csiebox_client* client) {
  if (!login(client)) {
    fprintf(stderr, "login fail\n");
    return 0;
  }
  fprintf(stderr, "login success\n");

  userdir = (char *)malloc(500);
  strcpy(userdir , client->arg.path);

  ftw(client->arg.path);

  userdir = strcat(userdir , "/" ) ;
  strcpy(temp , userdir);
  sync_all(client);

  strcpy(temp , userdir);
  strcat(temp , "longestPath.txt");
  FILE *fp = fopen(temp , "w");
  //fprintf(stderr , "print longestpath to %s\n", temp);
  fprintf(fp , "%s\n" , dir_path[dir_count - 1]);
  fclose(fp);

  int length , i  = 0;
  int fd , wd = 0;
  char buffer[EVENT_BUF_LEN];
  memset(buffer , 0 , EVENT_BUF_LEN);
  fd = inotify_init();
  //fprintf(stderr , "%s\n" , client->arg.path);

  wd = inotify_add_watch(fd , client->arg.path , IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
  Node head;
  head.next = NULL;
  head.wd = wd;
  head.string = client->arg.path;
  //put_into_hash(&inotify_hash, (void *)client->arg.path , wd);
  for(i = 0 ; i < dir_count ; i++)
  {
    strcpy(&temp[strlen(userdir)] , dir_path[i]);
    strcpy(dir_path[i] , temp);
    //fprintf(stderr , "%s\n" , dir_path[i]);
    wd = inotify_add_watch(fd , dir_path[i] , IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
    put_into_list(&head , wd , dir_path[i] );
  }

  char *target = (char *)malloc(500) , *path = (char *)malloc(500);
  struct stat stat_buf;
  while(length = read(fd , buffer , EVENT_BUF_LEN) > 0)
  {
    i = 0;
    while(i < length)
    {
      struct inotify_event* event = (struct inotify_event*)&buffer[i];
      get_from_list(&head , event->wd , path );
      if(strlen(path) > strlen(client->arg.path) )
      {
        strcpy(target , &path[strlen(userdir)]);
        strcat(target , "/");
        strcat(target , event->name);
      }
      else
        strcpy(target , event->name);
      //fprintf(stderr , "%s path %s modified\n" ,path ,  target);
      if(event->mask & IN_CREATE)
      {
        //fprintf(stderr , "create ");
        if(event->mask & IN_ISDIR)
        {
          //fprintf(stderr , "directory ");
          syncmeta(client , target);
          strcpy(target , path);
          strcat(target , "/");
          strcat(target , event->name);
          //fprintf(stderr , "%s\n" , target);
          wd = inotify_add_watch(fd , target , IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
          put_into_list(&head , wd , target);
          target = (char *)malloc(500);
        }
        else
        {
          file_path[file_count] = (char *)malloc(500);
          strcpy(file_path[file_count] , target);
          file_count ++;
          strcpy(target , path);
          strcat(target , "/");
          strcat(target , event->name);
          int flag = 0;
          lstat(target , &stat_buf);
          file_inode[file_count - 1] = stat_buf.st_ino;
          for(int j = 0 ; j < file_count - 1; j ++)
          {
            if(file_inode[j] == stat_buf.st_ino)
            {
              //fprintf(stderr , "hardlink\nsrc = %s , target = %s\n" ,file_path[file_count - 1] , file_path[j] );
              flag = 1;
              hardlink(client , file_path[file_count - 1] , file_path[j]);
              break;
            }
          }
          if(flag == 0)
          {
            //fprintf(stderr , "slink or reg file\n");
            syncmeta(client , file_path[file_count - 1]);
          }
        }
      }
      if(event->mask & IN_DELETE)
      {
       // fprintf(stderr , "delete\n");
        rmbox(client , target);
        if(event->mask & IN_ISDIR)
        {
          strcpy(target , path);
          strcat(target , "/");
          strcat(target , event->name);
          int rm_wd = del_from_list(&head , target);
          //inotify_rm_watch(fd , rm_wd);
        }
        else
        {
          for(int j = 0 ; j < file_count ; j++)
          {
            if(strcmp(target , file_path[j]) == 0)
            {
              free(file_path[j]);
              for(int k = j ; k < file_count - 1 ; k++)
              {
                file_path[k] = file_path[k + 1];
                file_inode[k] = file_inode[k + 1];
              }
              break;
            }
          }
        }
      }
      if(event->mask & IN_ATTRIB)
      {
        //fprintf(stderr , "attrib\n");
        syncmeta(client , target);
      }
      if(event->mask & IN_MODIFY)
      {
        //fprintf(stderr , "modify\n");
        syncmeta(client , target);
      }
      i += EVENT_SIZE + event->len;
    }
    memset(buffer , 0 , EVENT_BUF_LEN);
  }
  close(fd);
  return 1;
}

void csiebox_client_destroy(csiebox_client** client) {
  csiebox_client* tmp = *client;
  *client = 0;
  if (!tmp) {
    return;
  }
  close(tmp->conn_fd);
  free(tmp);
}

//read config file
static int parse_arg(csiebox_client* client, int argc, char** argv) {
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
  int accept_config_total = 5;
  int accept_config[5] = {0, 0, 0, 0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
    if (strcmp("name", key) == 0) {
      if (vallen <= sizeof(client->arg.name)) {
        strncpy(client->arg.name, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("server", key) == 0) {
      if (vallen <= sizeof(client->arg.server)) {
        strncpy(client->arg.server, val, vallen);
        accept_config[1] = 1;
      }
    } else if (strcmp("user", key) == 0) {
      if (vallen <= sizeof(client->arg.user)) {
        strncpy(client->arg.user, val, vallen);
        accept_config[2] = 1;
      }
    } else if (strcmp("passwd", key) == 0) {
      if (vallen <= sizeof(client->arg.passwd)) {
        strncpy(client->arg.passwd, val, vallen);
        accept_config[3] = 1;
      }
    } else if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(client->arg.path)) {
        strncpy(client->arg.path, val, vallen);
        accept_config[4] = 1;
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

static int rmbox(csiebox_client *client , char *path)
{
  csiebox_protocol_rm req;
  memset(&req , 0 , sizeof(req));
  req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  req.message.header.req.op = CSIEBOX_PROTOCOL_OP_RM;
  req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
  req.message.body.pathlen = strlen(path);

  if(!send_message(client->conn_fd , &req , sizeof(req)))
  {
    fprintf(stderr , "send rm_header fail\n");
    return 0;
  }

  if(!send_message(client->conn_fd , path , strlen(path) + 1))
  {
    fprintf(stderr , "send rm_path fail\n");
    return 0;
  }
  csiebox_protocol_header header;
  memset(&header , 0 , sizeof(header));
  if(recv_message(client->conn_fd , &header , sizeof(header)))
  {
    if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
      header.res.op == CSIEBOX_PROTOCOL_OP_RM )
    {
      if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK)
        return 1;
      else
        return 0;
    }
    else
      return 0;
  }

}

static int hardlink(csiebox_client *client , char *srcpath , char *targetpath)
{
  csiebox_protocol_hardlink req;
  req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  req.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
  req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
  req.message.body.srclen = strlen(srcpath);
  req.message.body.targetlen = strlen(targetpath);

  if(!send_message(client->conn_fd , &req , sizeof(req)))
  {
    fprintf(stderr , "send hlink fail\n");
    return 0;
  }
  send_message(client->conn_fd , srcpath , strlen(srcpath) + 1);
  send_message(client->conn_fd , targetpath , strlen(targetpath) + 1);
  csiebox_protocol_header header;
  memset(&header , 0 , sizeof(header));
  if(recv_message(client->conn_fd , &header , sizeof(header)))
  {
    if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
      header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK &&
      header.res.status == CSIEBOX_PROTOCOL_STATUS_OK)
      return 1;
    else
      return 0;
  }
  else
    return 0;
}

static int syncfile(csiebox_client *client , char *path)
{
  csiebox_protocol_file req;
  strcpy(&temp[strlen(userdir)] , path);
  memset(&req , 0 , sizeof(req));
  req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  req.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
  req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);

  FILE *fp = fopen(temp , "r");
  int size;
  if(fp == NULL)
    return 1; // no need to sync
  else
  {
    fseek(fp , 0 , SEEK_END);
    size = ftell(fp);
    rewind(fp);
  }
  req.message.body.datalen = size;
  if(size == 0)
    return 1; // no need to sync

  if(!send_message(client->conn_fd , &req , sizeof(req)))
  {
    fprintf(stderr , "send header fail\n");
    return 0;
  }

  char *buffer = (char *)malloc(sizeof(char) * size);
  if(fread(buffer , 1 , size , fp) != size)
  {
    fprintf(stderr , "read file error\n");
    return 0;
  }

  if(!send_message(client->conn_fd , buffer , size))
  {
    fprintf(stderr , "send file fail\n");
    return 0;
  }
  fclose(fp);
  csiebox_protocol_header header;
  memset(&header , 0 , sizeof(header));
  if(recv_message(client->conn_fd , &header , sizeof(header)))
  {
    if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
      header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_META &&
      header.res.status == CSIEBOX_PROTOCOL_STATUS_OK)
      return 1;
    else
      return 0;
  }
  else
    return 0;
}

static int syncmeta(csiebox_client* client , char *path)
{
  strcpy(&temp[strlen(userdir)] , path);
  csiebox_protocol_meta req;
  memset(&req , 0 , sizeof(req));
  req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  req.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
  req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
  req.message.body.pathlen = strlen(path);
  struct stat stat_buf;
  if (lstat(temp , &stat_buf) < 0)
    return 0;

  memcpy(&req.message.body.stat , &stat_buf , sizeof(stat_buf));
  if(S_ISDIR(stat_buf.st_mode) == 0)
    md5_file(temp , req.message.body.hash);

  if(!send_message(client->conn_fd , &req , sizeof(req)))
  {
    fprintf(stderr , "send header fail\n");
    return 0;
  }

  if(!send_message(client->conn_fd , path , strlen(path) + 1))
  {
    fprintf(stderr , "send path fail\n");
    return 0;
  }

  if(S_ISLNK(stat_buf.st_mode))
  {
    //fprintf(stderr , "sync slink : %s\n" , temp);
    char *slinkbuff = (char *)malloc(1000);
    int slinklen = readlink(temp , slinkbuff , 1000);
    slinkbuff[slinklen] = '\0';
    slinklen = strlen(slinkbuff);
    send_message(client->conn_fd , &slinklen , sizeof(int) );
    send_message(client->conn_fd , slinkbuff , slinklen + 1);
    free(slinkbuff);
  }
  csiebox_protocol_header header;
  memset(&header , 0 , sizeof(header));
  if(recv_message(client->conn_fd , &header , sizeof(header)))
  {
    if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
      header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_META )
    {
      if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK)
        return 1;
      else if(header.res.status == CSIEBOX_PROTOCOL_STATUS_MORE)
      {
        return syncfile(client , path);
      }
    }
    else
      return 0;
  }
}

static int syncend(csiebox_client* client)
{
  csiebox_protocol_header req;
  memset(&req , 0 , sizeof(req));
  req.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  req.req.op = CSIEBOX_PROTOCOL_OP_SYNC_END;
  if(!send_message(client->conn_fd , &req , sizeof(req)))
  {
    fprintf(stderr , "end fail\n");
    return 0;
  }
  return 1;
}

static int login(csiebox_client* client) {
  csiebox_protocol_login req;
  memset(&req, 0, sizeof(req));
  req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  req.message.header.req.op = CSIEBOX_PROTOCOL_OP_LOGIN;
  req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
  memcpy(req.message.body.user, client->arg.user, strlen(client->arg.user));
  md5(client->arg.passwd,
      strlen(client->arg.passwd),
      req.message.body.passwd_hash);
  if (!send_message(client->conn_fd, &req, sizeof(req))) {
    fprintf(stderr, "send fail\n");
    return 0;
  }
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  if (recv_message(client->conn_fd, &header, sizeof(header))) {
    if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
        header.res.op == CSIEBOX_PROTOCOL_OP_LOGIN &&
        header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) {
      client->client_id = header.res.client_id;
      return 1;
    } else {
      return 0;
    }
  }
  return 0;
}
