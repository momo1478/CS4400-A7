/*
 * friendlist.c - [Starting code for] a web-based friend-graph manager.
 *
 * Based on:
 *  tiny.c - A simple, iterative HTTP/1.0 Web server that uses the 
 *      GET method to serve static and dynamic content.
 *   Tiny Web server
 *   Dave O'Hallaron
 *   Carnegie Mellon University
 */
#include "csapp.h"
#include "dictionary.h"
#include "more_string.h"

static void doit(int fd);
static dictionary_t *read_requesthdrs(rio_t *rp);
static void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *d);
static void clienterror(int fd, char *cause, char *errnum, 
                        char *shortmsg, char *longmsg);
static void print_stringdictionary(dictionary_t *d);
static void print_friendmap();
static void serve_request(int fd, char* body);

static void get_friends(int fd, dictionary_t *query);
static void post_befriend(int fd, dictionary_t *query);
static void post_unfriend(int fd, dictionary_t *query);



dictionary_t* mdic;

int main(int argc, char **argv) 
{
  int listenfd, connfd;
  char hostname[MAXLINE], port[MAXLINE];
  socklen_t clientlen;
  struct sockaddr_storage clientaddr;

  /* Check command line args */
  if (argc != 2) {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    exit(1);
  }

  listenfd = Open_listenfd(argv[1]);
  mdic = (dictionary_t*)make_dictionary(COMPARE_CASE_SENS,free);

  /* Test CODE */
  //dictionary_t* newA = (dictionary_t*)make_dictionary(COMPARE_CASE_SENS,free);
  //dictionary_t* newM = (dictionary_t*)make_dictionary(COMPARE_CASE_SENS,free);
  //dictionary_set(mdic,"me", newA);
  //dictionary_set(newA,"alice", NULL);

  //dictionary_set(mdic,"alice", newM);
  //dictionary_set(newM,"me",NULL);

  /* Don't kill the server if there's an error, because
     we want to survive errors due to a client. But we
     do want to report errors. */
  exit_on_error(0);

  /* Also, don't stop on broken connections: */
  Signal(SIGPIPE, SIG_IGN);

  while (1) {
    clientlen = sizeof(clientaddr);
    connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
    if (connfd >= 0) {
      Getnameinfo((SA *) &clientaddr, clientlen, hostname, MAXLINE, 
                  port, MAXLINE, 0);
      printf("Accepted connection from (%s, %s)\n", hostname, port);
      doit(connfd);
      Close(connfd);
    }
  }
}

/*
 * doit - handle one HTTP request/response transaction
 */
void doit(int fd) 
{
  char buf[MAXLINE], *method, *uri, *version;
  rio_t rio;
  dictionary_t *headers, *query;

  /* Read request line and headers */
  Rio_readinitb(&rio, fd);
  if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
    return;
  printf("%s", buf);
  
  if (!parse_request_line(buf, &method, &uri, &version))
  {
    clienterror(fd, method, "400", "Bad Request",
                "Friendlist did not recognize the request");
  } 
  else 
  {
    if (strcasecmp(version, "HTTP/1.0")
        && strcasecmp(version, "HTTP/1.1")) 
    {
      clienterror(fd, version, "501", "Not Implemented",
                  "Friendlist does not implement that version");
    } 
    else if (strcasecmp(method, "GET")
               && strcasecmp(method, "POST")) 
    {
      clienterror(fd, method, "501", "Not Implemented",
                  "Friendlist does not implement that method");
    } 
    else 
    {
      headers = read_requesthdrs(&rio);

      /* Parse all query arguments into a dictionary */
      query = make_dictionary(COMPARE_CASE_SENS, free);
      parse_uriquery(uri, query);
      if (!strcasecmp(method, "POST"))
        read_postquery(&rio, headers, query);

      /* For debugging, print the dictionary */
      //print_stringdictionary(query);

      /* You'll want to handle different queries here,
         but the intial implementation always returns
         nothing: */

      if (starts_with("/friends", uri))
        get_friends(fd,query);
      else if (starts_with("/befriend", uri))
      	post_befriend(fd,query);
      else if (starts_with("/unfriend", uri))
      	post_unfriend(fd,query);


      /* Clean up */
      free_dictionary(query);
      free_dictionary(headers);
    }

    /* Clean up status line */
    free(method);
    free(uri);
    free(version);
  }
}

/*
 * read_requesthdrs - read HTTP request headers
 */
dictionary_t *read_requesthdrs(rio_t *rp) 
{
  char buf[MAXLINE];
  dictionary_t *d = make_dictionary(COMPARE_CASE_INSENS, free);

  Rio_readlineb(rp, buf, MAXLINE);
  printf("%s", buf);
  while(strcmp(buf, "\r\n")) 
  {
    Rio_readlineb(rp, buf, MAXLINE);
    printf("%s", buf);
    parse_header_line(buf, d);
  }
  
  return d;
}

void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *dest)
{
  char *len_str, *type, *buffer;
  int len;
  
  len_str = dictionary_get(headers, "Content-Length");
  len = (len_str ? atoi(len_str) : 0);

  type = dictionary_get(headers, "Content-Type");
  
  buffer = malloc(len+1);
  Rio_readnb(rp, buffer, len);
  buffer[len] = 0;

  if (!strcasecmp(type, "application/x-www-form-urlencoded")) 
  {
    parse_query(buffer, dest);
  }

  free(buffer);
}

static char *ok_header(size_t len, const char *content_type) 
{
  char *len_str, *header;
  
  header = append_strings("HTTP/1.0 200 OK\r\n",
                          "Server: Friendlist Web Server\r\n",
                          "Connection: close\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n",
                          "Content-type: ", content_type, "\r\n\r\n",
                          NULL);
  free(len_str);

  return header;
}

/*
 * serve_request - example request handler
 */
static void get_friends(int fd, dictionary_t *query)
{
  char *body;

  if(dictionary_count(query) != 1)
  {
  	clienterror(fd, "GET", "400", "Bad Request",
                  "/friends requires 1 user.");
	return;
  }

  const char* user = dictionary_get(query,"user");
  if(user == NULL)
  {
  	clienterror(fd, "GET", "400", "Bad Request",
                  "Invalid user field input");
	return;
  }

  dictionary_t *friendsOfU = (dictionary_t*)dictionary_get(mdic,user);
  if(friendsOfU == NULL)
  {
    body = "";
    serve_request(fd, body);
    //clienterror(fd, "GET", "400", "Bad Request",
    //           "User does not exist/Could not find user.");
	return;	
  }
  const char** allfriendNames = dictionary_keys(friendsOfU);
  print_stringdictionary(friendsOfU);
  
  body = join_strings(allfriendNames,'\n');

  //Send response back to client.
  serve_request(fd, body); 
}

/*
 * serve_request - example request handler
 */
static void post_befriend(int fd, dictionary_t *query)
{
  char *body;
  
  if(dictionary_count(query) != 2)
  {
  	clienterror(fd, "POST", "400", "Bad Request",
                  "/befriend requires only 2 query arguments.");
	return;
  }

  //Find name in <user>
  const char* user = (char*)dictionary_get(query,"user");
  if(user == NULL)
  {
    printf("New User!\n");
    dictionary_t* newF = (dictionary_t*)make_dictionary(COMPARE_CASE_SENS,free);
    dictionary_set(mdic, user, newF);
  }

  //Get set of friends of <user>
  dictionary_t *userDic = (dictionary_t*)dictionary_get(mdic,user);
  if(userDic == NULL)
  {
    printf("New Dictionary!\n");
    dictionary_t* newF = (dictionary_t*)make_dictionary(COMPARE_CASE_SENS,free);
    dictionary_set(mdic, user, newF);
  }

  //Get all friends of <user> as a string.
  char** newFriends = split_string( (char *)dictionary_get(query,"friends"),'\n');
  if(newFriends == NULL)
  {
  	clienterror(fd, "POST", "400", "Bad Request",
                  "User does not exist");
	return;
  }

  //Add new friends!
  int i;
  for (i = 0; newFriends[i] != NULL; ++i)
  {
        //<user> registered in the master dictionary?
  	dictionary_t* newF = (dictionary_t*)dictionary_get(mdic,user);
  	if(newF == NULL)
  	{
  		newF = (dictionary_t*)make_dictionary(COMPARE_CASE_SENS,free);
  		dictionary_set(mdic, user, newF);
  	}
	//<user> is not friends with new friend?
  	if(dictionary_get(newF,newFriends[i]) == NULL)
  	{
  		dictionary_set(newF,newFriends[i], NULL);
  	}

	//new friend is not registered in master dictionary?
  	dictionary_t* newFR = (dictionary_t*)dictionary_get(mdic,newFriends[i]);
  	if(newFR == NULL)
  	{
  		newFR = (dictionary_t*)make_dictionary(COMPARE_CASE_SENS,free);
  		dictionary_set(mdic, newFriends[i], newFR);
  	}
	//new friend is not friends with <user>?
  	if(dictionary_get(newFR,user) == NULL)
  	{
  		dictionary_set(newFR,user, NULL);
  	}
  }

  print_friendmap();
  
  //Respond with new friends list.
  userDic = (dictionary_t*)dictionary_get(mdic,user);
  const char** friendNames = dictionary_keys(userDic);

  body = join_strings(friendNames,'\n');

  //Respond back to client
  serve_request(fd, body);
}

/*
 * serve_request - example request handler
 */
static void post_unfriend(int fd, dictionary_t *query)
{
  char *body;
  
  if(dictionary_count(query) != 2)
  {
  	clienterror(fd, "POST", "400", "Bad Request",
                  "/unfriend requires only 2 query arguments.");
	return;
  }

  //Find name in <user>
  const char* user = (char*)dictionary_get(query,"user");
  if(user == NULL)
  {
    clienterror(fd, "POST", "400", "Bad Request",
                  "Invalid user field input");
	return;
  }

  //Get set of friends of <user>
  dictionary_t *userDic = (dictionary_t*)dictionary_get(mdic,user);
  if(userDic == NULL)
  {
    clienterror(fd, "POST", "400", "Bad Request",
                  "User does not exist.");
	return;
  }

  //Get all friends of <user> as a string.
  char** enemies = split_string( (char *)dictionary_get(query,"friends"),'\n');
  if(enemies == NULL)
  {
  	clienterror(fd, "GET", "400", "Bad Request",
                  "Unable to retrieve users friends for removal process.");
	return;
  }

  //Remove friends
  int i;
  for (i = 0; enemies[i] != NULL; ++i)
  {
	//<user> is not friends with new friend?
	dictionary_remove(userDic,enemies[i]);
  

	//new friend is not registered in master dictionary?
  	dictionary_t* enemyFriendSet = (dictionary_t*)dictionary_get(mdic,enemies[i]);
  	if(enemyFriendSet != NULL)
  	{
	  //new friend is not friends with <user>?
	  dictionary_remove(enemyFriendSet,user);
  	}
	
  }

  print_friendmap();
  
  //Respond with new friends list.
  userDic = (dictionary_t*)dictionary_get(mdic,user);
  const char** friendNames = dictionary_keys(userDic);

  body = join_strings(friendNames,'\n');

  //Respond back to client
  serve_request(fd, body);
}

/*
 * serve_request - example request handler
 */
static void serve_request(int fd, char* body)
{
  char *header;
  size_t len = strlen(body);
  
  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

/*
 * clienterror - returns an error message to the client
 */
void clienterror(int fd, char *cause, char *errnum, 
		 char *shortmsg, char *longmsg) 
{
  size_t len;
  char *header, *body, *len_str;

  body = append_strings("<html><title>Friendlist Error</title>",
                        "<body bgcolor=""ffffff"">\r\n",
                        errnum, " ", shortmsg,
                        "<p>", longmsg, ": ", cause,
                        "<hr><em>Friendlist Server</em>\r\n",
                        NULL);
  len = strlen(body);

  /* Print the HTTP response */
  header = append_strings("HTTP/1.0 ", errnum, " ", shortmsg, "\r\n",
                          "Content-type: text/html; charset=utf-8\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n\r\n",
                          NULL);
  free(len_str);
  
  Rio_writen(fd, header, strlen(header));
  Rio_writen(fd, body, len);

  free(header);
  free(body);
}

static void print_stringdictionary(dictionary_t *d)
{
  int i, count;

  count = dictionary_count(d);
  for (i = 0; i < count; i++) {
    printf("%s=%s\n",
           dictionary_key(d, i),
           (const char *)dictionary_value(d, i));
  }
  printf("\n");
}

static void print_friendmap()
{
  int i,count;

  count = dictionary_count(mdic);
  for (i = 0; i < count; i++)
  {
    printf("[%s] friend's\n",dictionary_key(mdic, i));
    printf("----------\n");
    print_stringdictionary(dictionary_value(mdic, i));
  }
}
