/* J. David's webserver */
/* This is a simple webserver.
 * Created November 1999 by J. David Blackstone.
 * CSE 4344 (Network concepts), Prof. Zeigler
 * University of Texas at Arlington
 */
/* This program compiles for Sparc Solaris 2.6.
 * To compile for Linux:
 *  1) Comment out the #include <pthread.h> line.
 *  2) Comment out the line that defines the variable newthread.
 *  3) Comment out the two lines that run pthread_create().
 *  4) Uncomment the line that runs accept_request().
 *  5) Remove -lsocket from the Makefile.
 */

/*
 * 阅读顺序：main -> startup -> accept_request -> execute_cgi
 */

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdint.h>

#define ISspace(x) isspace((int)(x))  //判断是否为x这个字符

#define SERVER_STRING "Server: jdbhttpd/0.1.0\r\n"
#define STDIN   0
#define STDOUT  1
#define STDERR  2

void accept_request(void *);		//处理从套接字上监听到的一个 HTTP 请求，在这里可以很大一部分地体现服务器处理请求流程
void bad_request(int);				//返回给客户端这是个错误请求，HTTP 状态码
void cat(int, FILE *);				//读取服务器上某个文件写到 socket 套接字
void cannot_execute(int);			//主要处理发生在执行 cgi 程序时出现的错误
void error_die(const char *);		//把错误信息写到 perror 并退出
void execute_cgi(int, const char *, const char *, const char *);	//运行 cgi 程序的处理，也是个主要函数
int get_line(int, char *, int);		//读取套接字的一行，把回车换行等情况都统一为换行符结束
void headers(int, const char *);	//把 HTTP 响应的头部写到套接字
void not_found(int);				//主要处理找不到请求的文件时的情况
void serve_file(int, const char *);	//调用 cat 把服务器文件返回给浏览器
int startup(u_short *);				//初始化 httpd 服务，包括建立套接字，绑定端口，进行监听等
void unimplemented(int);			//返回给浏览器表明收到的 HTTP 请求所用的 method 不被支持

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/

/*
 * accept_request函数先初始化client：客户端套接字描述符、buf：读取请求行时的数据缓存区、numchars：请求行字符长度、method：请求行中的方法名、path：请求行中的路径、url：请求行中的 URL 字段、
 * st：文件属性、cgi：cgi 标志位、query_string：指向 URL 中请求参数的指针。
 * 先通过get_line函数获取客户端发送的 HTTP 请求报文的请求行 requestline 部分，并存储在字符串数组 buf 中，一个HTTP请求报文由请求行（requestline）、请求头部（header）、空行和请求数据4个部分组成，
 * 请求行由请求方法字段（get或post）、URL字段和HTTP协议版本字段3个字段组成，它们用空格分隔。如：GET /index.html HTTP/1.1。
 * 将 buf 中的方法字段存储在字符串数组method中。
 * 判断method中方法名，如果同时存在 GET 和 POST 方法，则报错，如果为 POST 方法则将 cgi 字段置1，也就是开启 cgi。
 * 将 buf 中的 URL 字段存储在字符串数组url中。
 * 如果为 GET 方法，则先判断 URL 中是否存在?字符，如果存在，将query_string指向?后的参数字段，将 URL 与参数字段分离，且开启 cgi。
 * 将分离后的 URL 存储在 path字段，默认服务器根目录为 htdocs，如果path字段以/结尾，则加上默认路径index.html，表示访问主页。判断该文件在服务器中是否存在，如果不存在该文件，读取 HTTP 请求报文的请求头，然后丢弃，返回404错误。
 * 如果存在但只是个目录名，而不是文件名，则查找该目录下的index.html文件。判断用户权限 S_IXUSR：用户可以执行、S_IXGRP：组可以执行、S_IXOTH：其它人可以执行，如果通过权限判断，则开启 cgi。
 * 最后判断 cgi 是否开启，如果未开启（不带参数 GET），则直接调用serve_file函数，输出服务器文件到浏览器，即用 HTTP 格式写到套接字上。如果 cgi 开启（带参数 GET，POST 方式，url 为可执行文件），调用execute_cgi函数执行 CGI 脚本
 * */

/*
    HTTP请求格式：
    ------------------------------------------------------------------
    | 请求方法 | 空格符 | URL | 空格符 | 协议版本 | 回车符 | 换行符 |	-->请求行
    ------------------------------------------------------------------
    | 头部字段名 | ：|    值    | 回车符 | 换行符 |                     --|
    ------------------------------------------------------------------     |
                    .................                                       |>请求头部
    ------------------------------------------------------------------     |
    | 头部字段名 | ：|    值    | 回车符 | 换行符 |                     --|
    ------------------------------------------------------------------
    | '\r' | '\n' |                                                     -->空行
    ------------------------------------------------------------------
                    .................                                   -->请求数据
    ------------------------------------------------------------------

    例：
        POST /htdocs'index.html HTTP/1.1 \r\n
        Host: www.somenet.com            \r\n
        Content-Length: 9                \r\n
        \r\n
        color=red
*/
void accept_request(void *arg)
{
    int client = (intptr_t)arg;		//建立链接的socket描述符
    char buf[1024];					//读取请求行时的数据缓存区
    size_t numchars;				//请求行字符长度
    char method[255];				//请求行中的方法名
    char url[255];					//请求行中的 URL 字段
    char path[512];					//请求行中的路径
    size_t i, j;
    struct stat st;					//文件状态信息
    //是否调用CGI的标志
    int cgi = 0;      /* becomes true if server decides this is a CGI
                       * program */
    char *query_string = NULL;		//指向 URL 中请求参数的指针

	//获取客户端发送的 HTTP 请求报文的请求行 requestline 部分，并存储在字符串数组 buf 中
    numchars = get_line(client, buf, sizeof(buf));

    i = 0; j = 0;
	//截取 buf 中的方法字段，存储在字符串数组 method 中
    while (!ISspace(buf[i]) && (i < sizeof(method) - 1))  //根据空格定位方法,就是找上述的空格符
    {
        method[i] = buf[i];
        i++;
    }
    j=i;
    method[i] = '\0';
    //printf("line:%d method=%s", __LINE__, method);

    //实现了 GET 和 POST 方法, GET 和 POST 方法不能同时存在
    if (strcasecmp(method, "GET") && strcasecmp(method, "POST"))
    {
        unimplemented(client);
        return;
    }

	//如果为 POST 方法，将 cgi 标志位置1，将开启 cgi
    if (strcasecmp(method, "POST") == 0)
	{
        cgi = 1;
	}

    i = 0;
	//截取 buf 中的 URL 字段，存储在字符串数组 url 中
    while (ISspace(buf[j]) && (j < numchars))			//跳过空白字符
	{
        j++;
	}
    while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < numchars))
    {
        url[i] = buf[j];
        i++; j++;
    }
    url[i] = '\0';

	//如果为 GET 方法
    if (strcasecmp(method, "GET") == 0)
    {
        query_string = url;								//处理URL

		//查找URL是否存在'?'
        while ((*query_string != '?') && (*query_string != '\0'))
		{
            query_string++;
		}

		//如果URL存在'?'，开启 cgi，并将 query_string 指针指向'?'后的请求参数
        if (*query_string == '?')
        {
            cgi = 1;
            *query_string = '\0';						//将 URL 与参数字段分离
            query_string++;
        }
    }

	//格式化 URL 在 path 数组，默认服务器文件根目录在 htdocs 下
    sprintf(path, "htdocs%s", url);

	//如果路径以'/'符号结尾，则加上 "index.html"，即默认访问 index
    if (path[strlen(path) - 1] == '/')
	{
        strcat(path, "index.html");
	}

	//判断请求的文件在服务器中是否存在
    if (stat(path, &st) == -1)
	{
		//如果不存在，读取 HTTP 请求报文的请求头，然后丢弃
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
		{
            numchars = get_line(client, buf, sizeof(buf));
		}

		//返回404错误
        not_found(client);
    }
    else
    {
		//如果存在，但却是个目录而不是文件，则继续拼接目录，访问该目录下的 index.html
        if ( (st.st_mode & S_IFMT) == S_IFDIR)
		{
            strcat(path, "/index.html");
		}

		//判断用户权限 S_IXUSR：用户可以执行 S_IXGRP：组可以执行 S_IXOTH：其它人可以执行
        if ( (st.st_mode & S_IXUSR) || (st.st_mode & S_IXGRP) || (st.st_mode & S_IXOTH))
		{
			//如果通过权限判断，开启 cgi
            cgi = 1;
		}

		//如果 cgi 未开启，直接输出服务器文件到浏览器
        if (!cgi)
		{
            serve_file(client, path);
		}

		//如果 cgi 开启，则执行 cgi 程序
        else
		{
            execute_cgi(client, path, method, query_string);
		}
    }

	//断开与客户端的连接
    close(client);
}

/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket */
/**********************************************************************/
void bad_request(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "<P>Your browser sent a bad request, ");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "such as a POST without a Content-Length.\r\n");
    send(client, buf, sizeof(buf), 0);
}

/**********************************************************************/
/* Put the entire contents of a file out on a socket.  This function
 * is named after the UNIX "cat" command, because it might have been
 * easier just to do something like pipe, fork, and exec("cat").
 * Parameters: the client socket descriptor
 *             FILE pointer for the file to cat */
/**********************************************************************/
void cat(int client, FILE *resource)
{
    char buf[1024];

    fgets(buf, sizeof(buf), resource);
    while (!feof(resource))
    {
        send(client, buf, strlen(buf), 0);
        fgets(buf, sizeof(buf), resource);
    }
}

/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
void cannot_execute(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
 * on value of errno, which indicates system call errors) and exit the
 * program indicating an error. */
/**********************************************************************/
void error_die(const char *sc)
{
    perror(sc);
    exit(1);
}

/**********************************************************************/
/* Execute a CGI script.  Will need to set environment variables as
 * appropriate.
 * Parameters: client socket descriptor
 *             path to the CGI script */
/**********************************************************************/

/*
 * execute_cgi 函数先初始化buf：读取请求行时的数据缓存区、cgi_output：管道名、cgi_input：管道名、pid：进程号、status：进程的状态、numchars：请求行字符长度、content_length：POST 请求内容长度。
 * 判断如果是 GET 方法，则丢弃掉 HTTP 报文的请求头，如果是 POST 方法，则需要从HTTP 报文的请求头中找出 Content-Length，将其值赋给变量content_length（转为整型），最后判断请求长度是否合法。
 * 建立两个管道，cgi_input 和 cgi_output, 并 fork 自身产生子进程。
 * 在子进程中，把 STDOUT 重定向到 cgi_outputt 的写入端，把 STDIN 重定向到 cgi_input 的读取端，关闭 cgi_input 的写入端 和 cgi_output 的读取端,
 * 目的是将父进程的读写管道重定向到子进程的标准输入和标准输出。然后设置 request_method 的环境变量,
 * 即设置基本的CGI环境变量，请求类型、参数、长度之类 ，GET 的话设置 query_string 的环境变量，POST 的话设置 content_length 的环境变量，这些环境变量都是为了给 cgi 脚本调用，接着用 execl 运行 cgi 程序。
 * 在父进程中，关闭 cgi_input 的读取端 和 cgi_output 的写入端，如果 POST 的话，把 POST 数据写入 cgi_input，已被重定向到 STDIN，读取 cgi_output 的管道输出到客户端，该管道输入是 STDOUT。接着关闭所有管道，等待子进程结束。
 * 关闭与浏览器的连接，完成了一次 HTTP 请求与回应，因为 HTTP 是无连接的。
 * */

void execute_cgi(int client, const char *path,
        const char *method, const char *query_string)
{
    char buf[1024];						//读取请求行时的数据缓存区
    int cgi_output[2];					//管道名
    int cgi_input[2];					//管道名
    pid_t pid;							//进程号
    int status;							//进程的状态
    int i;
    char c;
    int numchars = 1;					//请求行字符长度
    int content_length = -1;			//POST 请求内容长度

    buf[0] = 'A'; buf[1] = '\0';

	//如果是 GET 方法，则丢弃 HTTP 报文的请求头
    if (strcasecmp(method, "GET") == 0)
	{
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
		{
            numchars = get_line(client, buf, sizeof(buf));
		}
	}
	//如果是 POST 方法，则需要从HTTP 报文的请求头中找出 Content-Length
    else if (strcasecmp(method, "POST") == 0) /*POST*/
    {
        numchars = get_line(client, buf, sizeof(buf));
        while ((numchars > 0) && strcmp("\n", buf))
        {
			//分离 content_length
            buf[15] = '\0';
            if (strcasecmp(buf, "Content-Length:") == 0)
			{
				//读出 content_length
                content_length = atoi(&(buf[16]));
			}
            numchars = get_line(client, buf, sizeof(buf));
        }

		//如果请求长度不合法（比如根本就不是数字），那么就报错，即没有找到content_lengt
        if (content_length == -1)
		{
            bad_request(client);
            return;
        }
    }
    else/*HEAD or other*/
    {
    }

	//建立管道
    if (pipe(cgi_output) < 0)
	{
        cannot_execute(client);
        return;
    }
	//建立管道
    if (pipe(cgi_input) < 0)
	{
        cannot_execute(client);
        return;
    }
	//生成子进程
    if ( (pid = fork()) < 0 )
	{
        cannot_execute(client);
        return;
    }
	//把 HTTP 200 状态码写到套接字
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);

	//子进程调用 CGI 脚本
    if (pid == 0)  /* child: CGI script */
    {
        char meth_env[255];
        char query_env[255];
        char length_env[255];

		//将父进程的读写管道重定向到子进程的标准输入和标准输出
		//把 STDOUT 重定向到 cgi_output 的写入端，把 STDIN 重定向到 cgi_input 的读取端
		//关闭 cgi_input 的写入端 和 cgi_output 的读取端
        dup2(cgi_output[1], STDOUT);
        dup2(cgi_input[0], STDIN);
        close(cgi_output[0]);
        close(cgi_input[1]);

		//设置 request_method 的环境变量，即服务器设置，设置基本的CGI环境变量，请求类型、参数、长度之类
        sprintf(meth_env, "REQUEST_METHOD=%s", method);
        putenv(meth_env);

		//GET 方法设置 query_string 的环境变量
        if (strcasecmp(method, "GET") == 0)
		{
            sprintf(query_env, "QUERY_STRING=%s", query_string);
            putenv(query_env);
        }
		//POST 方法设置 content_length 的环境变量
        else
		{   /* POST */
            sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
            putenv(length_env);
        }
		//使用 execl 运行 cgi 程序
        execl(path, NULL);
        exit(0);
    } 
	else
	{    
		/* parent */
		//父进程中关闭 cgi_input 的读取端 和 cgi_output 的写入端
        close(cgi_output[1]);
        close(cgi_input[0]);

		//把 POST 数据写入 cgi_input，已被重定向到 STDIN，读取 cgi_output 的管道输出到客户端，该管道输入是 STDOUT
        if (strcasecmp(method, "POST") == 0)
		{
            for (i = 0; i < content_length; i++)
			{
                recv(client, &c, 1, 0);
                write(cgi_input[1], &c, 1);
            }
		}

		//父进程从输出管道里面读出所有结果，返回给客户端
        while (read(cgi_output[0], &c, 1) > 0)
		{
            send(client, &c, 1, 0);
		}

		//关闭剩余的管道
        close(cgi_output[0]);
        close(cgi_input[1]);
		//等待子进程结束
        waitpid(pid, &status, 0);
    }
}

/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
int get_line(int sock, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;

    while ((i < size - 1) && (c != '\n'))
    {
        n = recv(sock, &c, 1, 0);
        /* DEBUG printf("%02X\n", c); */
        if (n > 0)
        {
            if (c == '\r')
            {
                n = recv(sock, &c, 1, MSG_PEEK);
                /* DEBUG printf("%02X\n", c); */
                if ((n > 0) && (c == '\n'))
                    recv(sock, &c, 1, 0);
                else
                    c = '\n';
            }
            buf[i] = c;
            i++;
        }
        else
            c = '\n';
    }
    buf[i] = '\0';

    return(i);
}

/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/
void headers(int client, const char *filename)
{
    char buf[1024];
    (void)filename;  /* could use filename to determine file type */

    strcpy(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/
void not_found(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "your request because the resource specified\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "is unavailable or nonexistent.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Send a regular file to the client.  Use headers, and report
 * errors to client if they occur.
 * Parameters: a pointer to a file structure produced from the socket
 *              file descriptor
 *             the name of the file to serve */
/**********************************************************************/
void serve_file(int client, const char *filename)
{
    FILE *resource = NULL;
    int numchars = 1;
    char buf[1024];

    buf[0] = 'A'; buf[1] = '\0';
    while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
        numchars = get_line(client, buf, sizeof(buf));

    resource = fopen(filename, "r");
    if (resource == NULL)
        not_found(client);
    else
    {
        headers(client, filename);
        cat(client, resource);
    }
    fclose(resource);
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/

/*
 * startup函数先初始化httpd：套接字描述符、on：setsockopt 函数中指向选项值的缓冲区、name：服务器套接字地址结构。
 * 通过socket函数来创建一个套接字描述符，其中 PF_INET 表明我们正在使用的 32 位 IP 地址(ipv4)，SOCK_STREAM 表示这个套接字是连接的一个端点。
 * 设置服务器套接字地址结构，分别是其协议、端口和 IP 地址。
 * 通过setsockopt函数设置套接字为 SO_REUSEADDR 选项，即允许套接口和一个已在使用中的地址捆绑。
 * 将当前套接字描述符httpd绑定到对应的端口，即name中的服务器套接字地址。
 * 如果默认指定端口值为0，就会动态随机分配一个端口，通过getsockname函数获取与当前套接字相关的服务器地址，并将指定端口设置为获取到的服务器地址的端口。
 * 套接字描述符绑定完毕后，将httpd转为监听套接字描述符。
 * 返回监听套接字描述符。
 * */

int startup(u_short *port)
{
    int httpd = 0;								//定义服务器 socket 描述符
    int on = 1;
    struct sockaddr_in name;					//定义 sockaddr_in 型结构体用来绑定服务器端的ip地址和端口
    
    httpd = socket(PF_INET, SOCK_STREAM, 0);	//创建服务器端 socket, PF_INET 地址类型为 ipv4, SOCK_STREAM socket 类型，0 前面类型参数默认协议(tcp)

	//处理创建失败
    if (httpd == -1)
	{
        error_die("socket");
	}

    memset(&name, 0, sizeof(name));				//初始化结构体
    name.sin_family = AF_INET;					//地址类型 ipv4
    name.sin_port = htons(*port);				//端口转化为网络字节序（大端存储）
    name.sin_addr.s_addr = htonl(INADDR_ANY);	//本机任意可用ip地址
    //指定ip地址
    //inet_pton(AF_INET, "192.168.3.11", &name.sin_port._addr);

	//设置套接字为 SO_REUSEADDR 选项，即允许套接口和一个已在使用中的地址捆绑
    if ((setsockopt(httpd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0)
    {  
        error_die("setsockopt failed");
    }

	//将当前套接字绑定到对应的端口
    if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)  //绑定地址
	{
        error_die("bind");
	}
    
    //如果 port 为0，随机选取
    if (*port == 0)  /* if dynamically allocating a port */
    {
        socklen_t namelen = sizeof(name);

		//通过 getsockname 函数获取与当前套接字相关的地址，并将指定端口设置为获取到的地址的端口
        if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
		{
			error_die("getsockname");
		}

        *port = ntohs(name.sin_port);			//修改port
    }

    if (listen(httpd, 5) < 0)					//服务器开始监听
	{
        error_die("listen");
	}

	//printf("file:%s, line:%d, return httpd = %d", __FILE__, __LINE__, httpd);
    return(httpd);								//返回服务器socket描述符
}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
void unimplemented(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</TITLE></HEAD>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/

/*
struct sockaddr_in {
	uint16_t sin_family;			// Protocol family (always AF_INET)
	uint16_t sin_port;				// Port number in network byte order
	struct in_addr sin_addr;		// IP address in network byte order
	unsigned char sin_zero[8];		// Pad to sizeof(struct sockaddr)
}
*/

int main(void)
{
    int server_sock = -1;								//定义服务器 socket 描述符
    u_short port = 4000;								//定义服务端监听端口
    int client_sock = -1;								//定义客户端 socket 描述符
    struct sockaddr_in client_name;						//定义 sockaddr_in 型结构体，accept 阶段用来获取信息
    socklen_t  client_name_len = sizeof(client_name);	//获取客户端地址长度
    pthread_t newthread;								//定义线程 id

    server_sock = startup(&port);						//初始化服务器
    printf("httpd running on port %d\n", port);			//打印端口号

    while (1)
    {
        client_sock = accept(server_sock, (struct sockaddr *)&client_name, &client_name_len);  //调用 accept 等待客户端请求，这里 accept 处于阻塞状态,
																							   //直到有客户端连接才会返回已连接套接字描述符 client_sock
		//处理 accept 异常
        if (client_sock == -1)
		{
			error_die("accept");
		}

        //accept_request(&client_sock);

        //此时 accept 成功返回一个client_sock, 于是派生一个新线程运行 accept_request 函数去处理客户端的请求
        if (pthread_create(&newthread , NULL, (void *)accept_request, (void *)(intptr_t)client_sock) != 0)
		{
            perror("pthread_create");					//处理 pthread_create 异常
		}
    }

    close(server_sock);

    return(0);
}
