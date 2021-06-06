#ifndef SDK_BINDINGS_C_SERVER_DBGGDBSERVER
#define SDK_BINDINGS_C_SERVER_DBGGDBSERVER

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "dbgshell.h"
#include "packets.h"
#include "gdbserver.h"

extern uint8_t g_gdbserver_running;
extern uint16_t g_gdbserver_port;
extern int sockfd, connfd;

void *start_dbggdbserver(void *arg);

#endif /* SDK_BINDINGS_C_SERVER_DBGGDBSERVER */
