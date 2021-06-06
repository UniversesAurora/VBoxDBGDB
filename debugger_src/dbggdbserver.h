// Copyright 2021 浮枕
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
