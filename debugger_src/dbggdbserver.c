/**
 * Copyright 2021 浮枕
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "dbggdbserver.h"


#define FLNM "dbggdbserver.c"


uint8_t g_gdbserver_running = 0;
uint16_t g_gdbserver_port = 10000;
int sockfd, connfd;


static void pthread_cleanup_dbggdbserver(void* arg)
{
    debug_printf("pthread_cleanup_dbggdbserver() called");
    close(sockfd);
    pktbuf_clear(&in);
    pktbuf_clear(&out);
}

uint64_t str_smart_realloc(char **pstr, uint64_t last_pos, uint64_t once_sz, char stop)
{
    if (!*pstr)
    {
        *pstr = (char *)malloc(sizeof(char) * once_sz);
        if (*pstr)
        {
            last_pos = once_sz;
            bzero(*pstr, sizeof(char) * once_sz);
        }
        else
            last_pos = 0;
    }
    else
    {
        uint64_t prev_pos = last_pos - once_sz;
        for (; prev_pos < last_pos; prev_pos++)
        {
            if ((*pstr)[prev_pos] == stop) break;
        }

        if (prev_pos == last_pos)
        {
            last_pos += once_sz;
            *pstr = (char *)realloc(*pstr, last_pos);
            if (*pstr)
                bzero((*pstr) + prev_pos, sizeof(char) * once_sz);
            else
                last_pos = 0;
        }
    }

    return last_pos;
}

#define RECV_ONCE_SZ 4096
void recv_cmd_dbggdbserver()
{
    char* recv_buff;
    uint64_t recv_len;
    ssize_t read_sz;

    while (1)
    {
        recv_len = 0;
        recv_buff = NULL;

        while (str_smart_realloc(&recv_buff, recv_len, RECV_ONCE_SZ, '\0') > recv_len)
        {
            read_sz = read(connfd, recv_buff + recv_len, RECV_ONCE_SZ);
            if (read_sz < 0)
            {
                sem_wait(&global_lock);
                print_sys_error(DBGSHELL_MSGERRO, "recv_cmd_dbggdbserver", "read");
                sem_post(&global_lock);
                goto END;
            }
            else if (read_sz == 0)
            {
                sem_wait(&global_lock);
                print_message(DBGSHELL_MSGWARN, "recv_cmd_dbggdbserver", "Connection closed");
                sem_post(&global_lock);
                goto END;
            }

            recv_len += RECV_ONCE_SZ;
        }

        recv_len = strlen(recv_buff);
        debug_printf("(%s)", recv_buff);

        if (write(connfd, "+$#00", sizeof("+$#00")) <= 0)
        {
            sem_wait(&global_lock);
            print_sys_error(DBGSHELL_MSGERRO, "recv_cmd_dbggdbserver", "write");
            sem_post(&global_lock);
        }

        free(recv_buff);
    }

END:
    if (recv_buff)
        free(recv_buff);
    return;
}


void* start_dbggdbserver(void* arg)
{
    socklen_t socklen;
    struct sockaddr_in server_addr, client_addr;
    int enable = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0)
    {
        sem_wait(&global_lock);
        print_message(DBGSHELL_MSGERRO, "start_dbggdbserver", "Exec socket() failed with %d", sockfd);
        print_sys_error(DBGSHELL_MSGERRO, "start_dbggdbserver", "socket");
        g_gdbserver_running = 0;
        sem_post(&global_lock);
        return NULL;
    }

    bzero(&server_addr, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htons(INADDR_ANY);
    server_addr.sin_port = htons(g_gdbserver_port);

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    {
        sem_wait(&global_lock);
        print_sys_error(DBGSHELL_MSGERRO, "start_dbggdbserver", "setsockopt");
        g_gdbserver_running = 0;
        sem_post(&global_lock);
        return NULL;
    }

    pthread_cleanup_push(pthread_cleanup_dbggdbserver, NULL);

    if ((bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr))) != 0)
    {
        sem_wait(&global_lock);
        print_sys_error(DBGSHELL_MSGERRO, "start_dbggdbserver", "bind");
        g_gdbserver_running = 0;
        sem_post(&global_lock);
        return NULL;
    }

    if ((listen(sockfd, 5)) != 0)
    {
        sem_wait(&global_lock);
        print_sys_error(DBGSHELL_MSGERRO, "start_dbggdbserver", "listen");
        g_gdbserver_running = 0;
        sem_post(&global_lock);
        return NULL;
    }

    socklen = sizeof(client_addr);

    while (1)
    {
        pktbuf_clear(&in);
        pktbuf_clear(&out);
        connfd = accept(sockfd, (struct sockaddr *)&client_addr, &socklen);
        if (connfd < 0)
        {
            sem_wait(&global_lock);
            print_message(DBGSHELL_MSGERRO, "start_dbggdbserver", "Exec accept() failed with %d", connfd);
            print_sys_error(DBGSHELL_MSGERRO, "start_dbggdbserver", "accept");
            sem_post(&global_lock);
            goto END;
        }

        initialize_async_io(sigint_handler);
        setsockopt(connfd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
        setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
        enable_async_notification(connfd);

        launch_server();
        // recv_cmd_dbggdbserver();

        close(connfd);
        pktbuf_clear(&in);
        pktbuf_clear(&out);
    }

END:
    sem_wait(&global_lock);
    pthread_cleanup_pop(1);
    g_gdbserver_running = 0;
    sem_post(&global_lock);
    return NULL;
}



