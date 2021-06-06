// Many codes in this file was borrowed from GdbConnection.cc in rr
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "dbggdbserver.h"
#include "packets.h"

#define FLNM "packets.c"

struct packet_buf
{
    uint8_t buf[PACKET_BUF_SIZE];
    int end;
} in, out;


uint8_t* inbuf_get()
{
    return in.buf;
}

int inbuf_end()
{
    return in.end;
}

int pktbuf_insert(struct packet_buf* pkt,
                   const uint8_t* buf, ssize_t len)
{
    if (pkt->end + len >= sizeof(pkt->buf))
    {
        sem_wait(&global_lock);
        print_message(DBGSHELL_MSGERRO, "pktbuf_insert", "Packet buffer overflow");
        sem_post(&global_lock);
        return -1;
    }

    memcpy(pkt->buf + pkt->end, buf, len);
    pkt->end += len;
    return 0;
}

void pktbuf_erase_head(struct packet_buf* pkt, ssize_t end)
{
    memmove(pkt->buf, pkt->buf + end, pkt->end - end);
    pkt->end -= end;
}

void inbuf_erase_head(ssize_t end)
{
    pktbuf_erase_head(&in, end);
}

void pktbuf_clear(struct packet_buf* pkt)
{
    pkt->end = 0;
}

static int poll_socket(int connfd, short events)
{
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = connfd;
    pfd.events = events;
    int ret = poll(&pfd, 1, -1);

    if (ret < 0)
    {
        sem_wait(&global_lock);
        print_message(DBGSHELL_MSGERRO, "poll_socket", "Failed to call poll()");
        print_sys_error(DBGSHELL_MSGERRO, "poll_socket", "poll");
        sem_post(&global_lock);
    }

    return ret;
}

static int poll_incoming(int connfd)
{
    return poll_socket(connfd, POLLIN);
}

static int poll_outgoing(int connfd)
{
    return poll_socket(connfd, POLLOUT);
}

int read_data_once()
{
    int ret;
    ssize_t nread;
    uint8_t buf[4096];

    ret = poll_incoming(connfd);
    if (ret < 0)
    {
        return -1;
    }

    nread = read(connfd, buf, sizeof(buf));

    if (nread <= 0)
    {
        sem_wait(&global_lock);
        print_message(DBGSHELL_MSGERRO, "read_data_once", "Connection closed");
        print_sys_error(DBGSHELL_MSGERRO, "read_data_once", "read");
        sem_post(&global_lock);
        return -1;
    }

    return pktbuf_insert(&in, buf, nread);
}

int write_flush()
{
    size_t write_index = 0;
    int ret;

    while (write_index < out.end)
    {
        ssize_t nwritten;
        ret = poll_outgoing(connfd);
        if (ret < 0)
            return ret;

        nwritten = write(connfd, out.buf + write_index,
                         out.end - write_index);

        if (nwritten < 0)
        {
            sem_wait(&global_lock);
            print_message(DBGSHELL_MSGERRO, "write_flush", "Write error");
            print_sys_error(DBGSHELL_MSGERRO, "write_flush", "write");
            sem_post(&global_lock);
            return -1;
        }

        write_index += nwritten;
    }

    pktbuf_clear(&out);
    return 0;
}

int write_data_raw(const uint8_t* data, ssize_t len)
{
    return pktbuf_insert(&out, data, len);
}

int write_hex(unsigned long hex)
{
    char buf[32];
    size_t len;
    len = snprintf(buf, sizeof(buf) - 1, "%02lx", hex);
    return write_data_raw((uint8_t*)buf, len);
}

int write_packet_bytes(const uint8_t* data,
                        size_t num_bytes)
{
    uint8_t checksum;
    size_t i;
    int ret;

    ret = write_data_raw((uint8_t *)"$", 1);
    if (ret < 0)
        return ret;

    for (i = 0, checksum = 0; i < num_bytes; ++i)
        checksum += data[i];

    ret = write_data_raw((uint8_t*)data, num_bytes);
    if (ret < 0)
        return ret;
    ret = write_data_raw((uint8_t*)"#", 1);
    if (ret < 0)
        return ret;
    ret = write_hex(checksum);
    return ret;
}

int write_packet(const char* data)
{
    int ret = write_packet_bytes((const uint8_t *)data, strlen(data));
    debug_printf("gdb out <- (%s)", out.buf);
    return ret;
}

int write_binary_packet(const char* pfx,
                         const uint8_t* data, ssize_t num_bytes)
{
    uint8_t* buf;
    ssize_t pfx_num_chars = strlen(pfx);
    ssize_t buf_num_bytes = 0;
    int i, ret;
    buf = malloc(2 * num_bytes + pfx_num_chars);
    memcpy(buf, pfx, pfx_num_chars);
    buf_num_bytes += pfx_num_chars;

    for (i = 0; i < num_bytes; ++i)
    {
        uint8_t b = data[i];

        switch (b)
        {
        case '#':
        case '$':
        case '}':
        case '*':
            buf[buf_num_bytes++] = '}';
            buf[buf_num_bytes++] = b ^ 0x20;
            break;

        default:
            buf[buf_num_bytes++] = b;
            break;
        }
    }

    ret = write_packet_bytes(buf, buf_num_bytes);
    free(buf);
    return ret;
}

bool skip_to_packet_start()
{
    ssize_t end = -1;

    for (size_t i = 0; i < in.end; ++i)
        if (in.buf[i] == '$' || in.buf[i] == INTERRUPT_CHAR)
        {
            end = i;
            break;
        }

    if (end < 0)
    {
        pktbuf_clear(&in);
        return false;
    }

    pktbuf_erase_head(&in, end);
    assert(1 <= in.end);
    assert('$' == in.buf[0] || INTERRUPT_CHAR == in.buf[0]);
    return true;
}

int read_packet()
{
    int ret;

    while (!skip_to_packet_start())
    {
        ret = read_data_once();
        if (ret < 0)
            return ret;
    }

    debug_printf("gdb in -> (%s)", in.buf);

    ret = write_data_raw((uint8_t*)"+", 1);
    if (ret < 0)
        return ret;

    return write_flush();
}

static int async_io_enabled;
void (*request_interrupt)(void);

void enable_async_notification(int fd)
{
#if defined(F_SETFL) && defined(FASYNC)
    int save_fcntl_flags;
    save_fcntl_flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, save_fcntl_flags | FASYNC);
#if defined(F_SETOWN)
    fcntl(fd, F_SETOWN, getpid());
#endif
#endif
}

static void input_interrupt(int unused)
{
    if (async_io_enabled)
    {
        int nread;
        char buf;
        nread = read(connfd, &buf, 1);
        // assert(nread == 1 && buf == INTERRUPT_CHAR);
        if (nread != 1 || buf != INTERRUPT_CHAR)
        {
            debug_printf("input_interrupt receive unusual with nread %d buf %d", nread, buf);
        }

        request_interrupt();
    }
}

static void block_unblock_async_io(int block)
{
    sigset_t sigio_set;
    sigemptyset(&sigio_set);
    sigaddset(&sigio_set, SIGIO);
    sigprocmask(block ? SIG_BLOCK : SIG_UNBLOCK, &sigio_set,
                NULL);
}

void enable_async_io(void)
{
    if (async_io_enabled)
        return;

    block_unblock_async_io(0);
    async_io_enabled = 1;
}

void disable_async_io(void)
{
    if (!async_io_enabled)
        return;

    block_unblock_async_io(1);
    async_io_enabled = 0;
}

void initialize_async_io(void (*intr_func)(void))
{
    request_interrupt = intr_func;
    async_io_enabled = 1;
    disable_async_io();
    signal(SIGIO, input_interrupt);
}
