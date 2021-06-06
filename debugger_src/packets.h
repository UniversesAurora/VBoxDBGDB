#ifndef PACKETS_H
#define PACKETS_H

#include <stdint.h>

#define PACKET_BUF_SIZE 0x16000

static const char INTERRUPT_CHAR = '\x03';
extern struct packet_buf in, out;

uint8_t* inbuf_get();
int inbuf_end();
void inbuf_erase_head(ssize_t end);
void pktbuf_clear(struct packet_buf *pkt);
int write_flush();
int write_packet(const char* data);
int write_binary_packet(const char* pfx,
                         const uint8_t* data, ssize_t num_bytes);
int read_packet();
void enable_async_io(void);
void disable_async_io(void);
void initialize_async_io(void (*intr_func)(void));
void enable_async_notification(int fd);

#endif /* PACKETS_H */
