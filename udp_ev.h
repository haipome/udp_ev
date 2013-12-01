/*
 * Description: udp event
 *     History: damonyang@tencent.com, 2013/11/25, create
 */

# pragma once

# include <stddef.h>
# include <stdint.h>
# include <sys/time.h>
# include <netinet/in.h>
# include <stdint.h>

# define UE_BUFFER_SIZE UINT16_MAX

struct ue_context
{
    int                 name;
    int                 sockfd;
    time_t              create_time;
    struct sockaddr_in  client_addr;
    void                *pkg;
    size_t              pkg_len;
};

typedef int ue_handle_udp_cb(struct ue_context *uc);
int ue_create(int name, char const *ip, int port, ue_handle_udp_cb *handler);

# ifdef DEBUG
int ue_trace(void);
# endif

enum
{
    UE_LOG_INFO,
    UE_LOG_WARN,
    UE_LOG_ERROR,
};

typedef void ue_handle_log_cb(int severity, char const *msg);
int ue_set_log_callback(ue_handle_log_cb *cb);

typedef void ue_handle_loop_cb(void);
int ue_run(ue_handle_loop_cb *loop);

int ue_send(int name, struct sockaddr_in *addr, void *pkg, size_t pkg_len);

int ue_exit(void);

int ue_addr_assign(struct sockaddr_in *addr, char const *ip, int port);
struct ue_context *ue_create_context(char const *ip, int port);
int ue_send_by_context(struct ue_context *uc, struct sockaddr_in *addr, void *pkg, size_t pkg_len);
int ue_recv_by_context(struct ue_context *uc, void *buf, size_t buf_size, struct timeval *timeout);

typedef void ue_handle_cron_cb(void);
int ue_cron(struct timeval *interval, ue_handle_cron_cb *cron);

struct ue_timer
{
    struct timeval  timeout;
    size_t          session_size;
};

typedef void ue_timeout_cb(void *session);

struct ue_timer *ue_timer_create(struct timeval *timeout, \
        size_t session_size, ue_timeout_cb *timeout_callback);

void *ue_timer_add(struct ue_timer *ut, void *session, uint32_t *sequence);
void *ue_timer_get(uint32_t sequence);
void  ue_timer_del(uint32_t sequence);

size_t ue_timer_num(struct ue_timer *ut);

uint32_t ue_timer_sequence(void *session);
struct ue_timer *ue_timer_which(void *session);

