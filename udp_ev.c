/*
 * Description: udp event
 *     History: damonyang@tencent.com, 2013/11/25, create
 */

# include <stdlib.h>
# include <string.h>
# include <strings.h>
# include <stdarg.h>
# include <assert.h>
# include <errno.h>
# include <limits.h>
# include <time.h>
# include <arpa/inet.h>
# include <sys/socket.h>
# include <unistd.h>
# include <fcntl.h>

# include "event2/event.h"
# include "event2/event_struct.h"
# include "udp_ev.h"

static struct event_base *ue_base;
static ue_handle_loop_cb *ue_loop;
static ue_handle_log_cb  *ue_log;

enum
{
    UE_TYPE_SOCK,
    UE_TYPE_CRON,
};

struct ue_info
{
    int                 what;
    struct ue_context   context;
    struct event        *ev;

    ue_handle_udp_cb    *handle_udp;
    ue_handle_cron_cb   *handle_cron;

    struct ue_info      *next;
};

struct ue_info *ue_info_list_head;

static int ue_loga(int severity, char const *fmt, ...)
{
    if (ue_log == NULL)
        return 0;

    char msg[32 * 1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    ue_log(severity, msg);

    return 0;
}

static int ue_set_nonblocking(int sockfd)
{
    int flags;

    flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0)
    {
        return flags;
    }

    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

int ue_addr_assign(struct sockaddr_in *addr, char const *ip, int port)
{
    bzero(addr, sizeof(*addr));
    addr->sin_family = AF_INET;
    if (ip)
    {
        if (inet_aton(ip, &addr->sin_addr) == 0)
            return -__LINE__;
    }
    else
    {
        addr->sin_addr.s_addr = htonl(INADDR_ANY);
    }

    addr->sin_port = htons((uint16_t)port);

    return 0;
}

static int ue_create_socket(char const *ip, int port)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -__LINE__;

    if (ue_set_nonblocking(sockfd) < 0)
    {
        close(sockfd);
        return -__LINE__;
    }

    if (ip == NULL && port == 0)
        return sockfd;

    struct sockaddr_in local_addr;
    if (ue_addr_assign(&local_addr, ip, port) < 0)
    {
        close(sockfd);
        return -__LINE__;
    }

    if (bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
    {
        close(sockfd);
        return -__LINE__;
    }

    return sockfd;
}

static void ue_handle_read(evutil_socket_t fd, short what, void *arg)
{
    struct ue_info *ui = (struct ue_info *)arg;
    char recv_buf[UE_BUFFER_SIZE];
    socklen_t addr_len = sizeof(ui->context.client_addr);
    int ret;

    ret = recvfrom((int)fd, recv_buf, sizeof(recv_buf), 0, \
            (struct sockaddr *)&ui->context.client_addr, &addr_len);
    if (ret < 0)
    {
        int severity = UE_LOG_ERROR;
        if (errno == EAGAIN)
            severity = UE_LOG_WARN;
        ue_loga(severity, "name: %d, socket fd: %d, recvfrom fail: %m", \
                ui->context.name, ui->context.sockfd);

        return;
    }

    if (ue_loop)
        ue_loop();

    ui->context.pkg     = recv_buf;
    ui->context.pkg_len = ret;

    ret = ui->handle_udp(&ui->context);
    if (ret < 0)
    {
        ue_loga(UE_LOG_ERROR, "name: %d, socket fd: %d, handle_udp fail: %d", \
                ui->context.name, ui->context.sockfd, ret);
    }

    return;
}

static struct ue_info *ue_find_by_name(int name)
{
    struct ue_info *curr = ue_info_list_head;
    while (curr)
    {
        if (curr->context.name == name)
            return curr;

        curr = curr->next;
    }

    return NULL;
}

# ifdef DEBUG
int ue_trace(void)
{
    int n = 0;
    struct ue_info *curr = ue_info_list_head;
    while (curr)
    {
        ue_loga(UE_LOG_INFO, "what: %d, name: %d, sockfd: %d, ev: %p, udp: %p, cron: %p, next: %p", \
                curr->what, curr->context.name, curr->context.sockfd, curr->ev, \
                curr->handle_udp, curr->handle_cron, curr->next);

        curr = curr->next;
        n += 1;
    }

    ue_loga(UE_LOG_INFO, "ue number: %d", n);

    return 0;
}
# endif

static int ue_list_add_tail(struct ue_info *ui)
{
    if (ue_info_list_head == NULL)
    {
        ue_info_list_head = ui;
        return 0;
    }

    struct ue_info *curr = ue_info_list_head;
    while (curr->next)
    {
        curr = curr->next;
    }

    ui->next = NULL;
    curr->next = ui;

    return 0;
}

static int ue_init_base(void)
{
    ue_base = event_base_new();
    if (ue_base == NULL)
        return -__LINE__;

    return 0;
}

int ue_create(int name, char const *ip, int port, ue_handle_udp_cb *handler)
{
    if (ue_find_by_name(name))
        return -__LINE__;

    if (port <= 0 || handler == NULL)
        return -__LINE__;

    if (ue_base == NULL && ue_init_base() < 0)
        return -__LINE__;

    int sockfd = ue_create_socket(ip, port);
    if (sockfd < 0)
        return -__LINE__;

    struct ue_info *ui = calloc(1, sizeof(*ui));
    if (ui == NULL)
        return -__LINE__;

    struct event *ev = event_new(ue_base, sockfd, EV_READ | EV_PERSIST, ue_handle_read, ui);
    if (ev == NULL)
    {
        close(sockfd);
        free(ui);
        return -__LINE__;
    }

    int ret = event_add(ev, NULL);
    if (ret < 0)
    {
        close(sockfd);
        event_free(ev);
        free(ui);
        return -__LINE__;
    }

    ui->context.name        = name;
    ui->what                = UE_TYPE_SOCK;
    ui->context.sockfd      = sockfd;
    ui->context.create_time = time(NULL);
    ui->ev                  = ev;
    ui->handle_udp          = handler;

    ue_list_add_tail(ui);

    return 0;
}

int ue_set_log_callback(ue_handle_log_cb *cb)
{
    ue_log = cb;
    event_set_log_callback(cb);

    return 0;
}

int ue_run(ue_handle_loop_cb *loop)
{
    if (ue_base == NULL && ue_init_base() < 0)
        return -__LINE__;

    ue_loop = loop;
    return event_base_loop(ue_base, 0);
}

int ue_send(int name, struct sockaddr_in *addr, void *pkg, size_t pkg_len)
{
    if (addr == NULL || pkg == NULL || pkg_len <= 0)
        return -__LINE__;

    struct ue_info *ui = ue_find_by_name(name);
    if (ui == NULL)
        return -__LINE__;

    int ret = sendto(ui->context.sockfd, pkg, pkg_len, 0, \
            (struct sockaddr *)addr, (socklen_t)sizeof(*addr));
    if (ret < 0)
        return -__LINE__;

    return 0;
}

int ue_exit(void)
{
    if (ue_base == NULL)
        return 0;

    return event_base_loopexit(ue_base, NULL);
}

struct ue_context *ue_create_context(char const *ip, int port)
{
    if (port < 0)
        return NULL;

    int sockfd = ue_create_socket(ip, port);
    if (sockfd < 0)
        return NULL;

    struct ue_context *uc = (struct ue_context *)calloc(1, sizeof(*uc));
    if (uc == NULL)
        return NULL;

    uc->sockfd = sockfd;
    uc->create_time = time(NULL);

    return uc;
}

int ue_send_by_context(struct ue_context *uc, struct sockaddr_in *addr, void *pkg, size_t pkg_len)
{
    if (uc == NULL || addr == NULL || pkg == NULL || pkg_len == 0)
        return -__LINE__;

    int ret = sendto(uc->sockfd, pkg, pkg_len, 0, (struct sockaddr *)addr, sizeof(*addr));
    if (ret < 0)
        return -__LINE__;

    return 0;
}

struct ue_context_arg
{
    struct ue_context *context;
    void              *buf;
    size_t            buf_size;
    int               pkg_len;
    int               timeout;
};

static void ue_handle_read_with_timeout(evutil_socket_t fd, short what, void *arg)
{
    struct ue_context_arg *ua = (struct ue_context_arg *)arg;
    int ret = 0;
    socklen_t addr_len = sizeof(ua->context->client_addr);

    switch (what)
    {
    case EV_TIMEOUT:
        ua->timeout = 1;
        break;
    case EV_READ:
        ret = recvfrom(fd, ua->buf, ua->buf_size, 0, \
                (struct sockaddr *)&ua->context->client_addr, &addr_len);
        if (ret > 0)
            ua->pkg_len = ret;
        break;
    }
}

int ue_recv_by_context(struct ue_context *uc, void *buf, size_t buf_size, struct timeval *timeout)
{
    if (uc == NULL || buf == NULL)
        return -__LINE__;

    static struct event_base *base;
    if (base == NULL)
    {
        base = event_base_new();
        if (base == NULL)
            return -__LINE__;
    }

    struct event read_event;
    struct ue_context_arg arg;
    memset(&arg, 0, sizeof(arg));
    arg.context  = uc;
    arg.buf      = buf;
    arg.buf_size = buf_size;

    event_assign(&read_event, base, EV_READ | EV_TIMEOUT, \
            uc->sockfd, ue_handle_read_with_timeout, &arg);

    int ret;
    ret = event_add(&read_event, timeout);
    if (ret < 0)
        return -__LINE__;
    
    ret = event_base_loop(base, EVLOOP_ONCE);
    if (ret < 0)
        return -__LINE__;

    if (arg.timeout)
        return 0;

    if (arg.timeout == 0 && arg.pkg_len == 0)
        return -__LINE__;

    uc->pkg     = buf;
    uc->pkg_len = arg.pkg_len;

    return 1;
}

static void ue_handle_cron(evutil_socket_t fd, short what, void *arg)
{
    struct ue_info *ui = (struct ue_info *)arg;
    ui->handle_cron();
}

int ue_cron(struct timeval *interval, ue_handle_cron_cb *cron)
{
    if (interval == NULL || cron == NULL)
        return -__LINE__;

    if (ue_base == NULL && ue_init_base() < 0)
        return -__LINE__;

    struct ue_info *ui = calloc(1, sizeof(*ui));
    if (ui == NULL)
        return -__LINE__;

    struct event *ev = event_new(ue_base, -1, EV_TIMEOUT | EV_PERSIST, ue_handle_cron, ui);
    if (ev == NULL)
    {
        free(ui);
        return -__LINE__;
    }

    int ret = event_add(ev, interval);
    if (ret < 0)
    {
        free(ui);
        event_free(ev);
        return -__LINE__;
    }

    ui->what        = UE_TYPE_CRON;
    ui->handle_cron = cron;

    return 0;
}

struct session_cache
{
    size_t block_size;
    size_t free_total;
    size_t free_curr;
    void   **free_arr;
};

# define SESSION_CACHE_INIT_POOL_SIZE 64

static struct session_cache *session_cache_create(size_t block_size)
{
    assert(block_size > 0);
    struct session_cache *cache = calloc(1, sizeof(*cache));
    if (cache == NULL)
        return NULL;

    cache->free_arr = calloc(SESSION_CACHE_INIT_POOL_SIZE, sizeof(void *));
    if (cache->free_arr == NULL)
    {
        free(cache);
        return NULL;
    }

    cache->block_size = block_size;
    cache->free_total = SESSION_CACHE_INIT_POOL_SIZE;

    return cache;
}

static void session_cache_destory(struct session_cache *cache)
{
    size_t i;
    for (i = 0; i < cache->free_total; ++i)
        free(cache->free_arr[i]);

    free(cache->free_arr);
    free(cache);
}

static void *session_cache_alloc(struct session_cache *cache)
{
    if (cache->free_curr > 0)
        return cache->free_arr[--cache->free_curr];

    return malloc(cache->block_size);
}

static void session_cache_free(struct session_cache *cache, void *obj)
{
    if (cache->free_curr < cache->free_total)
    {
        cache->free_arr[cache->free_curr++] = obj;
    }
    else
    {
        size_t new_total = cache->free_total * 2;
        void **new_free  = realloc(cache->free_arr, new_total * sizeof(void *));
        if (new_free != NULL)
        {
            cache->free_total = new_total;
            cache->free_arr   = new_free;
            cache->free_arr[cache->free_curr++] = obj;
        }
        else
        {
            free(obj);
        }
    }
}

struct ue_timer_context
{
    struct ue_timer      ut;
    struct session_cache *cache;
    struct timeval       event_timeout;
    ue_timeout_cb        *timeout_callback;
    size_t               number;
};

struct ue_session_node
{
    struct event            ev;
    struct ue_session_node  *next;
    struct ue_timer_context *context;
    uint32_t                sequence;
    char                    session[];
};

# define SESSION_HASH_TABLE_SIZE 100000
static struct ue_session_node *session_hash_table[SESSION_HASH_TABLE_SIZE];
static uint32_t                session_hash_sequence;

static uint32_t session_hash_sequence_generate(void)
{
    if (session_hash_sequence == 0)
        session_hash_sequence += 1;
    
    return session_hash_sequence++;
}

static uint32_t session_hash_put(struct ue_session_node *node)
{
    uint32_t sequence = session_hash_sequence_generate();
    uint32_t index = sequence % SESSION_HASH_TABLE_SIZE;
    if (session_hash_table[index] == NULL)
        session_hash_table[index] = node;
    else
    {
        struct ue_session_node *curr = session_hash_table[index];
        while (curr->next != NULL)
            curr = curr->next;
        curr->next = node;
    }

    return sequence;
}

static struct ue_session_node *session_hash_get(uint32_t sequence)
{
    uint32_t index = sequence % SESSION_HASH_TABLE_SIZE;
    if (session_hash_table[index])
    {
        struct ue_session_node *curr = session_hash_table[index];
        while (curr)
        {
            if (curr->sequence == sequence)
                return curr;
            curr = curr->next;
        }
    }

    return NULL;
}

static void session_hash_del(struct ue_session_node *node)
{
    assert(node != NULL);
    uint32_t index = node->sequence % SESSION_HASH_TABLE_SIZE;
    if (session_hash_table[index] == NULL)
        return;

    if (session_hash_table[index] == node)
    {
        session_hash_table[index] = node->next;
        return;
    }

    struct ue_session_node *curr = session_hash_table[index];
    while (curr->next)
    {
        if (curr->next == node)
        {
            curr->next = node->next;
            return;
        }
        curr = curr->next;
    }
}

struct ue_timer *ue_timer_create(struct timeval *timeout, \
        size_t session_size, ue_timeout_cb *timeout_callback)
{
    if (timeout == NULL || session_size == 0)
        return NULL;

    if (ue_base == NULL && ue_init_base() < 0)
        return NULL;

    struct ue_timer_context *context = calloc(1, sizeof(*context));
    if (context == NULL)
        return NULL;

    context->cache = session_cache_create(sizeof(struct ue_session_node) + session_size);
    if (context->cache == NULL)
    {
        free(context);
        return NULL;
    }

    const struct timeval *ev_out = event_base_init_common_timeout(ue_base, timeout);
    if (ev_out == NULL)
    {
        session_cache_destory(context->cache);
        free(context);
        return NULL;
    }

    memcpy(&context->event_timeout, ev_out, sizeof(*ev_out));
    memcpy(&context->ut.timeout, timeout, sizeof(*timeout));

    context->ut.session_size  = session_size;
    context->timeout_callback = timeout_callback;

    return &context->ut;
}

static void ue_timer_del_inner(struct ue_session_node *node);

static void ue_handle_session_timeout(evutil_socket_t fd, short what, void *arg)
{
    struct ue_session_node *node = (struct ue_session_node *)arg;
    node->context->timeout_callback(node->session);
    ue_timer_del_inner(node);
}

void *ue_timer_add(struct ue_timer *ut, void *session, uint32_t *sequence)
{
    if (ut == NULL || sequence == NULL)
        return NULL;
    struct ue_timer_context *context = (struct ue_timer_context *)ut;

    struct ue_session_node *node = session_cache_alloc(context->cache);
    if (node == NULL)
        return NULL;

    if (event_assign(&node->ev, ue_base, -1, EV_TIMEOUT, \
                ue_handle_session_timeout, node) < 0)
    {
        session_cache_free(context->cache, node);
        return NULL;
    }

    if (event_add(&node->ev, &context->event_timeout) < 0)
    {
        session_cache_free(context->cache, node);
        return NULL;
    }

    node->next    = NULL;
    node->context = context;

    node->sequence = session_hash_put(node);
    *sequence = node->sequence;

    if (session)
        memcpy(node->session, session, context->ut.session_size);
    else
        memset(node->session, 0, context->ut.session_size);

    context->number += 1;

    return node->session;
}

void *ue_timer_get(uint32_t sequence)
{
    if (sequence == 0)
        return NULL;

    struct ue_session_node *node = session_hash_get(sequence);
    if (node == NULL)
        return NULL;

    return node->session;
}

static void ue_timer_del_inner(struct ue_session_node *node)
{
    session_hash_del(node);
    session_cache_free(node->context->cache, node);
    node->context->number -= 1;
}

void ue_timer_del(uint32_t sequence)
{
    if (sequence == 0)
        return;

    struct ue_session_node *node = session_hash_get(sequence);
    if (node == NULL)
        return;

    ue_timer_del_inner(node);
    event_del(&node->ev);
}

size_t ue_timer_num(struct ue_timer *ut)
{
    return ((struct ue_timer_context *)ut)->number;
}

uint32_t ue_timer_sequence(void *session)
{
    struct ue_session_node *node = (struct ue_session_node *)((char *)session - \
            offsetof(struct ue_session_node, session));

    return node->sequence;
}

struct ue_timer *ue_timer_which(void *session)
{
    struct ue_session_node *node = (struct ue_session_node *)((char *)session - \
            offsetof(struct ue_session_node, session));

    return &node->context->ut;
}

