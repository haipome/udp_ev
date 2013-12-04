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

/*
 * udp_ev 基于 libevent 实现了一些简单有用的 UDP 编程接口，包括：
 * 1、服务端接口
 * 2、客户端接口
 * 3、定时任务
 * 4、Timer（带有超时机制的 Session）
 */

/* 收包 buffer 大小 */
# define UE_BUFFER_SIZE UINT16_MAX

/* socket 上下文 */
struct ue_context
{
    int                 name;
    int                 sockfd;
    time_t              create_time;
    struct sockaddr_in  client_addr;
    void                *pkg;
    size_t              pkg_len;
};

/************************服务端接口*****************************/

/* UDP 包处理回调函数 */
typedef int ue_handle_udp_cb(struct ue_context *uc);

/*
 * 创建一个 socket 并绑定到置顶 IP 和 端口
 * 参数：
 *      name: socket 标识符，任意 int 型数字，不能重复，用于唯一标识一个端口
 *      ip  : IP 地址，如果为 NULL，则绑定到 INADDR_ANY
 *      port: 绑定的端口，不能为 0
 *      handler: UDP 包处理回调函数，成功收包后调用
 *
 * 返回负值表示失败
 */
int ue_create(int name, char const *ip, int port, ue_handle_udp_cb *handler);

/* 打印出所有打开的 socket，可以用于调试 */
int ue_trace(void);

enum
{
    UE_LOG_INFO,
    UE_LOG_WARN,
    UE_LOG_ERROR,
};

/* 
 * 日志回调函数
 * severity 表示日志严重级别，共分为 3 级：UE_LOG_INFO / UE_LOG_WARN / UE_LOG_ERROR
 * msg 为日志内容
 */
typedef void ue_handle_log_cb(int severity, char const *msg);

/* 设置日志回调函数，如果不设置，udp_ev 不会打印任何错误日志 */
int ue_set_log_callback(ue_handle_log_cb *cb);

/* 收包回调函数 */
typedef void ue_handle_loop_cb(void);

/*
 * 运行服务，进入主循环，直到 ue_exit 被调用为止
 * loop 如果不为 NULL，每次成功收到 UDP 包后，调用 UDP 包处理回调函数之前执行
 * 失败返回负值
 */
int ue_run(ue_handle_loop_cb *loop);

/*
 * 发送一个 UDP 包
 * 参数：
 *      name: socket 标识符
 *      addr: 发送的地址
 *      pkg : 待发送的 UDP 包的起始地址
 *      pkg_len: 待发送的 UDP 包长度
 *
 * 失败返回负值
 */
int ue_send(int name, struct sockaddr_in *addr, void *pkg, size_t pkg_len);

/* 退出服务，可以在信号处理函数中调用 */
int ue_exit(void);

/* 在第一次调用后的指定时间后退出，函数立即返回 */
int ue_exit_later(struct timeval *tv);

/******************************************************************/


/****************************客户端接口****************************/

/* 
 * 给 struct sockaddr_in 类型结构体赋值
 * 如果 ip 为 NULL，则 ip 值为 INADDR_ANY
 * 失败返回负值
 */
int ue_addr_assign(struct sockaddr_in *addr, char const *ip, int port);

/*
 * 创建一个 socket，并绑定到置顶 ip 和 端口
 * 如果 ip 为 NULL，则绑定到 INADDR_ANY
 * 如果 port 为 0，则由操作系统指定一个端口
 * 失败返回 NULL
 */
struct ue_context *ue_create_context(char const *ip, int port);

/*
 * 通过指定的 socket 发送一个 UDP 包
 * 失败返回负值
 */
int ue_send_by_context(struct ue_context *uc, struct sockaddr_in *addr, void *pkg, size_t pkg_len);

/*
 * 从指定 socket 收取一个 UDP 包，带有超时功能
 * 参数：
 *      uc  : socket
 *      buf : 收到缓冲区起始地址
 *      buf_size: 收包缓冲区长度
 *      timeout : 超时时间，如果为 NULL 则不超时
 * 返回值：
 *      <  0 : 失败
 *      == 0 : 超时
 *      >  0 : 成功，收到的包和包成保存在 uc 中
 */
int ue_recv_by_context(struct ue_context *uc, void *buf, size_t buf_size, struct timeval *timeout);

/* 关闭一个 socket */
int ue_close_context(struct ue_context *uc);

/******************************************************************/


/**************************定时任务********************************/

/* 定时任务回调函数 */
typedef void ue_handle_cron_cb(void);

/*
 * 设置一个定时任务，interval 为间隔时间
 * 失败返回负值
 */
int ue_cron(struct timeval *interval, ue_handle_cron_cb *cron);

/******************************************************************/


/************************ Timer ***********************************/

/* timer 上下文 */
struct ue_timer
{
    struct timeval  timeout;
    size_t          session_size;
};

/* timer 超时回调函数 */
typedef void ue_timeout_cb(void *session);

/*
 * 创建一个 timer，每个 timer 有相同的超时时间、session 大小和超时回调函数
 * 使用者在这个 timer 的基础上进行 add, get, del 操作
 * 参数：
 *      timeout: 超时时间
 *      session_size: session 大小
 *      timeout_callback: 超时回调函数
 *
 * 返回 NULL 表示创建失败
 */
struct ue_timer *ue_timer_create(struct timeval *timeout, \
        size_t session_size, ue_timeout_cb *timeout_callback);

/*
 * 在指定 timer 上添加一个节点，返回 session 的地址。
 * 如果参数 session 不为 NULL，则将 session 拷贝到实际的 session 中，否则
 * 将实际 session 初始化为 0.
 * *sequence 为该节点的序列号，该序列号为一个非 0 整数。
 */
void *ue_timer_add(struct ue_timer *ut, void *session, uint32_t *sequence);

/* 根据序列号获取一个节点的 session 地址 */
void *ue_timer_get(uint32_t sequence);

/* 根据序列号删除一个节点 */
void ue_timer_del(uint32_t sequence);

/* 返回指定 timer 中节点的数量 */
size_t ue_timer_num(struct ue_timer *ut);

/* 返回指定 session 的序列号 */
uint32_t ue_timer_sequence(void *session);

/* 返回指定 session 所在的 timer */
struct ue_timer *ue_timer_which(void *session);

/******************************************************************/

