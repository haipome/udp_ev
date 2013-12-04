/*
 * Description: 
 *     History: damonyang@tencent.com, 2013/11/27, create
 */

# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <error.h>
# include <errno.h>
# include <signal.h>
# include <unistd.h>

# include "udp_ev.h"

enum
{
    BASE_NAME = 1,
    SECOND_NAME,
};

struct session
{
    char str[100];
};

struct ue_timer *main_timer;

int handle_udp(struct ue_context *uc)
{
    uint32_t sequence;
    struct session * session = ue_timer_add(main_timer, NULL, &sequence);
    if (session == NULL)
        error(1, 0, "ue_timer_add fail");

    ((char *)uc->pkg)[uc->pkg_len] = 0;
    snprintf(session->str, sizeof(session->str), "%d: %s", sequence, (char *)uc->pkg);

    struct timeval tv = { 10, 1 };
    ue_exit_later(&tv);

    return ue_send(uc->name, &uc->client_addr, uc->pkg, uc->pkg_len);
}

void handle_timeout(void *data)
{
    struct session *session = data;
    puts(session->str);
}

void handle_loop(void)
{
    static int n;
    n += 1;
}

void handle_log(int severity, char const *msg)
{
    switch (severity)
    {
    case UE_LOG_INFO:
        printf("info: ");
        break;
    case UE_LOG_WARN:
        printf("warn: ");
        break;
    case UE_LOG_ERROR:
        printf("error: ");
        break;
    }

    printf("%s\n", msg);
}

void handle_signal(int signo)
{
    switch (signo)
    {
    case SIGQUIT:
        printf("meet SIGQUIT\n");
        ue_exit();
        break;
    default:
        printf("meet signo: %d\n", signo);
        break;
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3)
        error(1, 0, "Usage: %s port1 port2", argv[0]);

    //daemon(1, 1);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGQUIT, handle_signal);

    int ret;

    ret = ue_create(BASE_NAME, NULL, atoi(argv[1]), handle_udp);
    if (ret < 0)
        error(1, errno, "ue_create fail: %d", ret);

    struct timeval interval = { 1, 0 };
    ret = ue_cron(&interval, handle_loop);
    if (ret < 0)
        error(1, errno, "ue_cron fail: %d", ret);

    ret = ue_create(SECOND_NAME, NULL, atoi(argv[2]), handle_udp);
    if (ret < 0)
        error(1, errno, "ue_create fail: %d", ret);

    struct timeval tv = { 1, 0 };
    main_timer = ue_timer_create(&tv, sizeof(struct session), handle_timeout);
    if (main_timer == NULL)
        error(1, 0, "ue_timer_create fail");

    ue_set_log_callback(handle_log);
    ue_trace();

    ret = ue_run(NULL);
    if (ret < 0)
        error(1, errno, "ue_run fail: %d", ret);

    return 0;
}

