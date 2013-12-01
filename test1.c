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

int handle_udp(struct ue_context *uc)
{
    return ue_send(uc->name, &uc->client_addr, uc->pkg, uc->pkg_len);
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

    daemon(1, 1);

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

    ue_set_log_callback(handle_log);
    ue_trace();

    ret = ue_run(NULL);
    if (ret < 0)
        error(1, errno, "ue_run fail: %d", ret);

    return 0;
}

