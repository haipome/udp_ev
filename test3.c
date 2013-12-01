/*
 * Description: 
 *     History: damonyang@tencent.com, 2013/12/01, create
 */

# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <error.h>
# include <errno.h>

# include "udp_ev.h"

struct session_node
{
    char str[100];
};

void handle_timeout(void *session)
{
    struct session_node *data = (struct session_node *)session;
    struct ue_timer *ut = ue_timer_which(session);

    printf("time out, sequence: %u, timer: %ld.%ld, size: %zu, data: %s\n", \
            ue_timer_sequence(session), ut->timeout.tv_sec, ut->timeout.tv_usec, \
            ut->session_size, data->str);
}

int main()
{
    struct timeval tv = { 1, 50 * 1000 };
    struct ue_timer *ut = ue_timer_create(&tv, sizeof(struct session_node), handle_timeout);
    if (ut == NULL)
        error(1, errno, "ue_timer_create fail");

    uint32_t sequence;
    struct session_node *data = ue_timer_add(ut, NULL, &sequence);
    if (data == NULL)
        error(1, errno, "ue_timer_add fail");

    strcpy(data->str, "hello world");

    printf("timer number: %zu\n", ue_timer_num(ut));
    printf("sequence: %u\n", sequence);

    ue_timer_del(sequence);

    ue_run(NULL);

    return 0;
}

