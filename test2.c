/*
 * Description: 
 *     History: damonyang@tencent.com, 2013/11/27, create
 */

# undef  _GNU_SOURCE
# define _GNU_SOURCE

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <errno.h>
# include <error.h>
# include <assert.h>

# include "udp_ev.h"

int main(int argc, char *argv[])
{
    if (argc != 3)
        error(1, 0, "Usage: %s ip port", argv[0]);

    int ret;
    struct sockaddr_in target;
    ret = ue_addr_assign(&target, argv[1], atoi(argv[2]));
    if (ret < 0)
        error(1, errno, "ue_addr_assign fail: %d", ret);

    struct ue_context *uc = ue_create_context(NULL, 0);
    if (uc == NULL)
        error(1, errno, "ue_create_context fail");

    char *line = NULL;
    size_t buf_size = 0;
    while (getline(&line, &buf_size, stdin) != -1)
    {
        ret = ue_send_by_context(uc, &target, line, strlen(line));
        if (ret < 0)
            error(1, errno, "ue_send_by_context fail: %d", ret);

        char buf[65535];
        struct timeval timeout = { 1, 0 };
        ret = ue_recv_by_context(uc, buf, sizeof(buf), &timeout);
        if (ret < 0)
            error(1, errno, "ue_recv_by_context fail: %d", ret);
        else if (ret == 0)
            error(1, errno, "ue_recv_by_context timeout");

        printf("recv pkg len: %zu\n", uc->pkg_len);

        ((char *)uc->pkg)[uc->pkg_len] = 0;
        printf("%s", (char *)uc->pkg);
    }

    return 0;
}

