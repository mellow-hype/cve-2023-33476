#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "config.h"

#ifdef ENABLE_NLS
#include <locale.h>
#include <libintl.h>
#endif

#include "event.h"
#include "clients.h"
#include "process.h"
#include "upnpglobalvars.h"
#include "sql.h"
#include "upnpdescgen.h"
#include "minidlnapath.h"
#include "getifaddr.h"
#include "minixml.h"
#include "upnphttp.h"
#include "minidlnatypes.h"
#include "upnpsoap.h"
#include "containers.h"
#include "upnpreplyparse.h"
#include "scanner.h"
#include "log.h"

void ProcessHttpQuery_upnphttp(struct upnphttp *);
void ParseHttpHeaders(struct upnphttp *);

int LLVMFuzzerTestOneInput(char *buf, size_t size)
{
    struct upnphttp *h = New_upnphttp(size);
    const char *endheaders;
    h->req_buf = (char *)malloc(size+1);
    if (!h->req_buf)
    {
        return 0;
    }
    memcpy(h->req_buf, buf, size);
    h->req_buflen = size;
    h->req_buf[h->req_buflen] = '\0';
    /* search for the string "\r\n\r\n" */
    endheaders = strstr(h->req_buf, "\r\n\r\n");
    if(endheaders)
    {
        h->req_contentoff = endheaders - h->req_buf + 4;
        h->req_contentlen = h->req_buflen - h->req_contentoff;
        ProcessHttpQuery_upnphttp(h);
                    /* ParseHttpHeaders(h); */
                    /* ProcessHTTPPOST_upnphttp(h); */
        free(h->req_buf);
        free(h->res_buf);
        free(h);
        return 0;
    }
    free(h->req_buf);
    free(h->res_buf);
    free(h);
    return -1;
}

