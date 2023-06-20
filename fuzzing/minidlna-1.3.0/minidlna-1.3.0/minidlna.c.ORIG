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
#include "upnphttp.h"
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


size_t read_testcase(char *filename, char **inbuffer)
{
    // create a local copy of the pointer
    char* buffer = *inbuffer;
    buffer = NULL;
    size_t length = 0;
    FILE *testcase = fopen(filename, "r");
    if (testcase != NULL)
    {
        if (fseek(testcase, 0L, SEEK_END) == 0)
        {
            /* Get the size of the file. */
            long bufsize = ftell(testcase);
            printf("filesize: %ld\n", bufsize);
            if (bufsize == -1)
            {
                printf("error getting file size\n");
                goto exit_now;
            }

            /* Allocate our buffer to that size. */
            buffer = malloc(sizeof(char) * (bufsize + 1));
            if (buffer == NULL)
            {
                printf("error allocating memory for file data\n");
                goto exit_now;
            }

            /* Go back to the start of the file. */
            if (fseek(testcase, 0L, SEEK_SET) != 0)
            {
                printf("error moving SEEK head\n");
                goto exit_now;
            }

            /* Read the entire file into memory. */
            length = fread(buffer, sizeof(char), bufsize, testcase);
            if ( ferror( testcase ) != 0 ) {
                printf("error reading file data\n");
                goto exit_now;
            } else {
                buffer[length] = '\0'; /* Just to be safe. */
            }

            printf("size actually read from file: %lu\n", length);

            fclose(testcase);
            *inbuffer = buffer;
            return length;
        }
    }

    printf("error opening file: %s\n", filename);
    return 0;


exit_now:
    fclose(testcase);
    if (buffer != NULL)
        free(buffer);
    return 0;
}


int d_main(int argc, char **argv) {
    if (argc == 2) {
        char *buffer;
        size_t size = read_testcase(argv[1], &buffer);
        if (size == 0)
            return -1;
        printf("size that is going to be passed to fuzzer: %lu\n", size);
        printf("file contents: \n%s\n", buffer);
        int x = LLVMFuzzerTestOneInput(buffer, size);
        free(buffer);
        return x;
    }
    printf("usage: %s </path/to/testcase>\n", argv[0]);
    return -1;
}
