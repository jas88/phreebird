/* testfetch.c
 *
 * A small program to test and demonstrate functionality of the HTTP Fetcher
 *	library.  For a more in-depth example take a look at fetch, a program
 *	that fully utilizes HTTP Fetcher to implement a feature-rich HTTP download
 *	tool (available at http://fetch.sourceforge.net).
 *
 * Lyle Hanson (lhanson@users.sourceforge.net,
 * 	http://designwithacause.com/~lhanson)
 * This code is placed in the public domain.
 */

#include <stdio.h>
#include <http_fetcher.h>		/* Must include this to use HTTP Fetcher */

int main(int argc, char *argv[])
	{
	int ret;
	char *url = "www.google.com";   	/* Pointer to the url you want */
	char *fileBuf;						/* Pointer to downloaded data */

	ret = http_fetch(url, &fileBuf);	/* Downloads page */
	if(ret == -1)						/* All HTTP Fetcher functions return */
		http_perror("http_fetch");		/*	-1 on error. */
	else
		printf("Page successfully downloaded. (%s)\n", url);
	
	/* 
	 * Now we have the page downloaded and stored in fileBuf, we could save it
	 *	to disk, print it out, etc.  Notice that http_fetch() is the primary
	 *	function of the library, and for a barebones request is the only
	 *	function you need (in conjunction with http_perror).  With HTTP Fetcher
	 *	you can also set User Agent, referer, and timeout values, parse
	 *	filenames, etc... see the header file (http_fetcher.h) for function
	 *	usage/information.
	 */
	 
	return 0;
	}
