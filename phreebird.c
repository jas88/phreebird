#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

/* sockets */
#include <sys/types.h>
#include <sys/socket.h>

/* for non blocking */
#include <fcntl.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>

/* for libevent */
#include <event.h>

/* for ldns */

#include <ldns/ldns.h>

/* for libghthash */

#include "ght_hash_table.h"

#include <sys/time.h>
#include <time.h>

/* for http */
#include <sys/queue.h>
#include <err.h>
#include <evhttp.h>

/* for OpenSSL, specifically so we can +1/-1 NSEC3 White Lies */
#include <openssl/bn.h>

// SECTION 1: STRUCTS

struct phreebird_opts_struct
{
	char *dnskey_fname;
	bool gen_key;
	ldns_key *key;  // one key to rule them all
	ldns_key_list *keylist;
	int stubsock;
	int backsock;
	struct sockaddr_in back_addr;	
	ght_hash_table_t *correlator;
	unsigned long long pcount;
	ldns_rdf *owner_rdf;
	ldns_rr *dnskey;
	ldns_rr *ds;
	uint16_t *keytag;
	struct evhttp *httpd;
	unsigned short http_port;
	// for TCP
	int listensock;
	
};
typedef struct phreebird_opts_struct phreebird_opts;

struct request_cache_struct
{
	phreebird_opts *opts; // TCP needed it
	unsigned short id;
	bool edns_do;
	unsigned short edns_size;
	int method;
	bool free_buf;
	// UDP	
	struct sockaddr_in addr;
	// HTTP
	struct evhttp_request *req;
	// TCP
	struct event *clientevent;
	int clientfd;
};
typedef struct request_cache_struct request_cache;

struct nsec3_rate_limiter_struct
{
	unsigned int sec;
	unsigned int max;
	unsigned int count;
};
typedef struct nsec3_rate_limiter_struct nsec3_rate_limiter;



// SECTION 2:  GLOBALS

#define METHOD_UDP 0
#define METHOD_HTTP 1
#define METHOD_TCP 2


static bool debug;
static ght_hash_table_t *rrsig_cache; // XXX There are better things I could be using here than GHT
// XXX not using GHT's max cache size, which means we can have our memory drained (problem!)

static nsec3_rate_limiter nsec3_rater;

//premature optimization is the root of all evil but I am not going to re-initialize this static rdf on every packet

ldns_rdf *time_rdf;

#define LOOKING_FOR_ARGSET 0
#define LOOKING_FOR_ARG 1
#define FOUND_VERSION_ARG 2
#define FOUND_QUERY_ARG 3
#define FAIL_PARSE      4

// SECTION 3:  FUNCTION DECLARATIONS

int main(int argc, char **argv);
int create_key(char *fname);
int setup_key(ldns_key *key);
int init_udp_socket(unsigned short port);
int init_sockets(phreebird_opts *opts);
int init_tcp_socket(unsigned short port);
int execute_event_listener(phreebird_opts *opts);
void init_key(phreebird_opts *opts);
void set_defaults(phreebird_opts *opts);
void stub_handler_UDP(int fd, short event, void *arg);
void stub_handler_TCP(int fd, short event, void *arg);
void stub_handler_HTTP(struct evhttp_request *req, void *arg);
void clientcallback(int clientfd, short event, void *arg) ;
void listen_handler(int listenfd, short event, void *arg) ;
void stub_handle_request(phreebird_opts *opts, char *buf, size_t len, request_cache *store_cache);
void backend_handler_UDP(int fd, short event, void *arg);
void backend_handle_response(phreebird_opts *opts, char *buf, size_t len, struct sockaddr_in* cAddr);
void send_response_pkt(ldns_pkt *response, request_cache *store_cache, phreebird_opts *opts);
void http_reply(int rcode, unsigned char *buf, int len, struct evhttp_request *req);
void response_fixup(ldns_pkt *response, int edns);
int do_sign(ldns_rr_list *dest, ldns_rr_list *src, ldns_key_list *keylist);
void do_help();
ldns_pkt *build_response(ldns_rdf *orig_q, ldns_rr *rr, ldns_key_list *keylist, bool sign);
ldns_rr_list *build_nsec3_response(ldns_rdf *name, ldns_rdf *shortname, char *mask, bool do_bangbang);
void pb_abort(char *str);
bool validate_name(char *str);

unsigned long listen_addr=INADDR_ANY;
char *listen_name=NULL;

// SECTION 4:  MAIN

int main(int argc, char **argv){

	int c;
	char *p;
	phreebird_opts *opts;
	//extern char *optarg;
	//extern int optind, opterr, optopt;	

	listen_name=strdup("0.0.0.0");
	if (!listen_name) exit(255);

	opts = calloc(sizeof(struct phreebird_opts_struct), 1);  
	if(opts==NULL) exit(255);

	set_defaults(opts);

	while ((c = getopt(argc, argv, "k:gdb:?m:l:")) != -1) {
		switch (c){
			case 'k':
				LDNS_FREE(opts->dnskey_fname);
				opts->dnskey_fname = strdup(optarg);
				break;
			case 'g':
				opts->gen_key=1;
				break;
			case 'd':
				debug=1;
				break;
			case 'b':
				p=strchr(optarg, ':');
				if(p) *p=0;
				//LDNS_FREE(opts->backend_ip);
				inet_aton(optarg, &opts->back_addr.sin_addr);
				if(p){
					opts->back_addr.sin_port = htons(atoi(p+1));
					}
				//opts->backend_ip = strdup(optarg);
				//if(p){opts->backend_port = atoi(p+1);}
				break;
			case 'm':
				nsec3_rater.max = atoi(optarg);
				break;
			case 'l':
				inet_aton(optarg,&listen_addr);
				free(listen_name);
				listen_name=strdup(optarg);
				if (!listen_name) exit(255);
				break;
			case '?':
				do_help();
				exit(255);
				break;
			default:
				break;
			}
		}

	init_key(opts);
	init_sockets(opts);

	execute_event_listener(opts);
	//never reached
	return 0;


}


// SECTION 5:  INITIALIZATION

int create_key(char *fname){
	FILE *f;
	ldns_key *key;

	f = fopen(fname, "w");
	if(f==NULL) { return -1; }
	key = ldns_key_new_frm_algorithm(LDNS_RSASHA1_NSEC3, 1024);
	if(key==NULL) { pb_abort("couldn't make algo"); }
	ldns_key_print(f, key);
	fclose(f);
	fprintf(stdout, "Generated key: %s.  Restart without -g.\n", fname);
	exit(0);
	return(1);
}


void init_key(phreebird_opts *opts){
	int r;
	FILE *f;
	bool status;
	
	if(opts->gen_key){
		r=create_key(opts->dnskey_fname);
		if(r<0) {
			fprintf(stderr, "Unable to create key: %s\n", opts->dnskey_fname);
			exit(255);
			}
		}

	f = fopen(opts->dnskey_fname, "r");
	if(f==NULL){
		fprintf(stderr, "Unable to open key: %s\n", opts->dnskey_fname);
		fprintf(stderr, "Execute with -g flag to generate a key.\n\n");
		do_help();
		exit(255);
		}

	ldns_key_new_frm_fp(&opts->key, f);
	if(opts->key == NULL) { pb_abort("couldn't read key"); }
	if(debug) { ldns_key_print(stdout, opts->key); }


	opts->keylist = ldns_key_list_new();
	if(opts->keylist == NULL) { pb_abort("couldn't make keylist\n"); }
	status = ldns_key_list_push_key(opts->keylist, opts->key);	
	if(status == 0) { pb_abort("couldn't push key onto keylist\n"); }

}

int setup_key(ldns_key *key){
	struct timeval now;
	gettimeofday(&now, NULL);
	ldns_key_set_flags(key, LDNS_KEY_SEP_KEY | LDNS_KEY_ZONE_KEY);
	ldns_key_set_expiration(key, now.tv_sec + (1024 * 1024 * 256)); //now.tv_sec + 1024 );
	ldns_key_set_inception(key, 1);
	ldns_key_set_keytag(key, 2013);
	return(1);
}



void set_defaults(phreebird_opts *opts){
	debug=0;
	rrsig_cache = NULL;
	nsec3_rater.count=0;
	nsec3_rater.sec=0;
	nsec3_rater.max=200;
	opts->dnskey_fname = strdup("dns.key");
	opts->gen_key=0;
	opts->back_addr.sin_family = AF_INET;
	opts->back_addr.sin_port = htons(50053);
	inet_aton("127.0.0.1", &opts->back_addr.sin_addr);
	bzero(&(opts->back_addr.sin_zero), 8);
	opts->correlator = ght_create(1024*1024);
	opts->pcount=0;
	opts->http_port = 80;
	time_rdf = ldns_dname_new_frm_str("_dns._time.");
	}

int init_udp_socket(unsigned short port){
	int sock;
	int yes = 1;
	int bsize = 65536*64; // arbitrary
	int len = sizeof(struct sockaddr);
	struct sockaddr_in addr;
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "Unable to make UDP socket %u\n", port);
		exit(255);
		}
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
		fprintf(stderr, "Error setting socket option (reuseaddr).\n");
		exit(255);
		
	}
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bsize, sizeof(int)) < 0) {
		fprintf(stderr, "Error setting socket option (rcvbuf %u).\n", bsize);
		exit(255);
	}
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bsize, sizeof(int)) < 0) {
		fprintf(stderr, "Error setting socket option. (sndbuf %u).\n", bsize);
		exit(255);
	}
	
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = listen_addr;
	bzero(&(addr.sin_zero), 8);
	
	if (bind(sock, (struct sockaddr*)&addr, len) < 0) {
		fprintf(stderr, "Unable to bind to port: %u.\n", port);
		exit(255);
	}
	return sock;
}





int init_sockets(phreebird_opts *opts){

	opts->stubsock = init_udp_socket(53);	
	opts->backsock = init_udp_socket(0);
	opts->listensock = init_tcp_socket(53);
	return 1;
}

int init_tcp_socket(unsigned short port){
	int sock;	
	int optval=1;
	struct sockaddr_in addr;
	int status;


	sock = socket(PF_INET, SOCK_STREAM, 0);
	setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval));
	fcntl(sock, F_SETFL, O_NONBLOCK);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = listen_addr;
	addr.sin_port = htons(port);
	
	status = bind(sock, (void *)&addr, sizeof(struct sockaddr_in));	
	if(status<0) { pb_abort("couldn't bind to port\n"); }
	status = listen(sock, 128);
	if(status<0) { pb_abort("couldn't listen\n"); }
	return sock;
	
}

// SECTION 6:  STUB HANDLERS


int execute_event_listener(phreebird_opts *opts){

	struct event rec_from_stub, rec_from_backend, rec_from_tcp;
	struct evhttp *httpd;

	event_init();
	event_set(&rec_from_stub, opts->stubsock, EV_READ | EV_PERSIST, stub_handler_UDP, opts);
	event_set(&rec_from_backend, opts->backsock, EV_READ | EV_PERSIST, backend_handler_UDP, opts);
	event_set(&rec_from_tcp, opts->listensock, EV_READ | EV_PERSIST, stub_handler_TCP, opts);

	event_add(&rec_from_stub, NULL);
	event_add(&rec_from_backend, NULL);
	event_add(&rec_from_tcp, NULL);

	httpd = evhttp_start(listen_name, opts->http_port);
	if(httpd != NULL) {
		//pb_abort("couldn't start web server\n"); }
		evhttp_set_timeout(httpd, 3);
		evhttp_set_cb(httpd, "/.well-known/dns-http", stub_handler_HTTP, opts);
		//evhttp_set_cb(httpd, "/stop", exit, opts);
		//evhttp_set_gencb(httpd, stub_handler_HTTP, opts);
		opts->httpd = httpd;
		}
	event_dispatch();
	// never reached, but
	return(0);

}



void stub_handler_UDP(int fd, short event, void *arg){
	char buf[2048];
	size_t len;
	struct sockaddr_in cAddr;
	phreebird_opts *opts = arg;
	request_cache *store_cache;

	
	unsigned int l = sizeof(struct sockaddr);
	len = recvfrom(fd, buf, 2048, 0, (struct sockaddr*)&cAddr, &l);

	if(debug) { fprintf(stderr, "Received %u bytes from %s\n", len, inet_ntoa(cAddr.sin_addr));}

	store_cache = calloc(sizeof(struct request_cache_struct), 1); //ALLOC1
	if(store_cache == NULL) { pb_abort("couldn't allocate request_cache\n"); }
	memcpy(&(store_cache->addr),&cAddr, sizeof(struct sockaddr_in));
	store_cache->method = METHOD_UDP;
	store_cache->free_buf = 0;

	stub_handle_request(opts, buf, len, store_cache);
}




void stub_handler_TCP(int listenfd, short event, void *arg) {
	int clientfd;
	struct event * clientevent;
	/* supress unused variable warnings */
	(void) event;
	phreebird_opts *opts = arg;

 
	request_cache *store_cache;

	store_cache = calloc(sizeof(struct request_cache_struct), 1);	//ALLOC1 (variant)
	if(store_cache == NULL) { pb_abort("couldn't allocate request_cache\n"); }

	clientfd = accept(listenfd, NULL, NULL);
	clientevent = (struct event *) malloc(sizeof(struct event)); //ALLOC2

	store_cache->opts  =opts;
	store_cache->method=METHOD_TCP;
	store_cache->clientevent=clientevent;
	
	event_set(clientevent, clientfd, EV_READ | EV_PERSIST, clientcallback, store_cache);
	event_add(clientevent, NULL);
}	

void clientcallback(int clientfd, short event, void *arg) {
	char *buffer;
	int amount_read;
	//int amount_sent;
	//struct event * clientevent;
	/* supress unused variable warnings */
	(void) event;

	request_cache *store_cache;

	store_cache = (request_cache *)arg;

	unsigned short to_read;
	amount_read = read(clientfd, &to_read, 2);
	if (amount_read < 2) {
		close(clientfd);
		event_free(store_cache->clientevent); // FREE2
		return; // MIDRET, ok because no alloc before here
	}
	buffer = calloc(to_read, 1); //ALLOC3
	amount_read = read(clientfd, buffer, to_read);
	store_cache->clientfd = clientfd;

	// XXX we aren't even bothering to handle split reads right now
	// this is rather lazy.
	stub_handle_request(store_cache->opts, buffer, amount_read, store_cache);
	LDNS_FREE(buffer); //FREE3
}



void stub_handle_request(phreebird_opts *opts, char *buf, size_t len, request_cache *store_cache){
	ldns_pkt *request, *response;
	ldns_status status;	
	ldns_rr *q;
	int slen = sizeof(struct sockaddr);
	char hashkey[512];
	ght_hash_table_t *reqlist;
	//int offset;
	//ldns_rdf *shortname;
	ldns_rr *dnskey, *ds;
	//char nsbuf[512];	
	ldns_rdf *shortname = NULL;
	ldns_rdf *tmp       = NULL;

	request=response=NULL;

	memset(hashkey, 0, sizeof(hashkey));


	status = ldns_wire2pkt(&request, (uint8_t *)buf, len);
	if(status != LDNS_STATUS_OK){
		if(debug) { fprintf(stderr, "Bad packet received from %s\n", inet_ntoa(store_cache->addr.sin_addr)); }
		if(store_cache->method == METHOD_HTTP){
			http_reply(500, "fail", 4, store_cache->req);
			evhttp_request_free(store_cache->req);		
			}
		goto out;
		}
	if(debug) { ldns_pkt_print(stderr, request);}

	// insert handler for instant replies
	q = ldns_pkt_question(request)->_rrs[0];

	// needed for dns time

	shortname = ldns_rdf_clone(ldns_rr_owner(q));
	if(shortname == NULL) { pb_abort( "couldn't create shortname\n"); }
	while(ldns_dname_label_count(shortname) > 2) { // XXX yes, I know, this needs to be much more mature.  Walk before run.
		  ldns_rdf *tmp=NULL;
		  tmp=ldns_dname_left_chop(shortname);
		  if(tmp==NULL) { pb_abort("couldn't create tmpname 1\n"); }
		  ldns_rdf_free(shortname);
		  shortname=tmp;
		}

	//CASE 1:  The stub wants a DS or DNSKEY record.  We don't go back to the backend for this.



	if((ldns_rr_get_type(q) == LDNS_RR_TYPE_DNSKEY ||
		ldns_rr_get_type(q) == LDNS_RR_TYPE_DS)
		&& (ldns_dname_label_count(ldns_rr_owner(q))==2)){

		// XXX OK.	There are two bugs here:
		//	1) There might actually be DS or DNSKEY records behind this NS!  We really only should be
		//		 interposing when the response comes back blank.  We're not doing this now because that
		//           requires actually asking the backend.  In other words, have to re-engineer for a special case.
		//	2)	I'm being tremendously presumptuous, not even letting the user configure the number of labels
		//		 that separate the closed and open namespaces -- for example, I assume foo.com and bar.to,
		//		 but foo.co.uk is right out.  This is actually a fairly tricky problem; I'll fix it but only once I can
		//            actually find a three-label DNSSEC name I can register somewhere

		ldns_key_set_pubkey_owner(opts->key, ldns_rr_owner(q));

		dnskey = ldns_key2rr(opts->key);
		if(dnskey == NULL) { pb_abort("couldn't set DNSKEY\n"); }
		if(ldns_rr_get_type(q) == LDNS_RR_TYPE_DS) {
			ds     = ldns_key_rr2ds(dnskey, LDNS_SHA1);
			if(ds == NULL) { pb_abort("couldn't set DS\n"); }
			}

		buf[sizeof(buf)]=0;

		// response will never be NULL, we'll pb_abort first
		if(q->_rr_type == LDNS_RR_TYPE_DNSKEY){			
			response = build_response(ldns_rr_owner(q), dnskey, opts->keylist, true);
			}
		if(q->_rr_type == LDNS_RR_TYPE_DS){		
			response = build_response(ldns_rr_owner(q), ds, opts->keylist, true);
			}

		ldns_pkt_set_id(response, ldns_pkt_id(request));
		send_response_pkt(response, store_cache, opts);	// XXX we actually need to set >512 if edns missing
		ldns_pkt_free(response);

		// ldns_pkt_free deep freed its rrs.  So a DS response left the DNSKEY
		// We don't generate the DS on a DNSKEY request
		if(ldns_rr_get_type(q) == LDNS_RR_TYPE_DS) ldns_rr_free(dnskey);
		
		
		}
	// CASE 2:  The stub is requesting a magic record that we supply (in this case, dnstime)
	else if(ldns_rdf_compare(time_rdf, shortname)==0 && ldns_rr_get_type(q)==LDNS_RR_TYPE_TXT){
		// This is DNS Time support, intended for somewhere high in the DNS heirarchy.
		// The idea is you should be able to get a signed expression of time, enough to bootstrap time.
		// This _intentionally_ works for both _dns._time and $RANDOM._dns._time -- in fact, that's _required_
		// for scalability
		char rrbuf[256];
		char tbuf[32];
		const char *tformat = "%Y%m%d%H%M%S";		
		struct timeval now;		
		//struct tm* ptm;
		ldns_buffer *lb;
		ldns_rr *time_rr = NULL;
		bool do_sign;

		lb = ldns_buffer_new(256);
		if(lb==NULL) { pb_abort("couldn't create buffer\n"); }
		ldns_rdf2buffer_str_dname(lb, time_rdf);

		do_sign = ldns_pkt_edns_do(request);

		gettimeofday(&now, NULL);
		
		strftime(tbuf, sizeof(tbuf), tformat, gmtime(&now.tv_sec));
		snprintf(rrbuf, sizeof(rrbuf), "%s IN TXT \"v=dtm1 t=%s\"", lb->_data, tbuf);
		ldns_rr_new_frm_str(&time_rr, rrbuf, 1, NULL, NULL);
		if(time_rr == NULL) { pb_abort("couldn't create time_rr\n"); }
		response = build_response(ldns_rr_owner(q), time_rr, opts->keylist, do_sign);
		ldns_pkt_set_id(response, ldns_pkt_id(request));

		send_response_pkt(response, store_cache, opts);	// XXX we actually need to set >512 if edns missing

		ldns_buffer_free(lb);
		ldns_pkt_free(response);
		}
	// CASE 3:  We're signing something that the backend has to provide us the answers for.
	// WE DO NOT CACHE ANSWERS -- this is an intentional design decision, which makes sure we can always
	// reply correctly.  There are complex rules for what answers to return when.
	else{
		// run to the backend
		int status;
		ldns_buffer *name;
		name = ldns_buffer_new(512);
		ldns_rdf2buffer_str_dname(name, ldns_rr_owner(q));
		snprintf(hashkey, sizeof(hashkey), "%s/%u/%u/%u", name->_data, ldns_rr_get_type(q) , ldns_rr_get_class(q), ldns_pkt_id(request));
		ldns_buffer_free(name);

		// We may have multiple hosts asking for the same name/type/class/txid.  Yes, even TXID.  It's only a 65K range!
		
		reqlist = ght_get(opts->correlator, sizeof(hashkey), hashkey);
		if(reqlist == NULL){
		   reqlist = ght_create(128); // XXX could be better?
		   if(reqlist == NULL) { pb_abort("couldn't create GHT hash\n"); }
		   ght_insert(opts->correlator, reqlist, sizeof(hashkey), hashkey);
		}
		store_cache->id = ldns_pkt_id(request);
		store_cache->edns_do = ldns_pkt_edns_do(request);
		store_cache->edns_size = ldns_pkt_edns_udp_size(request);
		
		status = ght_insert(reqlist, store_cache, sizeof(opts->pcount), &opts->pcount);
		if(status<0) { 
			ght_remove(opts->correlator, sizeof(hashkey), hashkey);
			//LDNS_FREE(store_cache);
			ght_finalize(reqlist);
			goto out;
			}
		
		// don't think I need to care about this failing
		sendto(opts->backsock, buf, len, 0, (void *)&(opts->back_addr), slen);

		}
	out:
	if(request) ldns_pkt_free(request);
	if(shortname) ldns_rdf_free(shortname);
	if(store_cache->free_buf==1) { LDNS_FREE(buf);}; //FREE1(variant)

}

void stub_handler_HTTP(struct evhttp_request *req, void *arg)
{
	phreebird_opts *opts;
	request_cache *store_cache;
	char *offset, *decoded;
	int orig_len, decoded_len;

	char *version_start = NULL;
	int version;
	char *query_b64 = NULL;
	int ustate = LOOKING_FOR_ARGSET;
	int arglen = strlen(req->uri);
	char *u = req->uri;
	int i;

	/* In theory, evhttp should have a URL cracker.  In reality, this is a basic state machine.
	 * It should handle things well -- state machines are nice like that -- but obviously it requires
	 * pen testing.
	 */

	for(i=0; i<arglen; i++){
		if(ustate == LOOKING_FOR_ARGSET){
			if(u[i] == '?'){
				ustate = LOOKING_FOR_ARG;
				continue;
				}
			}
		if(ustate == LOOKING_FOR_ARG){
			if(u[i] == 'v') {
				ustate = FOUND_VERSION_ARG;
				if(i+2 < arglen && u[i+1]=='=') { version_start = u+i+2; }
				else                          { ustate = FAIL_PARSE; }
				continue;
				}
			if(req->uri[i] == 'q') {
				ustate = FOUND_QUERY_ARG;
				if(i+2 < arglen && u[i+1]=='=') { query_b64 = u+i+2; }
				else                          { ustate = FAIL_PARSE; }
				continue;
				}
			}
		if(ustate == FOUND_VERSION_ARG || ustate == FOUND_QUERY_ARG){
			if(u[i] == '&') {
				u[i] = 0;
				ustate = LOOKING_FOR_ARG;
				continue;
				}
			}
		}

	
	if(ustate == FAIL_PARSE || version_start == NULL || query_b64 == NULL){
		http_reply(500, "fail", 4, req);
		return; //MIDRET
		}
	version = atoi(version_start);
	if(version<1) {
		// Assuming the TLS model, where you can ask for whatever version you want.  We'll
		// add a flag on return saying what version was supported.
		http_reply(500, "fail", 4, req);
		return; // MIDRET
		}

		
	opts = (phreebird_opts *)arg;

	
	orig_len = strlen(query_b64);
	decoded = calloc(orig_len, 1); //ALLOC4

	decoded_len=ldns_b64_pton(query_b64, decoded, orig_len);
	if(decoded_len<0){ decoded_len = 0; }

	store_cache = calloc(sizeof(struct request_cache_struct), 1);
	if(store_cache == NULL) { pb_abort("couldn't decode b64 from HTTP\n"); }

	store_cache->req = req;
	store_cache->method = METHOD_HTTP;
	store_cache->free_buf = true;
		
	stub_handle_request(opts, decoded, decoded_len, store_cache);
	LDNS_FREE(decoded); //FREE4

}


// SECTION 7:  BACKEND COMMS

void backend_handler_UDP(int fd, short event, void *arg){
	unsigned char buf[2048];
	int len; // NOT size_t, as I discovered.
	struct sockaddr_in cAddr;
	phreebird_opts *opts = arg;
	
	int l = sizeof(struct sockaddr);
	len = recvfrom(fd, buf, 2048, 0, (struct sockaddr*)&cAddr, &l);
	if(len<0) return;

	if(debug) { fprintf(stderr, "Received %u bytes from %s\n", len, inet_ntoa(cAddr.sin_addr));}

	backend_handle_response(opts, buf, len, &cAddr);
	
}

void backend_handle_response(phreebird_opts *opts, char *buf, size_t len, struct sockaddr_in* cAddr){
	ldns_pkt *response = NULL;
	ldns_pkt *response_signed = NULL;
	ldns_status status;	
	ldns_rr *rr = NULL;
	int slen = sizeof(struct sockaddr);
	char hashkey[512];
	ght_hash_table_t *reqlist;	
	ght_iterator_t iterator;
	request_cache *store_cache;
	const void *p_key;
	uint8_t *newbuf;
	size_t newlen;
	ldns_rr_list *signatures = NULL;
	unsigned short an, ar, ns;
	ldns_rr_list *ans_orig = NULL;
	ldns_rr_list *ans_sign = NULL;
	ldns_rdf *shortname = NULL;
	ldns_rdf *zonename = NULL;
	ldns_rr *nsec3_rr, *nsec3_rr_enclosing, *nsec3_rr_wildcard = NULL;
	ldns_rr_list *nsec3_rr_list = NULL;
	ldns_rr_list *nsec3_rr_enclosing_list = NULL;
	ldns_rr_list *nsec3_rr_wildcard_list = NULL;
	ldns_pkt *silly = NULL;	
	bool nsec3_signed_it = false;
	bool servfail = false;
	ldns_rr_list *empty_answer = NULL;
	ldns_rr_list *empty_authority = NULL;
	ldns_rr_list *empty_additional = NULL;
	

// NSEC3
	
	char *type;
	ldns_rdf *wildname = NULL;
	ldns_buffer *shortname_buf = NULL;

	char wildbuf[512];
	
	ldns_rdf *parent_zone = NULL;
	char *c;
	BIGNUM *left, *right;
	char *lbuf, *rbuf;
	char lhash[64], rhash[64];
	char nsec_descrip[256];
	int  llen, rlen;
	char salt[2];
	char mask[2048];
	bool b_status = false;
	int sign_status;
//

	ldns_buffer *name;
	
	
	ans_sign = NULL;
	memset(hashkey, 0, sizeof(hashkey));

	status = ldns_wire2pkt(&response, buf, len);
	
	if(status != LDNS_STATUS_OK){
		if(debug) { fprintf(stderr, "Bad packet received from %s\n", inet_ntoa(cAddr->sin_addr)); }
		return; //MIDRET
		}
	if(debug) { ldns_pkt_print(stderr, response);}

	rr = ldns_pkt_question(response)->_rrs[0];

	// XXX OK.  This entire approach has a flaw: The backend server loses context of the original IP making the request.
	// That's fine for an initial release but it's a huge problem for the very GeoIP backends that an online signer can support.
	// There are three fixes, one or more of which will be implemented in a future release:
	// 1) Mangle Table.  In this case, we alter the packets coming in and out of the host.
	//     This has the advantage of fairly ridiculous performance, because the kernel becomes our event engine.
	// 2) EDNS0 Backend Declaration.  This is the OpenDNS/Google (I'm not going to try to tease apart that history)
	//     approach where the forwarded query says who made it.  It works well, but it does depend on the backend
	//     implementing support.
	// 3) L2 forwarding.  In this approach, we basically force there to be two hosts, and statically set ourselves as the
	//     IP gateway for the host we're supplementing.  For various reasons I'm not the biggest fan of this approach.
	// Anyway, you can see why I'm not going down this particular rabbit hole right now.

	shortname = ldns_rdf_clone(ldns_rr_owner(rr));
	if(shortname == NULL) { pb_abort( "couldn't create shortname\n"); }
	while(ldns_dname_label_count(shortname) > 2) { // XXX yes, I know, this needs to be much more mature.  Walk before run.
	//if(ldns_dname_label_count(shortname) != 2) { // this strips one(1) label iff label count != 2
		  ldns_rdf *tmp=NULL;
		  tmp=ldns_dname_left_chop(shortname);
		  if(tmp==NULL) { pb_abort("couldn't create tmpname 2\n"); }
		  LDNS_FREE(shortname);
		  shortname=tmp;
		}
	
	ldns_key_set_pubkey_owner(opts->key, shortname);

	/* Add NSEC3 records */
	if(ldns_pkt_ancount(response)==0){
		// WHEW.  OK, so NSEC3 records are Base32 Extended (with a period at the end)
		// OpenSSL accepts Hex.
		// We need to turn them from B32e to Binary, to Hex, to Bignum.
		// Then we need to add and subtract 1.
		// Then we need to convert both Bignums to Binary, which we then B32e.
		// Fun!

		
		// 0: First, sign what's already in there

		do_sign(ldns_pkt_authority(response), ldns_pkt_authority(response), opts->keylist);

		if(ldns_pkt_get_rcode(response) == LDNS_RCODE_NXDOMAIN){

			// 1: Do the qname white lie		
			
	 		type=ldns_rr_type2str(ldns_rr_get_type(rr));

			snprintf(mask, sizeof(mask), "%s RRSIG", type);

			// will always succeed (or pb_abort)
			nsec3_rr_list = build_nsec3_response(ldns_rr_owner(rr), shortname, mask, true);
			
			sign_status = do_sign(nsec3_rr_list, nsec3_rr_list, opts->keylist);
			if(sign_status < 0) { servfail = true; goto out; }
			

			// 2: Do the closest encloser white lie
			// XXX yes this is ridiculous, re: the bitmask.  Apparently it's needed?
			snprintf(mask, sizeof(mask), "%s CERT NAPTR A NS CNAME SOA NULL WKS PTR HINFO MX TXT AAAA LOC SRV DS SSHFP IPSECKEY RRSIG NSEC NSEC3 DNSKEY DHCID NSEC3PARAM SPF TKEY RRSIG CNAME", type);
	 
			nsec3_rr_enclosing_list = build_nsec3_response(shortname, shortname, mask, false);
			sign_status = do_sign(nsec3_rr_enclosing_list, nsec3_rr_enclosing_list, opts->keylist);
			if(sign_status < 0) { servfail = true; goto out; }

			// 3: Do the wildcard white lie
			shortname_buf = ldns_buffer_new(512);
			if(shortname_buf == NULL) { pb_abort("couldn't create shortname_buf\n"); }
			ldns_rdf2buffer_str_dname(shortname_buf, shortname);
			
			snprintf(wildbuf, sizeof(wildbuf), "*.%s", shortname_buf->_data);
			if(validate_name(shortname_buf->_data) != true){ servfail=true; goto out; }
			wildname = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, wildbuf);
			if(wildname == NULL) { pb_abort("couldn't create wildname\n"); }


			snprintf(mask, sizeof(mask), "%s RRSIG", type);
			nsec3_rr_wildcard_list = build_nsec3_response(wildname, shortname, mask, true);

			do_sign(nsec3_rr_wildcard_list, nsec3_rr_wildcard_list, opts->keylist);
			ldns_buffer_free(shortname_buf);
			ldns_rdf_free(wildname);
			
			if(sign_status < 0) { servfail = true; goto out; }
			}
		else {
	 		type=ldns_rr_type2str(ldns_rr_get_type(rr));

			snprintf(mask, sizeof(mask), "CERT NAPTR A NS SOA NULL WKS PTR HINFO MX TXT LOC SRV DS SSHFP IPSECKEY RRSIG NSEC NSEC3 DNSKEY DHCID NSEC3PARAM SPF TKEY RRSIG");

			// will always succeed (or pb_abort)
			nsec3_rr_list = build_nsec3_response(ldns_rr_owner(rr), shortname, mask, false);
			
			sign_status = do_sign(nsec3_rr_list, nsec3_rr_list, opts->keylist);
			if(sign_status < 0) { servfail = true; goto out; }
			}	


		// 4: Push to list.  Note this only works if all signatures worked.
		if(nsec3_rr_list!=NULL){
			b_status = ldns_rr_list_push_rr_list(ldns_pkt_authority(response), nsec3_rr_list);
			if(b_status == false) { pb_abort("couldn't push to list\n"); }
			ldns_rr_list_free(nsec3_rr_list);
			}

		if(nsec3_rr_enclosing_list!=NULL){
			b_status = ldns_rr_list_push_rr_list(ldns_pkt_authority(response), nsec3_rr_enclosing_list);
			if(b_status == false) { pb_abort("couldn't push to list\n"); }
			ldns_rr_list_free(nsec3_rr_enclosing_list);
			}
		

		if(nsec3_rr_wildcard_list!=NULL){
			b_status = ldns_rr_list_push_rr_list(ldns_pkt_authority(response), nsec3_rr_wildcard_list);		
			if(b_status == false) { pb_abort("couldn't push to list\n"); }
			ldns_rr_list_free(nsec3_rr_wildcard_list);
			}



		nsec3_signed_it = true;

		}


	out:

	name = ldns_buffer_new(512);
	ldns_rdf2buffer_str_dname(name, ldns_rr_owner(rr));
	snprintf(hashkey, sizeof(hashkey), "%s/%u/%u/%u", name->_data, ldns_rr_get_type(rr) , ldns_rr_get_class(rr), ldns_pkt_id(response));
	ldns_buffer_free(name);
	//snprintf(hashkey, sizeof(hashkey), "%s/%u/%u/%u", ldns_rr_owner(rr)->_data, ldns_rr_get_type(rr) , ldns_rr_get_class(rr), ldns_pkt_id(response));

	reqlist = ght_get(opts->correlator, sizeof(hashkey), hashkey);
	if(reqlist == NULL) {
		if(debug) { fprintf(stderr, "Response received from backend, unmappable to front end (%s)", hashkey); }
		return; // MIDRET
		}


	if(servfail==true){

		ldns_rr_list_deep_free(ldns_pkt_answer(response));
		ldns_rr_list_deep_free(ldns_pkt_authority(response));
		ldns_rr_list_deep_free(ldns_pkt_additional(response));

		// these won't leak, IFF we can ldns_pkt_free(response)
		ldns_pkt_set_answer(response, ldns_rr_list_new());
		ldns_pkt_set_authority(response, ldns_rr_list_new());
		ldns_pkt_set_additional(response, ldns_rr_list_new());
		
		ldns_pkt_set_rcode(response, LDNS_RCODE_SERVFAIL);
		response_fixup(response, ldns_pkt_edns_do(response));
		// XXX this is still _occasionally_ 4ing broken packets.  I blame communism.
		}

	// the idea is that we may have multiple requests from the same source, and we want to respond to all of them.

	for(store_cache = ght_first((void *)reqlist, &iterator, &p_key); store_cache; store_cache = ght_next((void *)reqlist, &iterator, &p_key)){
		if(debug) { fprintf(stderr, "sending to: %s:%u\n", inet_ntoa(store_cache->addr.sin_addr), ntohs(store_cache->addr.sin_port)); }
		if(store_cache->edns_do){
			if(response_signed==NULL){
				response_signed = ldns_pkt_clone(response);
				do_sign(ldns_pkt_answer(response), ldns_pkt_answer(response), opts->keylist);
				if(!nsec3_signed_it) do_sign(ldns_pkt_authority(response), ldns_pkt_authority(response), opts->keylist);
				}
			send_response_pkt(response, store_cache, opts);  // XXX we actually need to set >512 if edns missing				
			}
		else {
			send_response_pkt(response, store_cache, opts);  // XXX we actually need to set >512 if edns missing
			}

		LDNS_FREE(store_cache); //FREE1 (a)
		}
	ght_remove(opts->correlator, sizeof(hashkey), hashkey);
	ght_finalize(reqlist);

	if(shortname) ldns_rdf_free(shortname);	
	if(response) ldns_pkt_free(response); //XXX probably buggy
	if(response_signed) ldns_pkt_free(response_signed);
	
}


// SECTION 8:  RESPONSE MANAGERS


void send_response_pkt(ldns_pkt *response, request_cache *store_cache, phreebird_opts *opts){
	uint8_t *newbuf;
	size_t newlen;
	unsigned short newlen_flip;
	int slen = sizeof(struct sockaddr);
	int max = store_cache->edns_size;
	ldns_status status;

	response_fixup(response, store_cache->edns_do);
	
	status = ldns_pkt2wire(&newbuf, response, &newlen);
	if(status != LDNS_STATUS_OK) { pb_abort("couldn't gen packet\n"); } 
	

	if(store_cache->method==METHOD_UDP && max && newlen > max) {
		}

	if(store_cache->method == METHOD_TCP){
		newlen_flip = htons(newlen);
		write(store_cache->clientfd, &newlen_flip, 2);
		write(store_cache->clientfd, newbuf, newlen);
		// not keeping the socket open
		event_del(store_cache->clientevent);
		close(store_cache->clientfd);
		LDNS_FREE(store_cache->clientevent);		
		}
	
	if(store_cache->method == METHOD_UDP){
		if(max && newlen > max){
			LDNS_FREE(newbuf); // XXX
			ldns_pkt_set_tc(response, 1);
			status = ldns_pkt2wire(&newbuf, response, &newlen);
			if(status != LDNS_STATUS_OK) { pb_abort("couldn't gen packet\n"); } 
			newlen = max;
			}
		sendto(opts->stubsock, newbuf, newlen, 0, (void *)&store_cache->addr, slen);
 		}
	if(store_cache->method == METHOD_HTTP){
		http_reply(HTTP_OK, newbuf, newlen, store_cache->req);
		}

	//if(store_cache->req) { evhttp_request_free(store_cache->req);}			
	LDNS_FREE(newbuf);

}




// XXX add caching headers matched with TTL of reply
void http_reply(int rcode, unsigned char *buf, int len, struct evhttp_request *req){
	struct evbuffer *evbuf;
	char *ok = "OK";
	char *bad = "Bad Packet";

	evbuf = evbuffer_new();
	evbuffer_add(evbuf, buf, len);
	evhttp_add_header(req->output_headers, "Content-Type", "binary/dns");
	evhttp_add_header(req->output_headers, "X-DNS-HTTP-Version", "1");
	if(rcode==HTTP_OK) { evhttp_send_reply(req, rcode, ok, evbuf);}
	else               { evhttp_send_reply(req, rcode, bad, evbuf);}

	evbuffer_free(evbuf);
}

ldns_pkt *build_response(ldns_rdf *orig_q, ldns_rr *rr, ldns_key_list *keylist, bool sign){
	ldns_pkt *response;
	ldns_rr *q;
	char buf[256];
	ldns_buffer *lb;
	int i;

	lb = ldns_buffer_new(256);
	ldns_rdf2buffer_str_dname(lb, orig_q);

	// XXX this is truly awful, find out how to fix it

	if(ldns_rr_get_type(rr) == LDNS_RR_TYPE_DNSKEY){
		snprintf(buf, sizeof(buf), "%s IN DNSKEY", lb->_data);
		}
	if(ldns_rr_get_type(rr)  == LDNS_RR_TYPE_DS){
		snprintf(buf, sizeof(buf), "%s IN DS", lb->_data);
		}
	if(ldns_rr_get_type(rr)  == LDNS_RR_TYPE_TXT){
		snprintf(buf, sizeof(buf), "%s IN TXT", lb->_data);
		}
	buf[sizeof(buf)-1]=0;

	response = ldns_pkt_new();
	ldns_rr_new_question_frm_str(&q, buf, NULL, NULL); // API doesn't have "new question frm anything else but str"
	ldns_rr_list_push_rr(ldns_pkt_question(response), q);
	ldns_rr_list_push_rr(ldns_pkt_answer(response), rr);


	// XXX this shouldn't be needed
	//for(i=0; i<ldns_pkt_answer(response)->_rr_count; i++){
	//	ldns_pkt_answer(response)->_rrs[i]->_owner = ldns_rr_owner(q); 
	//	}

	response_fixup(response, 1);
	// XXX faceplam ugly, like this entire section
	if(sign){
		ldns_key_set_pubkey_owner(keylist->_keys[0], ldns_rr_owner(q));
		do_sign(ldns_pkt_answer(response), ldns_pkt_answer(response), keylist);
		response_fixup(response, 1);
		}
	

	ldns_buffer_free(lb);
	

	return response;
	

}


// SECTION 9:  UTILITY



void response_fixup(ldns_pkt *response, int edns){
	if(edns){		
		ldns_pkt_set_edns_do(response, 1);
		ldns_pkt_set_edns_udp_size(response, 4096); // XXX should match client EDNS0 UDP Size
		}

	// XXX there's a bug here I'm just sort of steamrolling over.

	ldns_pkt_set_aa(response, 1); 
	ldns_pkt_set_qr(response, 1);
	ldns_pkt_set_opcode(response, 0);
	//ldns_pkt_set_rcode(response,0);

	// pkts should have all pointers set by ldns itself
	ldns_pkt_set_section_count(response, LDNS_SECTION_QUESTION, ldns_rr_list_rr_count(ldns_pkt_question(response)));
	ldns_pkt_set_section_count(response, LDNS_SECTION_ANSWER, ldns_rr_list_rr_count(ldns_pkt_answer(response)));
	ldns_pkt_set_section_count(response, LDNS_SECTION_AUTHORITY, ldns_rr_list_rr_count(ldns_pkt_authority(response)));
	ldns_pkt_set_section_count(response, LDNS_SECTION_ADDITIONAL, ldns_rr_list_rr_count(ldns_pkt_additional(response)));
}

void drop_sig(void *data, const void *key){
	if(debug) fprintf(stderr, "Dropped signature\n");
	ldns_rr_list_deep_free((ldns_rr_list *)data);
}

int do_sign(ldns_rr_list *dest, ldns_rr_list *src, ldns_key_list *keylist){
	ldns_rr_list *signatures;
	ldns_buffer *sigtext;  // XXX write a better hasher
	ldns_rr *rr;
	int i, j;
	char *buf;
	char c;
	ldns_status status;
	struct timeval now;
	bool rate_exceeded=false;


	if(ldns_rr_list_rr_count(src)==0){ return; }

	// XXX *must* allow cache size to be specified, and allow records to expire!
	if(rrsig_cache == NULL){
		rrsig_cache = ght_create(50*1024);
		ght_set_bounded_buckets(rrsig_cache, 5, drop_sig);
	   if(rrsig_cache == NULL) { pb_abort("couldn't create rrsig_cache\n"); }
		}

	sigtext = ldns_buffer_new(8192); // XXX might need to grow
	if(sigtext==NULL) { pb_abort("couldn't create sigtext\n"); }

	ldns_rr_list_sort(src); // XXX technically this is destructive, but yadda yadda RFC 1034/1035.  May add a shuffler after though.  We do this so caching works right.

	status = ldns_rr_list2buffer_str(sigtext, src); // XXX probably want to change this to wire
	if(status != LDNS_STATUS_OK) { pb_abort("couldn't convert list 2 buffer\n"); }

	signatures = ght_get(rrsig_cache, sigtext->_position, sigtext->_data);
	if(debug) fprintf(stderr, "We found: %x\n", signatures);
	if(signatures == NULL){
		if(debug) fprintf(stderr, "generating sigs\n");

		// XXX This rate limiter is a bit ghetto.  Should work, though.
		if(ldns_rr_list_rr_count(src)>0 &&
		   ldns_rr_list_rr(src, 0)->_rr_type == LDNS_RR_TYPE_NSEC3){
		   	gettimeofday(&now, NULL);
			if(nsec3_rater.sec != now.tv_sec){
				nsec3_rater.count=0;
				nsec3_rater.sec = now.tv_sec;
				}
			nsec3_rater.count++;
			if(nsec3_rater.count > nsec3_rater.max) { rate_exceeded=true; goto end; }
			}
		   
		signatures = ldns_sign_public(src, keylist);
		// We tolerate this returning NULL
		for(i=0; i<signatures->_rr_count; i++){
			rr = signatures->_rrs[i];
		}
		if(signatures) {
			if(debug) fprintf(stderr, "We are writing: %x\n", signatures);
			ght_insert(rrsig_cache, signatures, sigtext->_position, sigtext->_data);
			}
		}

	if(signatures){		
		ldns_rr_list_push_rr_list(dest, ldns_rr_list_clone(signatures));
		}
	end:
	ldns_buffer_free(sigtext);	
	if(rate_exceeded==true) { return -1; }
	return(1);
}


ldns_rr_list *build_nsec3_response(ldns_rdf *name, ldns_rdf *shortname, char *mask, bool do_bangbang){
	char salt[2];
	ldns_rdf *hashed_owner;
	BIGNUM *left, *right;
	ldns_status status;
	int llen, rlen, len;
	char *lbuf, *rbuf;
	ldns_rr_list *nsec3_rr_list = NULL;
	char nsec_descrip[2048];
	char lhash[64], rhash[64];
	ldns_rr *nsec3_rr;
	ldns_buffer *shortname_buf = NULL;
	char buf[1024];
	
	// 0:  Get a shortname buffer
	shortname_buf = ldns_buffer_new(2048);
	if(shortname_buf == NULL) { pb_abort("couldn't create shortname_buf\n"); }
	ldns_rdf2buffer_str_dname(shortname_buf, shortname);
	
	// XXX allow variable salt	
	salt[0] = 0x12;
	salt[1] = 0x90;
	hashed_owner = ldns_nsec3_hash_name(name, 1, 1, 2, (void *)salt);	
	if(hashed_owner == NULL) { pb_abort("couldn't create hashed_owner\n"); }
	
	
	// set that pesky extra dot to a null
	//c = strchr(hashed_owner->_data, '.');
	//*c = 0;
	
	len = ldns_b32_pton_extended_hex(hashed_owner->_data, strlen(hashed_owner->_data),
							   buf, sizeof(buf));
	
	left  = BN_new(); //ALLOC5
	right = BN_new(); //ALLOC6
	if(left==NULL || right==NULL) { pb_abort("couldn't create bignum\n"); }
	
	BN_bin2bn(buf, len, left);
	
	BN_copy(right, left);

	if(do_bangbang) BN_sub_word(left, 1);
	
	BN_add_word(right, 1);
	
	
	llen = BN_num_bytes(left);
	lbuf = calloc(llen, 1); //ALLOC7
	if(lbuf == NULL) { pb_abort("couldn't allocate buf"); }
	BN_bn2bin(left, lbuf);	// XXX OK openSSL I don't like your API
	
	rlen = BN_num_bytes(right);
	rbuf = calloc(rlen, 1); //ALLOC8
	if(rbuf == NULL) { pb_abort("couldn't allocate buf"); }
	BN_bn2bin(right, rbuf);  // XXX OK openSSL I don't like your API
	
	ldns_b32_ntop_extended_hex(lbuf, llen, lhash, sizeof(lhash));
	ldns_b32_ntop_extended_hex(rbuf, rlen, rhash, sizeof(rhash));
	
	
	nsec3_rr_list = ldns_rr_list_new(); //ALLOC10
	if(nsec3_rr_list == NULL) { pb_abort("couldn't allocate rr_list"); }
	
	// Whew.  We've got the left and right hashes.	Now to throw them into an NSEC3 record
	// Better yet, figure out how to create these records manually

	if(validate_name(shortname_buf->_data)){
		// validate name restricts to a-zA-Z0-9-_.  Not perfect, but it does suppress injection
		snprintf(nsec_descrip, sizeof(nsec_descrip), "%s.%s 0 IN NSEC3 1 0 1 1290 %s %s",
													lhash, shortname_buf->_data, rhash, mask);
		status = ldns_rr_new_frm_str(&nsec3_rr, nsec_descrip, 0, NULL, NULL); //ALLOC9
		
		//do_sign(ldns_pkt_authority(response), ldns_pkt_authority(response), opts->keylist);
		
		ldns_rr_list_push_rr(nsec3_rr_list, nsec3_rr);		
		//do_sign(nsec3_rr_list, nsec3_rr_list, opts->keylist);
		
		//ldns_rr_list_push_rr_list(ldns_pkt_authority(response), nsec3_rr_list);
		//nsec3_signed_it = true;
		
		//LDNS_FREE(type);
		}
	LDNS_FREE(lbuf);//FREE7
	LDNS_FREE(rbuf);//FREE8
	BN_free(left);//FREE5
	BN_free(right);//FREE6
	
	//BN_print_fp(stderr, bn);
	//fprintf(stderr, "\n");
	//BN_print_fp(stderr, bn2);

	return nsec3_rr_list;

}

void pb_abort(char *str){
	fprintf(stderr, "%s\n", str);
	exit(1);
}

// XXX this is a really cheap hack...for now.  In the long run, we have to start building domains
// from RDF assembly.
// [updated to restrict to a-zA-Z0-9-_, which isn't technically legal anymore (all should be UTF-8 now]

bool validate_name(char *str){
	int i=0;
	while(str[i]!=0){
		if(i>0 && str[i]=='.' && str[i-1]=='.') { return false; }
		if( !(str[i] >= '0' && str[i] <= '9') &&
			!(str[i] >= 'a' && str[i] <= 'z') &&
			!(str[i] >= 'A' && str[i] <= 'Z') &&
			!(str[i] == '-') &&
			!(str[i] == '.') &&
			!(str[i] == '_') ) { return false; }
		i++;
	}
	return true;
}




void do_help(){
	fprintf(stdout, "Phreebird %s:  DNSSEC Supplementation Engine.\n", PB_VERSION);
	fprintf(stdout, "Author:         Dan Kaminsky, dan@doxpara.com\n");
	fprintf(stdout, "WARNING:        THIS IS EXPERIMENTAL CODE THAT SHOULD NOT BE.\n");
	fprintf(stdout, "                DEPLOYED ON PRODUCTION NETWORKS.  Yet.\n");
	fprintf(stdout, "Options:\n");
	fprintf(stdout, "  -k : Filename of private key (default: dns.key)\n");
	fprintf(stdout, "  -l : IP address to listen on (default: 0.0.0.0)\n");
	fprintf(stdout, "  -d : Activate debugging\n");
	fprintf(stdout, "  -m : Set max # of unique NSEC3 responses to sign a second (Default: 200)\n");
	fprintf(stdout, "Dangerous Options:\n");
	fprintf(stdout, "  -g : Generate private key\n");
	fprintf(stdout, "  -b backend_ip:backend_port : Declare the location of the backend to proxy\n");	
	fprintf(stdout, "     (DO NOT ALLOW INTERNET TO SPOOF BACKEND TO PHREEBIRD.)\n");	
	
}
	

