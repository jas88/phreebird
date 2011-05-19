#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>

//#include "cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>

#include <errno.h>
#include <arpa/inet.h>
#include <unbound.h>

#include <dlfcn.h>


static struct ub_ctx* uctx = NULL;

#define SEEKING_VERSION -1
#define SEEKING_KEY 0
#define SEEKING_ENDKEY 1
#define SEEKING_VALUE 2
#define SEEKING_ENDVALUE 3

struct dnstxt_opts_struct {
	int version;
	char *hash;
	char *hash_algorithm;
	char *hash_range;
	int livehash;
	int sts;
	int secure_reneg;
	char *str;
	
};
typedef struct dnstxt_opts_struct dnstxt_opts;	
	
dnstxt_opts *parse_dnstxt(char *lstr, dnstxt_opts *opts);
int populate_dnstxt(char *key, char *value, dnstxt_opts *opts);


dnstxt_opts *parse_dnstxt(char *lstr, dnstxt_opts *opts)
{
	char *str;
	char *key, *value;
	int state = SEEKING_VERSION;
	int i=0;
	str = strdup(lstr);
	opts->str = str;
	int len;

	key=value=NULL;

	len=strlen(str);
	while(i++<=len+1){ // includes the null
		if(str[i]=='\'') { str[i]=' '; continue; } // cheap hack
		if(state == SEEKING_VERSION){
			if(str[i]=='v'){
				key = str+i;
				state = SEEKING_ENDKEY; // XXX ugh
				goto eol;
				}
			}
		if(state == SEEKING_KEY){
			if(str[i]!=' ') {
				key = str+i;
				state = SEEKING_ENDKEY;
				goto eol;
				}
			}
		if(state == SEEKING_ENDKEY){
			if(str[i]=='='){
				str[i]=0;
				state = SEEKING_VALUE;
				goto eol;
				}
			}
		if(state == SEEKING_VALUE){
			if(str[i]!=' '){
				value = str+i;
				state = SEEKING_ENDVALUE;
				goto eol;
				}
			}
		if(state == SEEKING_ENDVALUE){
			if(str[i]==' ' || str[i]==0){
				str[i]=0;
				populate_dnstxt(key, value, opts);
				state = SEEKING_KEY;
				}
			}
		eol:
			state=state;
	}
	return opts;
}

#define VERSION "v"
#define HASH    "h"
#define HASH_ALGORITHM "ha"
#define STS     "sts"
#define SECURE_RENEGOTIATE "sr"
#define LIVEHASH "lh"
#define HASHRANGE "hr"


int populate_dnstxt(char *key, char *value, dnstxt_opts *opts){
	if(strncmp(key, VERSION, sizeof(VERSION)+1)==0) {
		if(strncmp(value, "key", 3)==0 && strlen(value)==4) opts->version = atoi(&value[3]);
		}
	if(strncmp(key, HASH_ALGORITHM, sizeof(HASH_ALGORITHM)+1)==0) { opts->hash_algorithm = value; }
	if(strncmp(key, HASH, sizeof(HASH_ALGORITHM)+1)==0) { opts->hash = value; }
	if(strncmp(key, STS, sizeof(STS)+1)==0) { opts->sts = atoi(value); }
	if(strncmp(key, SECURE_RENEGOTIATE, sizeof(SECURE_RENEGOTIATE)+1)==0) { opts->secure_reneg = atoi(value); }
	if(strncmp(key, LIVEHASH, sizeof(LIVEHASH)+1)==0) { opts->livehash = atoi(value); }
	if(strncmp(key, HASHRANGE, sizeof(HASHRANGE)+1)==0) { opts->hash_range = value; }
	return(1);

}


int envdebug(){
	return (getenv("DNSSEC_DEBUG") && strncmp(getenv("DNSSEC_DEBUG"), "1", 2)==0);
}

dnstxt_opts *dnstxt_opts_new(){
	dnstxt_opts *opts;
	opts = calloc(sizeof(struct dnstxt_opts_struct), 1);
	// caller should check for null
	return opts;
}

void dnstxt_opts_free(dnstxt_opts *opts){
	if(opts->str != NULL) { free(opts->str); }
	free(opts);
}

#define HASH_RANGE_PUBKEY "pubkey"

int X509_verify_cert(X509_STORE_CTX *ctx)
{
	static int (*X509_verify_cert_orig)(X509_STORE_CTX *) = NULL;
	dnstxt_opts *opts = NULL;
	char data[1024];
	char buf[256];
	char hashhex[64];
	char *livehashhex = NULL;
	int i;
	int done;
	int livehash = 0;
	int good = 0;
	int found = 0;
	char *restxt;

	struct ub_result* result;
	int retval;

	
	
	if(X509_verify_cert_orig == NULL){
	   X509_verify_cert_orig = (int (*)()) dlsym(RTLD_NEXT, "X509_verify_cert");
		}

	//OK, lets try to interrogate this puppy

	X509_NAME_get_text_by_NID (ctx->cert->cert_info->subject, NID_commonName, data, sizeof(data));

	unsigned int n;
	unsigned char md[EVP_MAX_MD_SIZE];
	const EVP_MD *fdig;

	fdig = EVP_sha1();


	

	/* OK, we've got the basic data.  lets load in LDNS */
	if(uctx == NULL){ 
		uctx = ub_ctx_create();
		}

	// XXX what if /etc/hosts doesn't exist?
	ub_ctx_hosts(uctx, "/etc/hosts");
	ub_ctx_set_option(uctx, "do-ip6:", "no"); // Yes, I know this kills perf. Ideally, we're not using libunbound at all
	ub_ctx_set_option(uctx, "prefetch-key:", "yes");

	//ub_ctx_add_ta_file(uctx, "/etc/ssh/dns_keys"); //XXX have to figure out how to read out of openssl.cnf, will just borrow from ssh for now
	// XXX Long term:  Need a good way to persistently update this via RFC 5011
	//ub_ctx_add_ta(uctx, ". DNSKEY 256 3 8 AwEAAb1gcDhBlH/9MlgUxS0ik2dwY/JiBIpV+EhKZV7LccxNc6Qlj467 QjHQ3Fgm2i2LE9w6LqPFDSng5qVq1OYFyTBt3DQppqDnAPriTwW5qIQN DNFv34yo63sAdBeU4G9tv7dzT5sPyAgmVh5HDCe+6XM2+Iel1+kUKCel 8Icy19hR");
	ub_ctx_add_ta(uctx, ".                       9999999   IN      DNSKEY  257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=");


	// XXX There is a _tremendous_ amount of drama around the correct schema to use.
	// We don't want to force the issue, but we also want to give people a good starting point.
	
	snprintf(buf, sizeof(buf), "%s", data);

	#define TYPE_TXT 16
	retval = ub_resolve(uctx, buf, TYPE_TXT, 1, &result);
	if(envdebug()){ fprintf(stderr, "Resolving %s\n", buf); }

	if(result->havedata && result->secure) {		
		if(envdebug()){ fprintf(stderr, "Secure result recieved.\n"); }
		// Not enough -- have to validate that we actually *have* the hash as expected
		done=0;
		for(i=0; result->data[i] && !done; i++){
			opts = dnstxt_opts_new();
			restxt = calloc(result->len[i]+1, 1); // XXX someday, additive overflows like this are really going to burn us.  Not here though.
			memcpy(restxt, result->data[i], result->len[i]);
			parse_dnstxt(restxt, opts);
			free(restxt);
			// if hash range is across the pubkey, hash that, otherwise hash the entire cert.
			// XXX not 100% convinced that pubkey hashing is a good idea, but some people really
			// want this for operational reasons.  Must.  Respect.  Ops.
			if(opts->hash_range && strncmp(opts->hash_range, HASH_RANGE_PUBKEY, sizeof(HASH_RANGE_PUBKEY))==0) {				
				//hash_range = opts->hash_range;
				if(ctx->cert && ctx->cert->cert_info && ctx->cert->cert_info->key && ctx->cert->cert_info->key->public_key){
					ASN1_item_digest(ASN1_ITEM_rptr(ASN1_BIT_STRING),fdig,ctx->cert->cert_info->key->public_key,md,&n);
					}
			} else {				
				X509_digest(ctx->cert,fdig,md,&n);
			}
			snprintf(hashhex, sizeof(hashhex), "%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x", 
					md[0], md[1], md[2], md[3], md[4], md[5], md[6], md[7], md[8], md[9], 
					md[10], md[11], md[12], md[13], md[14], md[15], md[16], md[17], md[18], md[19]);
			hashhex[40]=0;
			
			if(envdebug()){ fprintf(stderr, "V:%i  Hash Algorithm:%s  Hash:%s  STS:%i.  Secure Reneg:%i  Livehash:%i  Hash Range:%s\n",
				opts->version, opts->hash_algorithm, opts->hash, opts->sts, opts->secure_reneg, opts->livehash, opts->hash_range); }
			
			if(opts->version!=1) { continue;}
			if(opts->livehash == 1) {				
				if(envdebug()){ fprintf(stderr, "Livehash claim detected.\n"); }
				found=1; livehash=1;
				// So the deal is, there could be multiple TXT records, some pubkey, some certhash.  We want to capture the hash 
				// XXX do we want to allow livehash lookups for *both* pubkey *and* cert?
				// This says we can have only _one_ livehash lookup, last one wins, and since there's reordering of DNS records,
				// you don't know which wins.
				if(livehashhex != NULL) { free(livehashhex); }
				livehashhex = strdup(hashhex);
				continue;
				}
			if(opts->hash_algorithm && opts->hash) {				
				if(envdebug()){ fprintf(stderr, "Hash detected:  %s %s\n", opts->hash_algorithm, opts->hash); }
				found=1; // this is the excluder -- *something* was securely declared
				// XXX support other ha's besides sha1
				if(opts->hash_algorithm && strncmp(opts->hash_algorithm, "sha1", 4) !=0) { continue; }
				if(strncmp(hashhex, opts->hash, strlen(hashhex))==0) { 					
					if(envdebug()){ fprintf(stderr, "Hash Validated\n"); }
					good=1; break;}
				}
			// XXX add handlers for STS / SR?  They're really consumed elsewhere.
			if(!good){
				dnstxt_opts_free(opts);
				opts=NULL;
				}
			}
		}
	ub_resolve_free(result);

	if(!good && livehash){
		snprintf(buf, sizeof(buf), "_keyhash-%s._ex.%s", livehashhex, data);
		if(envdebug()){ fprintf(stderr, "Resolving %s\n", buf); }
		retval = ub_resolve(uctx, buf, TYPE_TXT, 1, &result);

		if(result->havedata && result->secure) {
			// technically if there's ANYTHING here, it's cool.
			if(envdebug()){ fprintf(stderr, "Secure result found for %s\n", buf); }
 			good=1;
		} // we've validated this particular certificate
	}

	if(livehashhex != NULL) { free(livehashhex); }

	// We know this is good
	if(good) { 
		if(envdebug()){ fprintf(stderr, "DNSSEC validated\n"); }
		return 1; }
	// DNSSEC doesn't know -- ask X.509 CA
	if(!found) { 
		if(envdebug()){ fprintf(stderr, "No DNSSEC answer.  Falling back to X.509 CA.\n"); }
		return X509_verify_cert_orig(ctx); }
	// DNSSEC knows...and something's up.
	if(envdebug()){ fprintf(stderr, "DNSSEC validated, but hash did not match.  Rejecting.\n"); }
	return 0;
	
	

}


