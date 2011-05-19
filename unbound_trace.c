#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <unbound.h>

static struct ub_ctx* uctx = NULL;

#define TYPE_A 1
#define TYPE_TXT 16
struct ub_result* unbound_trace(char *domain, int type){
	int retval;
	struct ub_result *result;
	if(uctx == NULL){  uctx = ub_ctx_create(); }
	
	//ub_ctx_hosts(uctx, "/etc/hosts");//XXX need to check if there is one, make xplatform, etc
	//ub_ctx_set_option(uctx, "do-ip6:", "no"); // This lowers traffic, but you know, breaks IPv6.  Need smarter heuristics
	ub_ctx_set_option(uctx, "prefetch-key:", "yes"); // Speeds things up

	// XXX Long term:  Need a good way to persistently update this via RFC 5011
	ub_ctx_add_ta(uctx, ".                       9999999   IN      DNSKEY  257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=");
	retval = ub_resolve(uctx, domain, TYPE_A, 1, &result);
	return result;
}

int main(int argc, char **argv){
	struct ub_result *answers;
	char *domain = "www.pir.org";
	struct in_addr a;
	int i;

	if(argv[1]) { domain = argv[1]; }
	answers = unbound_trace(domain, TYPE_A);

	if(answers->secure)   { fprintf(stdout, "DNSSEC validation successful for domain %s.\n", domain); }
	if(answers->secure && answers->data[0]==NULL) { fprintf(stdout, "Unfortunately, this domain does not exist (but we have proof of that).\n"); }
	if(answers->bogus)                        { fprintf(stdout, "Possible attack on this domain.\n"); }
	if(answers->data[0]!=NULL) { 
		fprintf(stdout, "DNS Replies received.\n");
		for(i=0; answers->data[i]; i++){
			memcpy(&a.s_addr, answers->data[i], 4);
			fprintf(stdout, "%s: %s\n", domain, inet_ntoa(a));
		}
	}
}
	


