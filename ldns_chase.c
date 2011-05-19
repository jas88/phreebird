#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <ldns/ldns.h>



ldns_rr_list *ldns_chase(char *name, int type, char *nsname, bool secure, bool debug, ldns_status *status){

	ldns_resolver *res=NULL;
	ldns_rdf *ns=NULL;
	ldns_rdf *domain=NULL;
	ldns_rr_list *answers=NULL;
	ldns_rr_list *trusted_keys=NULL;
	ldns_pkt *answer=NULL;
	ldns_rr *rr=NULL;
	ldns_rr *rr1=NULL;
	ldns_rr *orig_rr=NULL;
	ldns_rr_list *ret = NULL;
	ldns_dnssec_data_chain *chain=NULL;
	ldns_dnssec_trust_tree *tree=NULL;
	int i=0;
	
	res = ldns_resolver_new();
	ldns_resolver_set_dnssec(res, 1);

	ns = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, nsname);
	ldns_resolver_push_nameserver(res, ns);	
	domain = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, name);

	trusted_keys = ldns_rr_list_new();

	ldns_rr_new_frm_str(&rr1, ".						43200	IN		DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=", 900000, NULL, NULL);
	ldns_rr_list_push_rr(trusted_keys, rr1);
	ldns_rr_list_push_rr(trusted_keys, ldns_key_rr2ds(rr1, LDNS_SHA1));
	
	answer=ldns_resolver_query(res, domain, type, LDNS_RR_CLASS_IN, LDNS_RD|LDNS_CD);
	if(secure==0) { ret = answer->_answer; goto cleanup;}

	answers = ldns_rr_list_new();
	orig_rr = ldns_rr_new();
		
	for(i=0; i<answer->_answer->_rr_count; i++){
		rr = answer->_answer->_rrs[i];
		if(rr->_rr_type != LDNS_RR_TYPE_RRSIG) ldns_rr_list_push_rr(answers, rr);
		}

	if (ldns_pkt_ancount(answer) < 1) {
			ldns_rr_set_type(orig_rr, type);
			ldns_rr_set_owner(orig_rr, ldns_rdf_clone(domain));
			chain = ldns_dnssec_build_data_chain(res, LDNS_RD|LDNS_CD, answers, answer, ldns_rr_clone(orig_rr));
	} else {
			/* chase the first answer */
			chain = ldns_dnssec_build_data_chain(res, LDNS_RD|LDNS_CD, answers, answer, NULL);
	}
	
	tree =ldns_dnssec_derive_trust_tree(chain, NULL);
	if(status!=NULL){
		*status=ldns_dnssec_trust_tree_contains_keys(tree, trusted_keys);		
		}
	if(*status==LDNS_STATUS_OK) { ret = answer->_answer; }

	ldns_dnssec_trust_tree_print(stdout, tree, 3, 1);

cleanup:
	if(res) free(res);
	if(ns)  free(ns);
	if(domain) free(domain);
	if(answers)free(answers);
	if(trusted_keys) free(trusted_keys);
	if(answer)       free(answer);
	if(rr)           free(rr);
	if(rr1)          free(rr1);
	if(orig_rr)      free(orig_rr);
	return(ret);
	
}

int main(int argc, char **argv){
	ldns_status status;
	ldns_rr_list *answers;
	char *domain = "www.pir.org";
	int i;

	if(argv[1]) { domain = argv[1]; }
	answers=ldns_chase(domain, LDNS_RR_TYPE_A, "4.2.2.2", 1, 1, &status);
	fprintf(stdout, "%s\n", ldns_get_errorstr_by_id(status));
	ldns_rr_list_print(stdout, answers); // XXX 1.01 will have a proper rr_list parser (CNAME handling is important)

}

