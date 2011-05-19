/*
 * validator/val_sigcrypt.c - validator signature crypto functions.
 *
 * Copyright (c) 2007, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * This file contains helper functions for the validator module.
 * The functions help with signature verification and checking, the
 * bridging between RR wireformat data and crypto calls.
 */
#include "config.h"
#include "validator/val_sigcrypt.h"
#include "validator/validator.h"
#include "util/data/msgreply.h"
#include "util/data/msgparse.h"
#include "util/data/dname.h"
#include "util/rbtree.h"
#include "util/module.h"
#include "util/net_help.h"
#include "util/regional.h"

#ifndef HAVE_SSL
#error "Need SSL library to do digital signature cryptography"
#endif

/** return number of rrs in an rrset */
static size_t
rrset_get_count(struct ub_packed_rrset_key* rrset)
{
	struct packed_rrset_data* d = (struct packed_rrset_data*)
	rrset->entry.data;
	if(!d) return 0;
	return d->count;
}

/**
 * Get RR signature count
 */
static size_t
rrset_get_sigcount(struct ub_packed_rrset_key* k)
{
	struct packed_rrset_data* d = (struct packed_rrset_data*)k->entry.data;
	return d->rrsig_count;
}

/**
 * Get signature keytag value
 * @param k: rrset (with signatures)
 * @param sig_idx: signature index.
 * @return keytag or 0 if malformed rrsig.
 */
static uint16_t 
rrset_get_sig_keytag(struct ub_packed_rrset_key* k, size_t sig_idx)
{
	uint16_t t;
	struct packed_rrset_data* d = (struct packed_rrset_data*)k->entry.data;
	log_assert(sig_idx < d->rrsig_count);
	if(d->rr_len[d->count + sig_idx] < 2+18)
		return 0;
	memmove(&t, d->rr_data[d->count + sig_idx]+2+16, 2);
	return ntohs(t);
}

/**
 * Get signature signing algorithm value
 * @param k: rrset (with signatures)
 * @param sig_idx: signature index.
 * @return algo or 0 if malformed rrsig.
 */
static int 
rrset_get_sig_algo(struct ub_packed_rrset_key* k, size_t sig_idx)
{
	struct packed_rrset_data* d = (struct packed_rrset_data*)k->entry.data;
	log_assert(sig_idx < d->rrsig_count);
	if(d->rr_len[d->count + sig_idx] < 2+3)
		return 0;
	return (int)d->rr_data[d->count + sig_idx][2+2];
}

/** get rdata pointer and size */
static void
rrset_get_rdata(struct ub_packed_rrset_key* k, size_t idx, uint8_t** rdata,
	size_t* len)
{
	struct packed_rrset_data* d = (struct packed_rrset_data*)k->entry.data;
	log_assert(d && idx < (d->count + d->rrsig_count));
	*rdata = d->rr_data[idx];
	*len = d->rr_len[idx];
}

uint16_t
dnskey_get_flags(struct ub_packed_rrset_key* k, size_t idx)
{
	uint8_t* rdata;
	size_t len;
	uint16_t f;
	rrset_get_rdata(k, idx, &rdata, &len);
	if(len < 2+2)
		return 0;
	memmove(&f, rdata+2, 2);
	f = ntohs(f);
	return f;
}

/**
 * Get DNSKEY protocol value from rdata
 * @param k: DNSKEY rrset.
 * @param idx: which key.
 */
static int
dnskey_get_protocol(struct ub_packed_rrset_key* k, size_t idx)
{
	uint8_t* rdata;
	size_t len;
	rrset_get_rdata(k, idx, &rdata, &len);
	if(len < 2+4)
		return 0;
	return (int)rdata[2+2];
}

int
dnskey_get_algo(struct ub_packed_rrset_key* k, size_t idx)
{
	uint8_t* rdata;
	size_t len;
	rrset_get_rdata(k, idx, &rdata, &len);
	if(len < 2+4)
		return 0;
	return (int)rdata[2+3];
}

/** get public key rdata field from a dnskey RR and do some checks */
static void
dnskey_get_pubkey(struct ub_packed_rrset_key* k, size_t idx,
	unsigned char** pk, unsigned int* pklen)
{
	uint8_t* rdata;
	size_t len;
	rrset_get_rdata(k, idx, &rdata, &len);
	if(len < 2+5) {
		*pk = NULL;
		*pklen = 0;
		return;
	}
	*pk = (unsigned char*)rdata+2+4;
	*pklen = (unsigned)len-2-4;
}

int
ds_get_key_algo(struct ub_packed_rrset_key* k, size_t idx)
{
	uint8_t* rdata;
	size_t len;
	rrset_get_rdata(k, idx, &rdata, &len);
	if(len < 2+3)
		return 0;
	return (int)rdata[2+2];
}

int
ds_get_digest_algo(struct ub_packed_rrset_key* k, size_t idx)
{
	uint8_t* rdata;
	size_t len;
	rrset_get_rdata(k, idx, &rdata, &len);
	if(len < 2+4)
		return 0;
	return (int)rdata[2+3];
}

uint16_t 
ds_get_keytag(struct ub_packed_rrset_key* ds_rrset, size_t ds_idx)
{
	uint16_t t;
	uint8_t* rdata;
	size_t len;
	rrset_get_rdata(ds_rrset, ds_idx, &rdata, &len);
	if(len < 2+2)
		return 0;
	memmove(&t, rdata+2, 2);
	return ntohs(t);
}

/**
 * Return pointer to the digest in a DS RR.
 * @param k: DS rrset.
 * @param idx: which DS.
 * @param digest: digest data is returned.
 *	on error, this is NULL.
 * @param len: length of digest is returned.
 *	on error, the length is 0.
 */
static void
ds_get_sigdata(struct ub_packed_rrset_key* k, size_t idx, uint8_t** digest,
        size_t* len)
{
	uint8_t* rdata;
	size_t rdlen;
	rrset_get_rdata(k, idx, &rdata, &rdlen);
	if(rdlen < 2+5) {
		*digest = NULL;
		*len = 0;
		return;
	}
	*digest = rdata + 2 + 4;
	*len = rdlen - 2 - 4;
}

/**
 * Return size of DS digest according to its hash algorithm.
 * @param k: DS rrset.
 * @param idx: which DS.
 * @return size in bytes of digest, or 0 if not supported. 
 */
static size_t
ds_digest_size_algo(struct ub_packed_rrset_key* k, size_t idx)
{
	switch(ds_get_digest_algo(k, idx)) {
#ifdef HAVE_EVP_SHA1
		case LDNS_SHA1:
			return SHA_DIGEST_LENGTH;
#endif
#ifdef HAVE_EVP_SHA256
		case LDNS_SHA256:
			return SHA256_DIGEST_LENGTH;
#endif
#ifdef USE_GOST
		case LDNS_HASH_GOST94:
			if(EVP_get_digestbyname("md_gost94"))
				return 32;
			else	return 0;
#endif
		default: break;
	}
	return 0;
}

#ifdef USE_GOST
/** Perform GOST94 hash */
static int
do_gost94(unsigned char* data, size_t len, unsigned char* dest)
{
	const EVP_MD* md = EVP_get_digestbyname("md_gost94");
	if(!md) 
		return 0;
	return ldns_digest_evp(data, (unsigned int)len, dest, md);
}
#endif

/**
 * Create a DS digest for a DNSKEY entry.
 *
 * @param env: module environment. Uses scratch space.
 * @param dnskey_rrset: DNSKEY rrset.
 * @param dnskey_idx: index of RR in rrset.
 * @param ds_rrset: DS rrset
 * @param ds_idx: index of RR in DS rrset.
 * @param digest: digest is returned in here (must be correctly sized).
 * @return false on error.
 */
static int
ds_create_dnskey_digest(struct module_env* env, 
	struct ub_packed_rrset_key* dnskey_rrset, size_t dnskey_idx,
	struct ub_packed_rrset_key* ds_rrset, size_t ds_idx,
	uint8_t* digest)
{
	ldns_buffer* b = env->scratch_buffer;
	uint8_t* dnskey_rdata;
	size_t dnskey_len;
	rrset_get_rdata(dnskey_rrset, dnskey_idx, &dnskey_rdata, &dnskey_len);

	/* create digest source material in buffer 
	 * digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
	 *	DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key. */
	ldns_buffer_clear(b);
	ldns_buffer_write(b, dnskey_rrset->rk.dname, 
		dnskey_rrset->rk.dname_len);
	query_dname_tolower(ldns_buffer_begin(b));
	ldns_buffer_write(b, dnskey_rdata+2, dnskey_len-2); /* skip rdatalen*/
	ldns_buffer_flip(b);
	
	switch(ds_get_digest_algo(ds_rrset, ds_idx)) {
#ifdef HAVE_EVP_SHA1
		case LDNS_SHA1:
			(void)SHA1((unsigned char*)ldns_buffer_begin(b),
				ldns_buffer_limit(b), (unsigned char*)digest);
			return 1;
#endif
#ifdef HAVE_EVP_SHA256
		case LDNS_SHA256:
			(void)SHA256((unsigned char*)ldns_buffer_begin(b),
				ldns_buffer_limit(b), (unsigned char*)digest);
			return 1;
#endif
#ifdef USE_GOST
		case LDNS_HASH_GOST94:
			if(do_gost94((unsigned char*)ldns_buffer_begin(b), 
				ldns_buffer_limit(b), (unsigned char*)digest))
				return 1;
#endif
		default: 
			verbose(VERB_QUERY, "unknown DS digest algorithm %d", 
				(int) ds_get_digest_algo(ds_rrset, ds_idx));
			break;
	}
	return 0;
}

int ds_digest_match_dnskey(struct module_env* env,
	struct ub_packed_rrset_key* dnskey_rrset, size_t dnskey_idx,
	struct ub_packed_rrset_key* ds_rrset, size_t ds_idx)
{
	uint8_t* ds;	/* DS digest */
	size_t dslen;
	uint8_t* digest; /* generated digest */
	size_t digestlen = ds_digest_size_algo(ds_rrset, ds_idx);
	
	if(digestlen == 0) {
		verbose(VERB_QUERY, "DS fail: not supported, or DS RR "
			"format error");
		return 0; /* not supported, or DS RR format error */
	}
	/* check digest length in DS with length from hash function */
	ds_get_sigdata(ds_rrset, ds_idx, &ds, &dslen);
	if(!ds || dslen != digestlen) {
		verbose(VERB_QUERY, "DS fail: DS RR algo and digest do not "
			"match each other");
		return 0; /* DS algorithm and digest do not match */
	}

	digest = regional_alloc(env->scratch, digestlen);
	if(!digest) {
		verbose(VERB_QUERY, "DS fail: out of memory");
		return 0; /* mem error */
	}
	if(!ds_create_dnskey_digest(env, dnskey_rrset, dnskey_idx, ds_rrset, 
		ds_idx, digest)) {
		verbose(VERB_QUERY, "DS fail: could not calc key digest");
		return 0; /* digest algo failed */
	}
	if(memcmp(digest, ds, dslen) != 0) {
		verbose(VERB_QUERY, "DS fail: digest is different");
		return 0; /* digest different */
	}
	return 1;
}

int 
ds_digest_algo_is_supported(struct ub_packed_rrset_key* ds_rrset, 
	size_t ds_idx)
{
	return (ds_digest_size_algo(ds_rrset, ds_idx) != 0);
}

/** return true if DNSKEY algorithm id is supported */
static int
dnskey_algo_id_is_supported(int id)
{
	switch(id) {
	case LDNS_DSA:
	case LDNS_DSA_NSEC3:
	case LDNS_RSASHA1:
	case LDNS_RSASHA1_NSEC3:
	case LDNS_RSAMD5:
#if defined(HAVE_EVP_SHA256) && defined(USE_SHA2)
	case LDNS_RSASHA256:
#endif
#if defined(HAVE_EVP_SHA512) && defined(USE_SHA2)
	case LDNS_RSASHA512:
#endif
		return 1;
#ifdef USE_GOST
	case LDNS_GOST:
		/* we support GOST if it can be loaded */
		return ldns_key_EVP_load_gost_id();
#endif
	default:
		return 0;
	}
}

int 
ds_key_algo_is_supported(struct ub_packed_rrset_key* ds_rrset, 
	size_t ds_idx)
{
	return dnskey_algo_id_is_supported(ds_get_key_algo(ds_rrset, ds_idx));
}

uint16_t 
dnskey_calc_keytag(struct ub_packed_rrset_key* dnskey_rrset, size_t dnskey_idx)
{
	uint8_t* data;
	size_t len;
	rrset_get_rdata(dnskey_rrset, dnskey_idx, &data, &len);
	/* do not pass rdatalen to ldns */
	return ldns_calc_keytag_raw(data+2, len-2);
}

int dnskey_algo_is_supported(struct ub_packed_rrset_key* dnskey_rrset,
        size_t dnskey_idx)
{
	return dnskey_algo_id_is_supported(dnskey_get_algo(dnskey_rrset, 
		dnskey_idx));
}

/**
 * Fillup needed algorithm array for DNSKEY set
 * @param dnskey: the key
 * @param needs: array per algorithm.
 * @return the number of algorithms that need valid signatures
 */
static size_t
dnskeyset_needs(struct ub_packed_rrset_key* dnskey, uint8_t needs[])
{
	uint8_t algo;
	size_t i, total = 0;
	size_t num = rrset_get_count(dnskey);

	memset(needs, 0, sizeof(uint8_t)*256);
	for(i=0; i<num; i++) {
		algo = (uint8_t)dnskey_get_algo(dnskey, i);
		if(needs[algo] == 0) {
			needs[algo] = 1;
			total++;
		}
	}
	return total;
}

/** see which algo needed */
static int any_needed_bogus(uint8_t needs[])
{
	int i;
	/* first check if a needed algo was bogus - report that */
	for(i=0; i<256; i++)
		if(needs[i] == 2)
			return 0;
	/* now check which algo is missing */
	for(i=0; i<256; i++)
		if(needs[i] == 1)
			return i;
	return 0;
}

enum sec_status 
dnskeyset_verify_rrset(struct module_env* env, struct val_env* ve,
	struct ub_packed_rrset_key* rrset, struct ub_packed_rrset_key* dnskey,
	char** reason)
{
	enum sec_status sec;
	size_t i, num, numneeds;
	rbtree_t* sortree = NULL;
	/* make sure that for all DNSKEY algorithms there are valid sigs */
	uint8_t needs[256]; /* 1 if need sig for that algorithm */
	int alg;

	num = rrset_get_sigcount(rrset);
	if(num == 0) {
		verbose(VERB_QUERY, "rrset failed to verify due to a lack of "
			"signatures");
		*reason = "no signatures";
		return sec_status_bogus;
	}

	numneeds = dnskeyset_needs(dnskey, needs);
	for(i=0; i<num; i++) {
		sec = dnskeyset_verify_rrset_sig(env, ve, *env->now, rrset, 
			dnskey, i, &sortree, reason);
		/* see which algorithm has been fixed up */
		if(sec == sec_status_secure) {
			uint8_t a = (uint8_t)rrset_get_sig_algo(rrset, i);
			if(needs[a]) {
				needs[a] = 0;
				numneeds --;
				if(numneeds == 0) /* done! */
					return sec;
			}
		} else if(sec == sec_status_bogus) {
			uint8_t a = (uint8_t)rrset_get_sig_algo(rrset, i);
			if(needs[a]) needs[a] = 2; /* need it, but bogus */
		}
	}
	verbose(VERB_ALGO, "rrset failed to verify: no valid signatures for "
		"%d algorithms", (int)numneeds);
	if((alg=any_needed_bogus(needs)) != 0) {
		char buf[256];
		ldns_lookup_table *t = ldns_lookup_by_id(ldns_algorithms, alg);
		if(t&&t->name)
			snprintf(buf, sizeof(buf), "no signatures with "
				"algorithm %s", t->name);
		else	snprintf(buf, sizeof(buf), "no signatures with "
				"algorithm ALG%u", (unsigned)alg);
		*reason = regional_strdup(env->scratch, buf);
		if(!*reason)
			*reason = "no signatures for all algorithms";
	}
	return sec_status_bogus;
}

enum sec_status 
dnskey_verify_rrset(struct module_env* env, struct val_env* ve,
        struct ub_packed_rrset_key* rrset, struct ub_packed_rrset_key* dnskey,
	size_t dnskey_idx, char** reason)
{
	enum sec_status sec;
	size_t i, num, numchecked = 0;
	rbtree_t* sortree = NULL;
	int buf_canon = 0;
	uint16_t tag = dnskey_calc_keytag(dnskey, dnskey_idx);
	int algo = dnskey_get_algo(dnskey, dnskey_idx);

	num = rrset_get_sigcount(rrset);
	if(num == 0) {
		verbose(VERB_QUERY, "rrset failed to verify due to a lack of "
			"signatures");
		*reason = "no signatures";
		return sec_status_bogus;
	}
	for(i=0; i<num; i++) {
		/* see if sig matches keytag and algo */
		if(algo != rrset_get_sig_algo(rrset, i) ||
			tag != rrset_get_sig_keytag(rrset, i))
			continue;
		buf_canon = 0;
		sec = dnskey_verify_rrset_sig(env->scratch, 
			env->scratch_buffer, ve, *env->now, rrset, 
			dnskey, dnskey_idx, i, &sortree, &buf_canon, reason);
		if(sec == sec_status_secure)
			return sec;
		numchecked ++;
	}
	verbose(VERB_ALGO, "rrset failed to verify: all signatures are bogus");
	if(!numchecked) *reason = "signatures from unknown keys";
	return sec_status_bogus;
}

enum sec_status 
dnskeyset_verify_rrset_sig(struct module_env* env, struct val_env* ve, 
	uint32_t now, struct ub_packed_rrset_key* rrset, 
	struct ub_packed_rrset_key* dnskey, size_t sig_idx, 
	struct rbtree_t** sortree, char** reason)
{
	/* find matching keys and check them */
	enum sec_status sec = sec_status_bogus;
	uint16_t tag = rrset_get_sig_keytag(rrset, sig_idx);
	int algo = rrset_get_sig_algo(rrset, sig_idx);
	size_t i, num = rrset_get_count(dnskey);
	size_t numchecked = 0;
	int buf_canon = 0;
	verbose(VERB_ALGO, "verify sig %d %d", (int)tag, algo);
	
	for(i=0; i<num; i++) {
		/* see if key matches keytag and algo */
		if(algo != dnskey_get_algo(dnskey, i) ||
			tag != dnskey_calc_keytag(dnskey, i))
			continue;
		numchecked ++;

		/* see if key verifies */
		sec = dnskey_verify_rrset_sig(env->scratch, 
			env->scratch_buffer, ve, now, rrset, dnskey, i, 
			sig_idx, sortree, &buf_canon, reason);
		if(sec == sec_status_secure)
			return sec;
	}
	if(numchecked == 0) {
		*reason = "signatures from unknown keys";
		verbose(VERB_QUERY, "verify: could not find appropriate key");
		return sec_status_bogus;
	}
	return sec_status_bogus;
}

/**
 * RR entries in a canonical sorted tree of RRs
 */
struct canon_rr {
	/** rbtree node, key is this structure */
	rbnode_t node;
	/** rrset the RR is in */
	struct ub_packed_rrset_key* rrset;
	/** which RR in the rrset */
	size_t rr_idx;
};

/**
 * Compare two RR for canonical order, in a field-style sweep.
 * @param d: rrset data
 * @param desc: ldns wireformat descriptor.
 * @param i: first RR to compare
 * @param j: first RR to compare
 * @return comparison code.
 */
static int
canonical_compare_byfield(struct packed_rrset_data* d, 
	const ldns_rr_descriptor* desc, size_t i, size_t j)
{
	/* sweep across rdata, keep track of some state:
	 * 	which rr field, and bytes left in field.
	 * 	current position in rdata, length left.
	 * 	are we in a dname, length left in a label.
	 */
	int wfi = -1;	/* current wireformat rdata field (rdf) */
	int wfj = -1;
	uint8_t* di = d->rr_data[i]+2; /* ptr to current rdata byte */
	uint8_t* dj = d->rr_data[j]+2;
	size_t ilen = d->rr_len[i]-2; /* length left in rdata */
	size_t jlen = d->rr_len[j]-2;
	int dname_i = 0;  /* true if these bytes are part of a name */
	int dname_j = 0;
	size_t lablen_i = 0; /* 0 for label length byte,for first byte of rdf*/
	size_t lablen_j = 0; /* otherwise remaining length of rdf or label */
	int dname_num_i = (int)desc->_dname_count; /* decreased at root label */
	int dname_num_j = (int)desc->_dname_count;

	/* loop while there are rdata bytes available for both rrs,
	 * and still some lowercasing needs to be done; either the dnames
	 * have not been reached yet, or they are currently being processed */
	while(ilen > 0 && jlen > 0 && (dname_num_i > 0 || dname_num_j > 0)) {
		/* compare these two bytes */
		/* lowercase if in a dname and not a label length byte */
		if( ((dname_i && lablen_i)?(uint8_t)tolower((int)*di):*di)
		 != ((dname_j && lablen_j)?(uint8_t)tolower((int)*dj):*dj)
		 ) {
		  if(((dname_i && lablen_i)?(uint8_t)tolower((int)*di):*di)
		  < ((dname_j && lablen_j)?(uint8_t)tolower((int)*dj):*dj))
		 	return -1;
		    return 1;
		}
		ilen--;
		jlen--;
		/* bytes are equal */

		/* advance field i */
		/* lablen 0 means that this byte is the first byte of the
		 * next rdata field; inspect this rdata field and setup
		 * to process the rest of this rdata field.
		 * The reason to first read the byte, then setup the rdf,
		 * is that we are then sure the byte is available and short
		 * rdata is handled gracefully (even if it is a formerr). */
		if(lablen_i == 0) { 
			if(dname_i) {
				/* scan this dname label */
				/* capture length to lowercase */
				lablen_i = (size_t)*di;
				if(lablen_i == 0) {
					/* end root label */
					dname_i = 0;
					dname_num_i--;
					/* if dname num is 0, then the
					 * remainder is binary only */
					if(dname_num_i == 0)
						lablen_i = ilen;
				}
			} else {
				/* scan this rdata field */
				wfi++;
				if(desc->_wireformat[wfi] 
					== LDNS_RDF_TYPE_DNAME) {
					dname_i = 1; 
					lablen_i = (size_t)*di;
					if(lablen_i == 0) {
						dname_i = 0;
						dname_num_i--;
						if(dname_num_i == 0)
							lablen_i = ilen;
					}
				} else if(desc->_wireformat[wfi] 
					== LDNS_RDF_TYPE_STR)
					lablen_i = (size_t)*di;
				else	lablen_i = get_rdf_size(
					desc->_wireformat[wfi]) - 1;
			}
		} else	lablen_i--;

		/* advance field j; same as for i */
		if(lablen_j == 0) { 
			if(dname_j) {
				lablen_j = (size_t)*dj;
				if(lablen_j == 0) {
					dname_j = 0;
					dname_num_j--;
					if(dname_num_j == 0)
						lablen_j = jlen;
				}
			} else {
				wfj++;
				if(desc->_wireformat[wfj] 
					== LDNS_RDF_TYPE_DNAME) {
					dname_j = 1; 
					lablen_j = (size_t)*dj;
					if(lablen_j == 0) {
						dname_j = 0;
						dname_num_j--;
						if(dname_num_j == 0)
							lablen_j = jlen;
					}
				} else if(desc->_wireformat[wfj] 
					== LDNS_RDF_TYPE_STR)
					lablen_j = (size_t)*dj;
				else	lablen_j = get_rdf_size(
					desc->_wireformat[wfj]) - 1;
			}
		} else	lablen_j--;
		di++;
		dj++;
	}
	/* end of the loop; because we advanced byte by byte; now we have
	 * that the rdata has ended, or that there is a binary remainder */
	/* shortest first */
	if(ilen == 0 && jlen == 0)
		return 0;
	if(ilen == 0)
		return -1;
	if(jlen == 0)
		return 1;
	/* binary remainder, capture comparison in wfi variable */
	if((wfi = memcmp(di, dj, (ilen<jlen)?ilen:jlen)) != 0)
		return wfi;
	if(ilen < jlen)
		return -1;
	if(jlen < ilen)
		return 1;
	return 0;
}

/**
 * Compare two RRs in the same RRset and determine their relative
 * canonical order.
 * @param rrset: the rrset in which to perform compares.
 * @param i: first RR to compare
 * @param j: first RR to compare
 * @return 0 if RR i== RR j, -1 if <, +1 if >.
 */
static int
canonical_compare(struct ub_packed_rrset_key* rrset, size_t i, size_t j)
{
	struct packed_rrset_data* d = (struct packed_rrset_data*)
		rrset->entry.data;
	const ldns_rr_descriptor* desc;
	uint16_t type = ntohs(rrset->rk.type);
	size_t minlen;
	int c;

	if(i==j)
		return 0;
	/* in case rdata-len is to be compared for canonical order
	c = memcmp(d->rr_data[i], d->rr_data[j], 2);
	if(c != 0)
		return c; */

	switch(type) {
		/* These RR types have only a name as RDATA. 
		 * This name has to be canonicalized.*/
		case LDNS_RR_TYPE_NS:
		case LDNS_RR_TYPE_MD:
		case LDNS_RR_TYPE_MF:
		case LDNS_RR_TYPE_CNAME:
		case LDNS_RR_TYPE_MB:
		case LDNS_RR_TYPE_MG:
		case LDNS_RR_TYPE_MR:
		case LDNS_RR_TYPE_PTR:
		case LDNS_RR_TYPE_DNAME:
			return query_dname_compare(d->rr_data[i]+2, 
				d->rr_data[j]+2);

		/* These RR types have STR and fixed size rdata fields
		 * before one or more name fields that need canonicalizing,
		 * and after that a byte-for byte remainder can be compared.
		 */
		/* type starts with the name; remainder is binary compared */
		case LDNS_RR_TYPE_NXT: 
		/* use rdata field formats */
		case LDNS_RR_TYPE_MINFO:
		case LDNS_RR_TYPE_RP:
		case LDNS_RR_TYPE_SOA:
		case LDNS_RR_TYPE_RT:
		case LDNS_RR_TYPE_AFSDB:
		case LDNS_RR_TYPE_KX:
		case LDNS_RR_TYPE_MX:
		case LDNS_RR_TYPE_SIG:
		case LDNS_RR_TYPE_PX:
		case LDNS_RR_TYPE_NAPTR:
		case LDNS_RR_TYPE_SRV:
			desc = ldns_rr_descript(type);
			log_assert(desc);
			/* this holds for the types that need canonicalizing */
			log_assert(desc->_minimum == desc->_maximum);
			return canonical_compare_byfield(d, desc, i, j);

		case LDNS_RR_TYPE_HINFO: /* no longer downcased */
		case LDNS_RR_TYPE_NSEC: 
		case LDNS_RR_TYPE_RRSIG:
	default:
		/* For unknown RR types, or types not listed above,
		 * no canonicalization is needed, do binary compare */
		/* byte for byte compare, equal means shortest first*/
		minlen = d->rr_len[i]-2;
		if(minlen > d->rr_len[j]-2)
			minlen = d->rr_len[j]-2;
		c = memcmp(d->rr_data[i]+2, d->rr_data[j]+2, minlen);
		if(c!=0)
			return c;
		/* rdata equal, shortest is first */
		if(d->rr_len[i] < d->rr_len[j])
			return -1;
		if(d->rr_len[i] > d->rr_len[j])
			return 1;
		/* rdata equal, length equal */
		break;
	}
	return 0;
}

int
canonical_tree_compare(const void* k1, const void* k2)
{
	struct canon_rr* r1 = (struct canon_rr*)k1;
	struct canon_rr* r2 = (struct canon_rr*)k2;
	log_assert(r1->rrset == r2->rrset);
	return canonical_compare(r1->rrset, r1->rr_idx, r2->rr_idx);
}

/**
 * Sort RRs for rrset in canonical order.
 * Does not actually canonicalize the RR rdatas.
 * Does not touch rrsigs.
 * @param rrset: to sort.
 * @param d: rrset data.
 * @param sortree: tree to sort into.
 * @param rrs: rr storage.
 */
static void
canonical_sort(struct ub_packed_rrset_key* rrset, struct packed_rrset_data* d,
	rbtree_t* sortree, struct canon_rr* rrs)
{
	size_t i;
	/* insert into rbtree to sort and detect duplicates */
	for(i=0; i<d->count; i++) {
		rrs[i].node.key = &rrs[i];
		rrs[i].rrset = rrset;
		rrs[i].rr_idx = i;
		if(!rbtree_insert(sortree, &rrs[i].node)) {
			/* this was a duplicate */
		}
	}
}

/**
 * Inser canonical owner name into buffer.
 * @param buf: buffer to insert into at current position.
 * @param k: rrset with its owner name.
 * @param sig: signature with signer name and label count.
 * 	must be length checked, at least 18 bytes long.
 * @param can_owner: position in buffer returned for future use.
 * @param can_owner_len: length of canonical owner name.
 */
static void
insert_can_owner(ldns_buffer* buf, struct ub_packed_rrset_key* k,
	uint8_t* sig, uint8_t** can_owner, size_t* can_owner_len)
{
	int rrsig_labels = (int)sig[3];
	int fqdn_labels = dname_signame_label_count(k->rk.dname);
	*can_owner = ldns_buffer_current(buf);
	if(rrsig_labels == fqdn_labels) {
		/* no change */
		ldns_buffer_write(buf, k->rk.dname, k->rk.dname_len);
		query_dname_tolower(*can_owner);
		*can_owner_len = k->rk.dname_len;
		return;
	}
	log_assert(rrsig_labels < fqdn_labels);
	/* *. | fqdn(rightmost rrsig_labels) */
	if(rrsig_labels < fqdn_labels) {
		int i;
		uint8_t* nm = k->rk.dname;
		size_t len = k->rk.dname_len;
		/* so skip fqdn_labels-rrsig_labels */
		for(i=0; i<fqdn_labels-rrsig_labels; i++) {
			dname_remove_label(&nm, &len);	
		}
		*can_owner_len = len+2;
		ldns_buffer_write(buf, (uint8_t*)"\001*", 2);
		ldns_buffer_write(buf, nm, len);
		query_dname_tolower(*can_owner);
	}
}

/**
 * Canonicalize Rdata in buffer.
 * @param buf: buffer at position just after the rdata.
 * @param rrset: rrset with type.
 * @param len: length of the rdata (including rdatalen uint16).
 */
static void
canonicalize_rdata(ldns_buffer* buf, struct ub_packed_rrset_key* rrset,
	size_t len)
{
	uint8_t* datstart = ldns_buffer_current(buf)-len+2;
	switch(ntohs(rrset->rk.type)) {
		case LDNS_RR_TYPE_NXT: 
		case LDNS_RR_TYPE_NS:
		case LDNS_RR_TYPE_MD:
		case LDNS_RR_TYPE_MF:
		case LDNS_RR_TYPE_CNAME:
		case LDNS_RR_TYPE_MB:
		case LDNS_RR_TYPE_MG:
		case LDNS_RR_TYPE_MR:
		case LDNS_RR_TYPE_PTR:
		case LDNS_RR_TYPE_DNAME:
			/* type only has a single argument, the name */
			query_dname_tolower(datstart);
			return;
		case LDNS_RR_TYPE_MINFO:
		case LDNS_RR_TYPE_RP:
		case LDNS_RR_TYPE_SOA:
			/* two names after another */
			query_dname_tolower(datstart);
			query_dname_tolower(datstart + 
				dname_valid(datstart, len-2));
			return;
		case LDNS_RR_TYPE_RT:
		case LDNS_RR_TYPE_AFSDB:
		case LDNS_RR_TYPE_KX:
		case LDNS_RR_TYPE_MX:
			/* skip fixed part */
			if(len < 2+2+1) /* rdlen, skiplen, 1byteroot */
				return;
			datstart += 2;
			query_dname_tolower(datstart);
			return;
		case LDNS_RR_TYPE_SIG:
		case LDNS_RR_TYPE_RRSIG:
			/* skip fixed part */
			if(len < 2+18+1)
				return;
			datstart += 18;
			query_dname_tolower(datstart);
			return;
		case LDNS_RR_TYPE_PX:
			/* skip, then two names after another */
			if(len < 2+2+1) 
				return;
			datstart += 2;
			query_dname_tolower(datstart);
			query_dname_tolower(datstart + 
				dname_valid(datstart, len-2-2));
			return;
		case LDNS_RR_TYPE_NAPTR:
			if(len < 2+4)
				return;
			len -= 2+4;
			datstart += 4;
			if(len < (size_t)datstart[0]+1) /* skip text field */
				return;
			len -= (size_t)datstart[0]+1;
			datstart += (size_t)datstart[0]+1;
			if(len < (size_t)datstart[0]+1) /* skip text field */
				return;
			len -= (size_t)datstart[0]+1;
			datstart += (size_t)datstart[0]+1;
			if(len < (size_t)datstart[0]+1) /* skip text field */
				return;
			len -= (size_t)datstart[0]+1;
			datstart += (size_t)datstart[0]+1;
			if(len < 1)	/* check name is at least 1 byte*/
				return;
			query_dname_tolower(datstart);
			return;
		case LDNS_RR_TYPE_SRV:
			/* skip fixed part */
			if(len < 2+6+1)
				return;
			datstart += 6;
			query_dname_tolower(datstart);
			return;

		/* do not canonicalize NSEC rdata name, compat with bug
		 * from bind 9.4 signer, where it does not do so */
		case LDNS_RR_TYPE_NSEC: /* type starts with the name */
		case LDNS_RR_TYPE_HINFO: /* not downcased */
		/* A6 not supported */
		default:	
			/* nothing to do for unknown types */
			return;
	}
}

/**
 * Create canonical form of rrset in the scratch buffer.
 * @param region: temporary region.
 * @param buf: the buffer to use.
 * @param k: the rrset to insert.
 * @param sig: RRSIG rdata to include.
 * @param siglen: RRSIG rdata len excluding signature field, but inclusive
 * 	signer name length.
 * @param sortree: if NULL is passed a new sorted rrset tree is built.
 * 	Otherwise it is reused.
 * @return false on alloc error.
 */
static int
rrset_canonical(struct regional* region, ldns_buffer* buf, 
	struct ub_packed_rrset_key* k, uint8_t* sig, size_t siglen,
	struct rbtree_t** sortree)
{
	struct packed_rrset_data* d = (struct packed_rrset_data*)k->entry.data;
	uint8_t* can_owner = NULL;
	size_t can_owner_len = 0;
	struct canon_rr* walk;
	struct canon_rr* rrs;

	if(!*sortree) {
		*sortree = (struct rbtree_t*)regional_alloc(region, 
			sizeof(rbtree_t));
		if(!*sortree)
			return 0;
		rrs = regional_alloc(region, sizeof(struct canon_rr)*d->count);
		if(!rrs) {
			*sortree = NULL;
			return 0;
		}
		rbtree_init(*sortree, &canonical_tree_compare);
		canonical_sort(k, d, *sortree, rrs);
	}

	ldns_buffer_clear(buf);
	ldns_buffer_write(buf, sig, siglen);
	/* canonicalize signer name */
	query_dname_tolower(ldns_buffer_begin(buf)+18); 
	RBTREE_FOR(walk, struct canon_rr*, (*sortree)) {
		/* see if there is enough space left in the buffer */
		if(ldns_buffer_remaining(buf) < can_owner_len + 2 + 2 + 4
			+ d->rr_len[walk->rr_idx]) {
			log_err("verify: failed to canonicalize, "
				"rrset too big");
			return 0;
		}
		/* determine canonical owner name */
		if(can_owner)
			ldns_buffer_write(buf, can_owner, can_owner_len);
		else	insert_can_owner(buf, k, sig, &can_owner, 
				&can_owner_len);
		ldns_buffer_write(buf, &k->rk.type, 2);
		ldns_buffer_write(buf, &k->rk.rrset_class, 2);
		ldns_buffer_write(buf, sig+4, 4);
		ldns_buffer_write(buf, d->rr_data[walk->rr_idx], 
			d->rr_len[walk->rr_idx]);
		canonicalize_rdata(buf, k, d->rr_len[walk->rr_idx]);
	}
	ldns_buffer_flip(buf);
	return 1;
}

/** pretty print rrsig error with dates */
static void
sigdate_error(const char* str, int32_t expi, int32_t incep, int32_t now)
{
	struct tm tm;
	char expi_buf[16];
	char incep_buf[16];
	char now_buf[16];
	time_t te, ti, tn;

	if(verbosity < VERB_QUERY)
		return;
	te = (time_t)expi;
	ti = (time_t)incep;
	tn = (time_t)now;
	memset(&tm, 0, sizeof(tm));
	if(gmtime_r(&te, &tm) && strftime(expi_buf, 15, "%Y%m%d%H%M%S", &tm)
	 &&gmtime_r(&ti, &tm) && strftime(incep_buf, 15, "%Y%m%d%H%M%S", &tm)
	 &&gmtime_r(&tn, &tm) && strftime(now_buf, 15, "%Y%m%d%H%M%S", &tm)) {
		log_info("%s expi=%s incep=%s now=%s", str, expi_buf, 
			incep_buf, now_buf);
	} else
		log_info("%s expi=%u incep=%u now=%u", str, (unsigned)expi, 
			(unsigned)incep, (unsigned)now);
}

/** check rrsig dates */
static int
check_dates(struct val_env* ve, uint32_t unow,
	uint8_t* expi_p, uint8_t* incep_p, char** reason)
{
	/* read out the dates */
	int32_t expi, incep, now;
	memmove(&expi, expi_p, sizeof(expi));
	memmove(&incep, incep_p, sizeof(incep));
	expi = ntohl(expi);
	incep = ntohl(incep);

	/* get current date */
	if(ve->date_override) {
		now = ve->date_override;
		verbose(VERB_ALGO, "date override option %d", (int)now); 
	} else	now = (int32_t)unow;

	/* check them */
	if(incep - expi > 0) {
		sigdate_error("verify: inception after expiration, "
			"signature bad", expi, incep, now);
		*reason = "signature inception after expiration";
		return 0;
	}
	if(incep - now > 0) {
		/* within skew ? (calc here to avoid calculation normally) */
		int32_t skew = (expi-incep)/10;
		if(skew < ve->skew_min) skew = ve->skew_min;
		if(skew > ve->skew_max) skew = ve->skew_max;
		if(incep - now > skew) {
			sigdate_error("verify: signature bad, current time is"
				" before inception date", expi, incep, now);
			*reason = "signature before inception date";
			return 0;
		}
		sigdate_error("verify warning suspicious signature inception "
			" or bad local clock", expi, incep, now);
	}
	if(now - expi > 0) {
		int32_t skew = (expi-incep)/10;
		if(skew < ve->skew_min) skew = ve->skew_min;
		if(skew > ve->skew_max) skew = ve->skew_max;
		if(now - expi > skew) {
			sigdate_error("verify: signature expired", expi, 
				incep, now);
			*reason = "signature expired";
			return 0;
		}
		sigdate_error("verify warning suspicious signature expiration "
			" or bad local clock", expi, incep, now);
	}
	return 1;
}

/** adjust rrset TTL for verified rrset, compare to original TTL and expi */
static void
adjust_ttl(struct val_env* ve, uint32_t unow, 
	struct ub_packed_rrset_key* rrset, uint8_t* orig_p, 
	uint8_t* expi_p, uint8_t* incep_p)
{
	struct packed_rrset_data* d = 
		(struct packed_rrset_data*)rrset->entry.data;
	/* read out the dates */
	int32_t origttl, expittl, expi, incep, now;
	memmove(&origttl, orig_p, sizeof(origttl));
	memmove(&expi, expi_p, sizeof(expi));
	memmove(&incep, incep_p, sizeof(incep));
	expi = ntohl(expi);
	incep = ntohl(incep);
	origttl = ntohl(origttl);

	/* get current date */
	if(ve->date_override) {
		now = ve->date_override;
	} else	now = (int32_t)unow;
	expittl = expi - now;

	/* so now:
	 * d->ttl: rrset ttl read from message or cache. May be reduced
	 * origttl: original TTL from signature, authoritative TTL max.
	 * expittl: TTL until the signature expires.
	 *
	 * Use the smallest of these.
	 */
	if(d->ttl > (uint32_t)origttl) {
		verbose(VERB_QUERY, "rrset TTL larger than original TTL,"
			" adjusting TTL downwards");
		d->ttl = origttl;
	}
	if(expittl > 0 && d->ttl > (uint32_t)expittl) {
		verbose(VERB_ALGO, "rrset TTL larger than sig expiration ttl,"
			" adjusting TTL downwards");
		d->ttl = expittl;
	}
}


/**
 * Output a libcrypto openssl error to the logfile.
 * @param str: string to add to it.
 * @param e: the error to output, error number from ERR_get_error().
 */
static void
log_crypto_error(const char* str, unsigned long e)
{
	char buf[128];
	/* or use ERR_error_string if ERR_error_string_n is not avail TODO */
	ERR_error_string_n(e, buf, sizeof(buf));
	/* buf now contains */
	/* error:[error code]:[library name]:[function name]:[reason string] */
	log_err("%s crypto %s", str, buf);
}

/**
 * Setup DSA key digest in DER encoding ... 
 * @param sig: input is signature output alloced ptr (unless failure).
 * 	caller must free alloced ptr if this routine returns true.
 * @param len: intput is initial siglen, output is output len.
 * @return false on failure.
 */
static int
setup_dsa_sig(unsigned char** sig, unsigned int* len)
{
	unsigned char* orig = *sig;
	unsigned int origlen = *len;
	int newlen;

	uint8_t t;
	BIGNUM *R, *S;
	DSA_SIG *dsasig;

	/* extract the R and S field from the sig buffer */
	if(origlen < 1 + 2*SHA_DIGEST_LENGTH)
		return 0;
	t = orig[0];
	R = BN_new();
	if(!R) return 0;
	(void) BN_bin2bn(orig + 1, SHA_DIGEST_LENGTH, R);
	S = BN_new();
	if(!S) return 0;
	(void) BN_bin2bn(orig + 21, SHA_DIGEST_LENGTH, S);
	dsasig = DSA_SIG_new();
	if(!dsasig) return 0;

	dsasig->r = R;
	dsasig->s = S;
	*sig = NULL;
	newlen = i2d_DSA_SIG(dsasig, sig);
	if(newlen < 0) {
		free(*sig);
		return 0;
	}
	*len = (unsigned int)newlen;
	DSA_SIG_free(dsasig);
	return 1;
}

/**
 * Setup key and digest for verification. Adjust sig if necessary.
 *
 * @param algo: key algorithm
 * @param evp_key: EVP PKEY public key to create.
 * @param digest_type: digest type to use
 * @param key: key to setup for.
 * @param keylen: length of key.
 * @return false on failure.
 */
static int
setup_key_digest(int algo, EVP_PKEY** evp_key, const EVP_MD** digest_type, 
	unsigned char* key, size_t keylen)
{
	DSA* dsa;
	RSA* rsa;

	switch(algo) {
		case LDNS_DSA:
		case LDNS_DSA_NSEC3:
			*evp_key = EVP_PKEY_new();
			if(!*evp_key) {
				log_err("verify: malloc failure in crypto");
				return sec_status_unchecked;
			}
			dsa = ldns_key_buf2dsa_raw(key, keylen);
			if(!dsa) {
				verbose(VERB_QUERY, "verify: "
					"ldns_key_buf2dsa_raw failed");
				return 0;
			}
			if(EVP_PKEY_assign_DSA(*evp_key, dsa) == 0) {
				verbose(VERB_QUERY, "verify: "
					"EVP_PKEY_assign_DSA failed");
				return 0;
			}
			*digest_type = EVP_dss1();

			break;
		case LDNS_RSASHA1:
		case LDNS_RSASHA1_NSEC3:
#if defined(HAVE_EVP_SHA256) && defined(USE_SHA2)
		case LDNS_RSASHA256:
#endif
#if defined(HAVE_EVP_SHA512) && defined(USE_SHA2)
		case LDNS_RSASHA512:
#endif
			*evp_key = EVP_PKEY_new();
			if(!*evp_key) {
				log_err("verify: malloc failure in crypto");
				return sec_status_unchecked;
			}
			rsa = ldns_key_buf2rsa_raw(key, keylen);
			if(!rsa) {
				verbose(VERB_QUERY, "verify: "
					"ldns_key_buf2rsa_raw SHA failed");
				return 0;
			}
			if(EVP_PKEY_assign_RSA(*evp_key, rsa) == 0) {
				verbose(VERB_QUERY, "verify: "
					"EVP_PKEY_assign_RSA SHA failed");
				return 0;
			}

			/* select SHA version */
#if defined(HAVE_EVP_SHA256) && defined(USE_SHA2)
			if(algo == LDNS_RSASHA256)
				*digest_type = EVP_sha256();
			else
#endif
#if defined(HAVE_EVP_SHA512) && defined(USE_SHA2)
				if(algo == LDNS_RSASHA512)
				*digest_type = EVP_sha512();
			else
#endif
				*digest_type = EVP_sha1();

			break;
		case LDNS_RSAMD5:
			*evp_key = EVP_PKEY_new();
			if(!*evp_key) {
				log_err("verify: malloc failure in crypto");
				return sec_status_unchecked;
			}
			rsa = ldns_key_buf2rsa_raw(key, keylen);
			if(!rsa) {
				verbose(VERB_QUERY, "verify: "
					"ldns_key_buf2rsa_raw MD5 failed");
				return 0;
			}
			if(EVP_PKEY_assign_RSA(*evp_key, rsa) == 0) {
				verbose(VERB_QUERY, "verify: "
					"EVP_PKEY_assign_RSA MD5 failed");
				return 0;
			}
			*digest_type = EVP_md5();

			break;
#ifdef USE_GOST
		case LDNS_GOST:
			*evp_key = ldns_gost2pkey_raw(key, keylen);
			if(!*evp_key) {
				verbose(VERB_QUERY, "verify: "
					"ldns_gost2pkey_raw failed");
				return 0;
			}
			*digest_type = EVP_get_digestbyname("md_gost94");
			if(!*digest_type) {
				verbose(VERB_QUERY, "verify: "
					"EVP_getdigest md_gost94 failed");
				return 0;
			}
			break;
#endif
		default:
			verbose(VERB_QUERY, "verify: unknown algorithm %d", 
				algo);
			return 0;
	}
	return 1;
}

/**
 * Check a canonical sig+rrset and signature against a dnskey
 * @param buf: buffer with data to verify, the first rrsig part and the
 *	canonicalized rrset.
 * @param algo: DNSKEY algorithm.
 * @param sigblock: signature rdata field from RRSIG
 * @param sigblock_len: length of sigblock data.
 * @param key: public key data from DNSKEY RR.
 * @param keylen: length of keydata.
 * @param reason: bogus reason in more detail.
 * @return secure if verification succeeded, bogus on crypto failure,
 *	unchecked on format errors and alloc failures.
 */
static enum sec_status
verify_canonrrset(ldns_buffer* buf, int algo, unsigned char* sigblock, 
	unsigned int sigblock_len, unsigned char* key, unsigned int keylen,
	char** reason)
{
	const EVP_MD *digest_type;
	EVP_MD_CTX ctx;
	int res, dofree = 0;
	EVP_PKEY *evp_key = NULL;
	
	if(!setup_key_digest(algo, &evp_key, &digest_type, key, keylen)) {
		verbose(VERB_QUERY, "verify: failed to setup key");
		*reason = "use of key for crypto failed";
		EVP_PKEY_free(evp_key);
		return sec_status_bogus;
	}
	/* if it is a DSA signature in bind format, convert to DER format */
	if((algo == LDNS_DSA || algo == LDNS_DSA_NSEC3) && 
		sigblock_len == 1+2*SHA_DIGEST_LENGTH) {
		if(!setup_dsa_sig(&sigblock, &sigblock_len)) {
			verbose(VERB_QUERY, "verify: failed to setup DSA sig");
			*reason = "use of key for DSA crypto failed";
			EVP_PKEY_free(evp_key);
			return sec_status_bogus;
		}
		dofree = 1;
	} 

	/* do the signature cryptography work */
	EVP_MD_CTX_init(&ctx);
	if(EVP_VerifyInit(&ctx, digest_type) == 0) {
		verbose(VERB_QUERY, "verify: EVP_VerifyInit failed");
		EVP_PKEY_free(evp_key);
		if(dofree) free(sigblock);
		return sec_status_unchecked;
	}
	if(EVP_VerifyUpdate(&ctx, (unsigned char*)ldns_buffer_begin(buf), 
		(unsigned int)ldns_buffer_limit(buf)) == 0) {
		verbose(VERB_QUERY, "verify: EVP_VerifyUpdate failed");
		EVP_PKEY_free(evp_key);
		if(dofree) free(sigblock);
		return sec_status_unchecked;
	}
		
	res = EVP_VerifyFinal(&ctx, sigblock, sigblock_len, evp_key);
	if(EVP_MD_CTX_cleanup(&ctx) == 0) {
		verbose(VERB_QUERY, "verify: EVP_MD_CTX_cleanup failed");
		EVP_PKEY_free(evp_key);
		if(dofree) free(sigblock);
		return sec_status_unchecked;
	}
	EVP_PKEY_free(evp_key);

	if(dofree)
		free(sigblock);

	if(res == 1) {
		return sec_status_secure;
	} else if(res == 0) {
		verbose(VERB_QUERY, "verify: signature mismatch");
		*reason = "signature crypto failed";
		return sec_status_bogus;
	}

	log_crypto_error("verify:", ERR_get_error());
	return sec_status_unchecked;
}

enum sec_status 
dnskey_verify_rrset_sig(struct regional* region, ldns_buffer* buf, 
	struct val_env* ve, uint32_t now,
        struct ub_packed_rrset_key* rrset, struct ub_packed_rrset_key* dnskey,
        size_t dnskey_idx, size_t sig_idx,
	struct rbtree_t** sortree, int* buf_canon, char** reason)
{
	enum sec_status sec;
	uint8_t* sig;		/* RRSIG rdata */
	size_t siglen;
	size_t rrnum = rrset_get_count(rrset);
	uint8_t* signer;	/* rrsig signer name */
	size_t signer_len;
	unsigned char* sigblock; /* signature rdata field */
	unsigned int sigblock_len;
	uint16_t ktag;		/* DNSKEY key tag */
	unsigned char* key;	/* public key rdata field */
	unsigned int keylen;
	rrset_get_rdata(rrset, rrnum + sig_idx, &sig, &siglen);
	/* min length of rdatalen, fixed rrsig, root signer, 1 byte sig */
	if(siglen < 2+20) {
		verbose(VERB_QUERY, "verify: signature too short");
		*reason = "signature too short";
		return sec_status_bogus;
	}

	if(!(dnskey_get_flags(dnskey, dnskey_idx) & DNSKEY_BIT_ZSK)) {
		verbose(VERB_QUERY, "verify: dnskey without ZSK flag");
		*reason = "dnskey without ZSK flag";
		return sec_status_bogus; 
	}

	if(dnskey_get_protocol(dnskey, dnskey_idx) != LDNS_DNSSEC_KEYPROTO) { 
		/* RFC 4034 says DNSKEY PROTOCOL MUST be 3 */
		verbose(VERB_QUERY, "verify: dnskey has wrong key protocol");
		*reason = "dnskey has wrong protocolnumber";
		return sec_status_bogus;
	}

	/* verify as many fields in rrsig as possible */
	signer = sig+2+18;
	signer_len = dname_valid(signer, siglen-2-18);
	if(!signer_len) {
		verbose(VERB_QUERY, "verify: malformed signer name");
		*reason = "signer name malformed";
		return sec_status_bogus; /* signer name invalid */
	}
	if(!dname_subdomain_c(rrset->rk.dname, signer)) {
		verbose(VERB_QUERY, "verify: signer name is off-tree");
		*reason = "signer name off-tree";
		return sec_status_bogus; /* signer name offtree */
	}
	sigblock = (unsigned char*)signer+signer_len;
	if(siglen < 2+18+signer_len+1) {
		verbose(VERB_QUERY, "verify: too short, no signature data");
		*reason = "signature too short, no signature data";
		return sec_status_bogus; /* sig rdf is < 1 byte */
	}
	sigblock_len = (unsigned int)(siglen - 2 - 18 - signer_len);

	/* verify key dname == sig signer name */
	if(query_dname_compare(signer, dnskey->rk.dname) != 0) {
		verbose(VERB_QUERY, "verify: wrong key for rrsig");
		log_nametypeclass(VERB_QUERY, "RRSIG signername is", 
			signer, 0, 0);
		log_nametypeclass(VERB_QUERY, "the key name is", 
			dnskey->rk.dname, 0, 0);
		*reason = "signer name mismatches key name";
		return sec_status_bogus;
	}

	/* verify covered type */
	/* memcmp works because type is in network format for rrset */
	if(memcmp(sig+2, &rrset->rk.type, 2) != 0) {
		verbose(VERB_QUERY, "verify: wrong type covered");
		*reason = "signature covers wrong type";
		return sec_status_bogus;
	}
	/* verify keytag and sig algo (possibly again) */
	if((int)sig[2+2] != dnskey_get_algo(dnskey, dnskey_idx)) {
		verbose(VERB_QUERY, "verify: wrong algorithm");
		*reason = "signature has wrong algorithm";
		return sec_status_bogus;
	}
	ktag = htons(dnskey_calc_keytag(dnskey, dnskey_idx));
	if(memcmp(sig+2+16, &ktag, 2) != 0) {
		verbose(VERB_QUERY, "verify: wrong keytag");
		*reason = "signature has wrong keytag";
		return sec_status_bogus;
	}

	/* verify labels is in a valid range */
	if((int)sig[2+3] > dname_signame_label_count(rrset->rk.dname)) {
		verbose(VERB_QUERY, "verify: labelcount out of range");
		*reason = "signature labelcount out of range";
		return sec_status_bogus;
	}

	/* original ttl, always ok */

	if(!*buf_canon) {
		/* create rrset canonical format in buffer, ready for 
		 * signature */
		if(!rrset_canonical(region, buf, rrset, sig+2, 
			18 + signer_len, sortree)) {
			log_err("verify: failed due to alloc error");
			return sec_status_unchecked;
		}
		*buf_canon = 1;
	}

	/* check that dnskey is available */
	dnskey_get_pubkey(dnskey, dnskey_idx, &key, &keylen);
	if(!key) {
		verbose(VERB_QUERY, "verify: short DNSKEY RR");
		return sec_status_unchecked;
	}

	/* verify */
	sec = verify_canonrrset(buf, (int)sig[2+2],
		sigblock, sigblock_len, key, keylen, reason);
	
	if(sec == sec_status_secure) {
		/* check if TTL is too high - reduce if so */
		adjust_ttl(ve, now, rrset, sig+2+4, sig+2+8, sig+2+12);

		/* verify inception, expiration dates 
		 * Do this last so that if you ignore expired-sigs the
		 * rest is sure to be OK. */
		if(!check_dates(ve, now, sig+2+8, sig+2+12, reason)) {
			return sec_status_bogus;
		}
	}

	return sec;
}