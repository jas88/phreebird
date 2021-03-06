/*
 * configparser.y -- yacc grammar for unbound configuration files
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
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

%{
#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "util/configyyrename.h"
#include "util/config_file.h"
#include "util/net_help.h"

int ub_c_lex(void);
void ub_c_error(const char *message);

/* these need to be global, otherwise they cannot be used inside yacc */
extern struct config_parser_state* cfg_parser;

#if 0
#define OUTYY(s)  printf s /* used ONLY when debugging */
#else
#define OUTYY(s)
#endif

%}
%union {
	char*	str;
};

%token SPACE LETTER NEWLINE COMMENT COLON ANY ZONESTR
%token <str> STRING_ARG
%token VAR_SERVER VAR_VERBOSITY VAR_NUM_THREADS VAR_PORT
%token VAR_OUTGOING_RANGE VAR_INTERFACE
%token VAR_DO_IP4 VAR_DO_IP6 VAR_DO_UDP VAR_DO_TCP 
%token VAR_CHROOT VAR_USERNAME VAR_DIRECTORY VAR_LOGFILE VAR_PIDFILE
%token VAR_MSG_CACHE_SIZE VAR_MSG_CACHE_SLABS VAR_NUM_QUERIES_PER_THREAD
%token VAR_RRSET_CACHE_SIZE VAR_RRSET_CACHE_SLABS VAR_OUTGOING_NUM_TCP
%token VAR_INFRA_HOST_TTL VAR_INFRA_LAME_TTL VAR_INFRA_CACHE_SLABS
%token VAR_INFRA_CACHE_NUMHOSTS VAR_INFRA_CACHE_LAME_SIZE VAR_NAME
%token VAR_STUB_ZONE VAR_STUB_HOST VAR_STUB_ADDR VAR_TARGET_FETCH_POLICY
%token VAR_HARDEN_SHORT_BUFSIZE VAR_HARDEN_LARGE_QUERIES
%token VAR_FORWARD_ZONE VAR_FORWARD_HOST VAR_FORWARD_ADDR
%token VAR_DO_NOT_QUERY_ADDRESS VAR_HIDE_IDENTITY VAR_HIDE_VERSION
%token VAR_IDENTITY VAR_VERSION VAR_HARDEN_GLUE VAR_MODULE_CONF
%token VAR_TRUST_ANCHOR_FILE VAR_TRUST_ANCHOR VAR_VAL_OVERRIDE_DATE
%token VAR_BOGUS_TTL VAR_VAL_CLEAN_ADDITIONAL VAR_VAL_PERMISSIVE_MODE
%token VAR_INCOMING_NUM_TCP VAR_MSG_BUFFER_SIZE VAR_KEY_CACHE_SIZE
%token VAR_KEY_CACHE_SLABS VAR_TRUSTED_KEYS_FILE 
%token VAR_VAL_NSEC3_KEYSIZE_ITERATIONS VAR_USE_SYSLOG 
%token VAR_OUTGOING_INTERFACE VAR_ROOT_HINTS VAR_DO_NOT_QUERY_LOCALHOST
%token VAR_CACHE_MAX_TTL VAR_HARDEN_DNSSEC_STRIPPED VAR_ACCESS_CONTROL
%token VAR_LOCAL_ZONE VAR_LOCAL_DATA VAR_INTERFACE_AUTOMATIC
%token VAR_STATISTICS_INTERVAL VAR_DO_DAEMONIZE VAR_USE_CAPS_FOR_ID
%token VAR_STATISTICS_CUMULATIVE VAR_OUTGOING_PORT_PERMIT 
%token VAR_OUTGOING_PORT_AVOID VAR_DLV_ANCHOR_FILE VAR_DLV_ANCHOR
%token VAR_NEG_CACHE_SIZE VAR_HARDEN_REFERRAL_PATH VAR_PRIVATE_ADDRESS
%token VAR_PRIVATE_DOMAIN VAR_REMOTE_CONTROL VAR_CONTROL_ENABLE
%token VAR_CONTROL_INTERFACE VAR_CONTROL_PORT VAR_SERVER_KEY_FILE
%token VAR_SERVER_CERT_FILE VAR_CONTROL_KEY_FILE VAR_CONTROL_CERT_FILE
%token VAR_EXTENDED_STATISTICS VAR_LOCAL_DATA_PTR VAR_JOSTLE_TIMEOUT
%token VAR_STUB_PRIME VAR_UNWANTED_REPLY_THRESHOLD VAR_LOG_TIME_ASCII
%token VAR_DOMAIN_INSECURE VAR_PYTHON VAR_PYTHON_SCRIPT VAR_VAL_SIG_SKEW_MIN
%token VAR_VAL_SIG_SKEW_MAX VAR_CACHE_MIN_TTL VAR_VAL_LOG_LEVEL
%token VAR_AUTO_TRUST_ANCHOR_FILE VAR_KEEP_MISSING VAR_ADD_HOLDDOWN 
%token VAR_DEL_HOLDDOWN VAR_SO_RCVBUF VAR_EDNS_BUFFER_SIZE VAR_PREFETCH
%token VAR_PREFETCH_KEY VAR_SO_SNDBUF VAR_HARDEN_BELOW_NXDOMAIN

%%
toplevelvars: /* empty */ | toplevelvars toplevelvar ;
toplevelvar: serverstart contents_server | stubstart contents_stub |
	forwardstart contents_forward | pythonstart contents_py | 
	rcstart contents_rc
	;

/* server: declaration */
serverstart: VAR_SERVER
	{ 
		OUTYY(("\nP(server:)\n")); 
	}
	;
contents_server: contents_server content_server 
	| ;
content_server: server_num_threads | server_verbosity | server_port |
	server_outgoing_range | server_do_ip4 |
	server_do_ip6 | server_do_udp | server_do_tcp | 
	server_interface | server_chroot | server_username | 
	server_directory | server_logfile | server_pidfile |
	server_msg_cache_size | server_msg_cache_slabs |
	server_num_queries_per_thread | server_rrset_cache_size | 
	server_rrset_cache_slabs | server_outgoing_num_tcp | 
	server_infra_host_ttl | server_infra_lame_ttl | 
	server_infra_cache_slabs | server_infra_cache_numhosts |
	server_infra_cache_lame_size | server_target_fetch_policy | 
	server_harden_short_bufsize | server_harden_large_queries |
	server_do_not_query_address | server_hide_identity |
	server_hide_version | server_identity | server_version |
	server_harden_glue | server_module_conf | server_trust_anchor_file |
	server_trust_anchor | server_val_override_date | server_bogus_ttl |
	server_val_clean_additional | server_val_permissive_mode |
	server_incoming_num_tcp | server_msg_buffer_size | 
	server_key_cache_size | server_key_cache_slabs | 
	server_trusted_keys_file | server_val_nsec3_keysize_iterations |
	server_use_syslog | server_outgoing_interface | server_root_hints |
	server_do_not_query_localhost | server_cache_max_ttl |
	server_harden_dnssec_stripped | server_access_control |
	server_local_zone | server_local_data | server_interface_automatic |
	server_statistics_interval | server_do_daemonize | 
	server_use_caps_for_id | server_statistics_cumulative |
	server_outgoing_port_permit | server_outgoing_port_avoid |
	server_dlv_anchor_file | server_dlv_anchor | server_neg_cache_size |
	server_harden_referral_path | server_private_address |
	server_private_domain | server_extended_statistics | 
	server_local_data_ptr | server_jostle_timeout | 
	server_unwanted_reply_threshold | server_log_time_ascii | 
	server_domain_insecure | server_val_sig_skew_min | 
	server_val_sig_skew_max | server_cache_min_ttl | server_val_log_level |
	server_auto_trust_anchor_file | server_add_holddown | 
	server_del_holddown | server_keep_missing | server_so_rcvbuf |
	server_edns_buffer_size | server_prefetch | server_prefetch_key |
	server_so_sndbuf | server_harden_below_nxdomain
	;
stubstart: VAR_STUB_ZONE
	{
		struct config_stub* s;
		OUTYY(("\nP(stub_zone:)\n")); 
		s = (struct config_stub*)calloc(1, sizeof(struct config_stub));
		if(s) {
			s->next = cfg_parser->cfg->stubs;
			cfg_parser->cfg->stubs = s;
		} else 
			yyerror("out of memory");
	}
	;
contents_stub: contents_stub content_stub 
	| ;
content_stub: stub_name | stub_host | stub_addr | stub_prime
	;
forwardstart: VAR_FORWARD_ZONE
	{
		struct config_stub* s;
		OUTYY(("\nP(forward_zone:)\n")); 
		s = (struct config_stub*)calloc(1, sizeof(struct config_stub));
		if(s) {
			s->next = cfg_parser->cfg->forwards;
			cfg_parser->cfg->forwards = s;
		} else 
			yyerror("out of memory");
	}
	;
contents_forward: contents_forward content_forward 
	| ;
content_forward: forward_name | forward_host | forward_addr 
	;
server_num_threads: VAR_NUM_THREADS STRING_ARG 
	{ 
		OUTYY(("P(server_num_threads:%s)\n", $2)); 
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->num_threads = atoi($2);
		free($2);
	}
	;
server_verbosity: VAR_VERBOSITY STRING_ARG 
	{ 
		OUTYY(("P(server_verbosity:%s)\n", $2)); 
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->verbosity = atoi($2);
		free($2);
	}
	;
server_statistics_interval: VAR_STATISTICS_INTERVAL STRING_ARG 
	{ 
		OUTYY(("P(server_statistics_interval:%s)\n", $2)); 
		if(strcmp($2, "") == 0 || strcmp($2, "0") == 0)
			cfg_parser->cfg->stat_interval = 0;
		else if(atoi($2) == 0)
			yyerror("number expected");
		else cfg_parser->cfg->stat_interval = atoi($2);
		free($2);
	}
	;
server_statistics_cumulative: VAR_STATISTICS_CUMULATIVE STRING_ARG
	{
		OUTYY(("P(server_statistics_cumulative:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->stat_cumulative = (strcmp($2, "yes")==0);
		free($2);
	}
	;
server_extended_statistics: VAR_EXTENDED_STATISTICS STRING_ARG
	{
		OUTYY(("P(server_extended_statistics:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->stat_extended = (strcmp($2, "yes")==0);
		free($2);
	}
	;
server_port: VAR_PORT STRING_ARG
	{
		OUTYY(("P(server_port:%s)\n", $2));
		if(atoi($2) == 0)
			yyerror("port number expected");
		else cfg_parser->cfg->port = atoi($2);
		free($2);
	}
	;
server_interface: VAR_INTERFACE STRING_ARG
	{
		OUTYY(("P(server_interface:%s)\n", $2));
		if(cfg_parser->cfg->num_ifs == 0)
			cfg_parser->cfg->ifs = calloc(1, sizeof(char*));
		else 	cfg_parser->cfg->ifs = realloc(cfg_parser->cfg->ifs,
				(cfg_parser->cfg->num_ifs+1)*sizeof(char*));
		if(!cfg_parser->cfg->ifs)
			yyerror("out of memory");
		else
			cfg_parser->cfg->ifs[cfg_parser->cfg->num_ifs++] = $2;
	}
	;
server_outgoing_interface: VAR_OUTGOING_INTERFACE STRING_ARG
	{
		OUTYY(("P(server_outgoing_interface:%s)\n", $2));
		if(cfg_parser->cfg->num_out_ifs == 0)
			cfg_parser->cfg->out_ifs = calloc(1, sizeof(char*));
		else 	cfg_parser->cfg->out_ifs = realloc(
			cfg_parser->cfg->out_ifs, 
			(cfg_parser->cfg->num_out_ifs+1)*sizeof(char*));
		if(!cfg_parser->cfg->out_ifs)
			yyerror("out of memory");
		else
			cfg_parser->cfg->out_ifs[
				cfg_parser->cfg->num_out_ifs++] = $2;
	}
	;
server_outgoing_range: VAR_OUTGOING_RANGE STRING_ARG
	{
		OUTYY(("P(server_outgoing_range:%s)\n", $2));
		if(atoi($2) == 0)
			yyerror("number expected");
		else cfg_parser->cfg->outgoing_num_ports = atoi($2);
		free($2);
	}
	;
server_outgoing_port_permit: VAR_OUTGOING_PORT_PERMIT STRING_ARG
	{
		OUTYY(("P(server_outgoing_port_permit:%s)\n", $2));
		if(!cfg_mark_ports($2, 1, 
			cfg_parser->cfg->outgoing_avail_ports, 65536))
			yyerror("port number or range (\"low-high\") expected");
		free($2);
	}
	;
server_outgoing_port_avoid: VAR_OUTGOING_PORT_AVOID STRING_ARG
	{
		OUTYY(("P(server_outgoing_port_avoid:%s)\n", $2));
		if(!cfg_mark_ports($2, 0, 
			cfg_parser->cfg->outgoing_avail_ports, 65536))
			yyerror("port number or range (\"low-high\") expected");
		free($2);
	}
	;
server_outgoing_num_tcp: VAR_OUTGOING_NUM_TCP STRING_ARG
	{
		OUTYY(("P(server_outgoing_num_tcp:%s)\n", $2));
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->outgoing_num_tcp = atoi($2);
		free($2);
	}
	;
server_incoming_num_tcp: VAR_INCOMING_NUM_TCP STRING_ARG
	{
		OUTYY(("P(server_incoming_num_tcp:%s)\n", $2));
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->incoming_num_tcp = atoi($2);
		free($2);
	}
	;
server_interface_automatic: VAR_INTERFACE_AUTOMATIC STRING_ARG
	{
		OUTYY(("P(server_interface_automatic:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->if_automatic = (strcmp($2, "yes")==0);
		free($2);
	}
	;
server_do_ip4: VAR_DO_IP4 STRING_ARG
	{
		OUTYY(("P(server_do_ip4:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->do_ip4 = (strcmp($2, "yes")==0);
		free($2);
	}
	;
server_do_ip6: VAR_DO_IP6 STRING_ARG
	{
		OUTYY(("P(server_do_ip6:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->do_ip6 = (strcmp($2, "yes")==0);
		free($2);
	}
	;
server_do_udp: VAR_DO_UDP STRING_ARG
	{
		OUTYY(("P(server_do_udp:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->do_udp = (strcmp($2, "yes")==0);
		free($2);
	}
	;
server_do_tcp: VAR_DO_TCP STRING_ARG
	{
		OUTYY(("P(server_do_tcp:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->do_tcp = (strcmp($2, "yes")==0);
		free($2);
	}
	;
server_do_daemonize: VAR_DO_DAEMONIZE STRING_ARG
	{
		OUTYY(("P(server_do_daemonize:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->do_daemonize = (strcmp($2, "yes")==0);
		free($2);
	}
	;
server_use_syslog: VAR_USE_SYSLOG STRING_ARG
	{
		OUTYY(("P(server_use_syslog:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->use_syslog = (strcmp($2, "yes")==0);
#if !defined(HAVE_SYSLOG_H) && !defined(UB_ON_WINDOWS)
		if(strcmp($2, "yes") == 0)
			yyerror("no syslog services are available. "
				"(reconfigure and compile to add)");
#endif
		free($2);
	}
	;
server_log_time_ascii: VAR_LOG_TIME_ASCII STRING_ARG
	{
		OUTYY(("P(server_log_time_ascii:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->log_time_ascii = (strcmp($2, "yes")==0);
		free($2);
	}
	;
server_chroot: VAR_CHROOT STRING_ARG
	{
		OUTYY(("P(server_chroot:%s)\n", $2));
		free(cfg_parser->cfg->chrootdir);
		cfg_parser->cfg->chrootdir = $2;
	}
	;
server_username: VAR_USERNAME STRING_ARG
	{
		OUTYY(("P(server_username:%s)\n", $2));
		free(cfg_parser->cfg->username);
		cfg_parser->cfg->username = $2;
	}
	;
server_directory: VAR_DIRECTORY STRING_ARG
	{
		OUTYY(("P(server_directory:%s)\n", $2));
		free(cfg_parser->cfg->directory);
		cfg_parser->cfg->directory = $2;
	}
	;
server_logfile: VAR_LOGFILE STRING_ARG
	{
		OUTYY(("P(server_logfile:%s)\n", $2));
		free(cfg_parser->cfg->logfile);
		cfg_parser->cfg->logfile = $2;
		cfg_parser->cfg->use_syslog = 0;
	}
	;
server_pidfile: VAR_PIDFILE STRING_ARG
	{
		OUTYY(("P(server_pidfile:%s)\n", $2));
		free(cfg_parser->cfg->pidfile);
		cfg_parser->cfg->pidfile = $2;
	}
	;
server_root_hints: VAR_ROOT_HINTS STRING_ARG
	{
		OUTYY(("P(server_root_hints:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->root_hints, $2))
			yyerror("out of memory");
	}
	;
server_dlv_anchor_file: VAR_DLV_ANCHOR_FILE STRING_ARG
	{
		OUTYY(("P(server_dlv_anchor_file:%s)\n", $2));
		free(cfg_parser->cfg->dlv_anchor_file);
		cfg_parser->cfg->dlv_anchor_file = $2;
	}
	;
server_dlv_anchor: VAR_DLV_ANCHOR STRING_ARG
	{
		OUTYY(("P(server_dlv_anchor:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->dlv_anchor_list, $2))
			yyerror("out of memory");
	}
	;
server_auto_trust_anchor_file: VAR_AUTO_TRUST_ANCHOR_FILE STRING_ARG
	{
		OUTYY(("P(server_auto_trust_anchor_file:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->
			auto_trust_anchor_file_list, $2))
			yyerror("out of memory");
	}
	;
server_trust_anchor_file: VAR_TRUST_ANCHOR_FILE STRING_ARG
	{
		OUTYY(("P(server_trust_anchor_file:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->
			trust_anchor_file_list, $2))
			yyerror("out of memory");
	}
	;
server_trusted_keys_file: VAR_TRUSTED_KEYS_FILE STRING_ARG
	{
		OUTYY(("P(server_trusted_keys_file:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->
			trusted_keys_file_list, $2))
			yyerror("out of memory");
	}
	;
server_trust_anchor: VAR_TRUST_ANCHOR STRING_ARG
	{
		OUTYY(("P(server_trust_anchor:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->trust_anchor_list, $2))
			yyerror("out of memory");
	}
	;
server_domain_insecure: VAR_DOMAIN_INSECURE STRING_ARG
	{
		OUTYY(("P(server_domain_insecure:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->domain_insecure, $2))
			yyerror("out of memory");
	}
	;
server_hide_identity: VAR_HIDE_IDENTITY STRING_ARG
	{
		OUTYY(("P(server_hide_identity:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->hide_identity = (strcmp($2, "yes")==0);
		free($2);
	}
	;
server_hide_version: VAR_HIDE_VERSION STRING_ARG
	{
		OUTYY(("P(server_hide_version:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->hide_version = (strcmp($2, "yes")==0);
		free($2);
	}
	;
server_identity: VAR_IDENTITY STRING_ARG
	{
		OUTYY(("P(server_identity:%s)\n", $2));
		free(cfg_parser->cfg->identity);
		cfg_parser->cfg->identity = $2;
	}
	;
server_version: VAR_VERSION STRING_ARG
	{
		OUTYY(("P(server_version:%s)\n", $2));
		free(cfg_parser->cfg->version);
		cfg_parser->cfg->version = $2;
	}
	;
server_so_rcvbuf: VAR_SO_RCVBUF STRING_ARG
	{
		OUTYY(("P(server_so_rcvbuf:%s)\n", $2));
		if(!cfg_parse_memsize($2, &cfg_parser->cfg->so_rcvbuf))
			yyerror("buffer size expected");
		free($2);
	}
	;
server_so_sndbuf: VAR_SO_SNDBUF STRING_ARG
	{
		OUTYY(("P(server_so_sndbuf:%s)\n", $2));
		if(!cfg_parse_memsize($2, &cfg_parser->cfg->so_sndbuf))
			yyerror("buffer size expected");
		free($2);
	}
	;
server_edns_buffer_size: VAR_EDNS_BUFFER_SIZE STRING_ARG
	{
		OUTYY(("P(server_edns_buffer_size:%s)\n", $2));
		if(atoi($2) == 0)
			yyerror("number expected");
		else if (atoi($2) < 12)
			yyerror("edns buffer size too small");
		else if (atoi($2) > 65535)
			cfg_parser->cfg->edns_buffer_size = 65535;
		else cfg_parser->cfg->edns_buffer_size = atoi($2);
		free($2);
	}
	;
server_msg_buffer_size: VAR_MSG_BUFFER_SIZE STRING_ARG
	{
		OUTYY(("P(server_msg_buffer_size:%s)\n", $2));
		if(atoi($2) == 0)
			yyerror("number expected");
		else if (atoi($2) < 4096)
			yyerror("message buffer size too small (use 4096)");
		else cfg_parser->cfg->msg_buffer_size = atoi($2);
		free($2);
	}
	;
server_msg_cache_size: VAR_MSG_CACHE_SIZE STRING_ARG
	{
		OUTYY(("P(server_msg_cache_size:%s)\n", $2));
		if(!cfg_parse_memsize($2, &cfg_parser->cfg->msg_cache_size))
			yyerror("memory size expected");
		free($2);
	}
	;
server_msg_cache_slabs: VAR_MSG_CACHE_SLABS STRING_ARG
	{
		OUTYY(("P(server_msg_cache_slabs:%s)\n", $2));
		if(atoi($2) == 0)
			yyerror("number expected");
		else {
			cfg_parser->cfg->msg_cache_slabs = atoi($2);
			if(!is_pow2(cfg_parser->cfg->msg_cache_slabs))
				yyerror("must be a power of 2");
		}
		free($2);
	}
	;
server_num_queries_per_thread: VAR_NUM_QUERIES_PER_THREAD STRING_ARG
	{
		OUTYY(("P(server_num_queries_per_thread:%s)\n", $2));
		if(atoi($2) == 0)
			yyerror("number expected");
		else cfg_parser->cfg->num_queries_per_thread = atoi($2);
		free($2);
	}
	;
server_jostle_timeout: VAR_JOSTLE_TIMEOUT STRING_ARG
	{
		OUTYY(("P(server_jostle_timeout:%s)\n", $2));
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->jostle_time = atoi($2);
		free($2);
	}
	;
server_rrset_cache_size: VAR_RRSET_CACHE_SIZE STRING_ARG
	{
		OUTYY(("P(server_rrset_cache_size:%s)\n", $2));
		if(!cfg_parse_memsize($2, &cfg_parser->cfg->rrset_cache_size))
			yyerror("memory size expected");
		free($2);
	}
	;
server_rrset_cache_slabs: VAR_RRSET_CACHE_SLABS STRING_ARG
	{
		OUTYY(("P(server_rrset_cache_slabs:%s)\n", $2));
		if(atoi($2) == 0)
			yyerror("number expected");
		else {
			cfg_parser->cfg->rrset_cache_slabs = atoi($2);
			if(!is_pow2(cfg_parser->cfg->rrset_cache_slabs))
				yyerror("must be a power of 2");
		}
		free($2);
	}
	;
server_infra_host_ttl: VAR_INFRA_HOST_TTL STRING_ARG
	{
		OUTYY(("P(server_infra_host_ttl:%s)\n", $2));
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->host_ttl = atoi($2);
		free($2);
	}
	;
server_infra_lame_ttl: VAR_INFRA_LAME_TTL STRING_ARG
	{
		OUTYY(("P(server_infra_lame_ttl:%s)\n", $2));
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->lame_ttl = atoi($2);
		free($2);
	}
	;
server_infra_cache_numhosts: VAR_INFRA_CACHE_NUMHOSTS STRING_ARG
	{
		OUTYY(("P(server_infra_cache_numhosts:%s)\n", $2));
		if(atoi($2) == 0)
			yyerror("number expected");
		else cfg_parser->cfg->infra_cache_numhosts = atoi($2);
		free($2);
	}
	;
server_infra_cache_lame_size: VAR_INFRA_CACHE_LAME_SIZE STRING_ARG
	{
		OUTYY(("P(server_infra_cache_lame_size:%s)\n", $2));
		if(!cfg_parse_memsize($2, &cfg_parser->cfg->
			infra_cache_lame_size))
			yyerror("number expected");
		free($2);
	}
	;
server_infra_cache_slabs: VAR_INFRA_CACHE_SLABS STRING_ARG
	{
		OUTYY(("P(server_infra_cache_slabs:%s)\n", $2));
		if(atoi($2) == 0)
			yyerror("number expected");
		else {
			cfg_parser->cfg->infra_cache_slabs = atoi($2);
			if(!is_pow2(cfg_parser->cfg->infra_cache_slabs))
				yyerror("must be a power of 2");
		}
		free($2);
	}
	;
server_target_fetch_policy: VAR_TARGET_FETCH_POLICY STRING_ARG
	{
		OUTYY(("P(server_target_fetch_policy:%s)\n", $2));
		free(cfg_parser->cfg->target_fetch_policy);
		cfg_parser->cfg->target_fetch_policy = $2;
	}
	;
server_harden_short_bufsize: VAR_HARDEN_SHORT_BUFSIZE STRING_ARG
	{
		OUTYY(("P(server_harden_short_bufsize:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->harden_short_bufsize = 
			(strcmp($2, "yes")==0);
		free($2);
	}
	;
server_harden_large_queries: VAR_HARDEN_LARGE_QUERIES STRING_ARG
	{
		OUTYY(("P(server_harden_large_queries:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->harden_large_queries = 
			(strcmp($2, "yes")==0);
		free($2);
	}
	;
server_harden_glue: VAR_HARDEN_GLUE STRING_ARG
	{
		OUTYY(("P(server_harden_glue:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->harden_glue = 
			(strcmp($2, "yes")==0);
		free($2);
	}
	;
server_harden_dnssec_stripped: VAR_HARDEN_DNSSEC_STRIPPED STRING_ARG
	{
		OUTYY(("P(server_harden_dnssec_stripped:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->harden_dnssec_stripped = 
			(strcmp($2, "yes")==0);
		free($2);
	}
	;
server_harden_below_nxdomain: VAR_HARDEN_BELOW_NXDOMAIN STRING_ARG
	{
		OUTYY(("P(server_harden_below_nxdomain:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->harden_below_nxdomain = 
			(strcmp($2, "yes")==0);
		free($2);
	}
	;
server_harden_referral_path: VAR_HARDEN_REFERRAL_PATH STRING_ARG
	{
		OUTYY(("P(server_harden_referral_path:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->harden_referral_path = 
			(strcmp($2, "yes")==0);
		free($2);
	}
	;
server_use_caps_for_id: VAR_USE_CAPS_FOR_ID STRING_ARG
	{
		OUTYY(("P(server_use_caps_for_id:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->use_caps_bits_for_id = 
			(strcmp($2, "yes")==0);
		free($2);
	}
	;
server_private_address: VAR_PRIVATE_ADDRESS STRING_ARG
	{
		OUTYY(("P(server_private_address:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->private_address, $2))
			yyerror("out of memory");
	}
	;
server_private_domain: VAR_PRIVATE_DOMAIN STRING_ARG
	{
		OUTYY(("P(server_private_domain:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->private_domain, $2))
			yyerror("out of memory");
	}
	;
server_prefetch: VAR_PREFETCH STRING_ARG
	{
		OUTYY(("P(server_prefetch:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->prefetch = (strcmp($2, "yes")==0);
		free($2);
	}
	;
server_prefetch_key: VAR_PREFETCH_KEY STRING_ARG
	{
		OUTYY(("P(server_prefetch_key:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->prefetch_key = (strcmp($2, "yes")==0);
		free($2);
	}
	;
server_unwanted_reply_threshold: VAR_UNWANTED_REPLY_THRESHOLD STRING_ARG
	{
		OUTYY(("P(server_unwanted_reply_threshold:%s)\n", $2));
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->unwanted_threshold = atoi($2);
		free($2);
	}
	;
server_do_not_query_address: VAR_DO_NOT_QUERY_ADDRESS STRING_ARG
	{
		OUTYY(("P(server_do_not_query_address:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->donotqueryaddrs, $2))
			yyerror("out of memory");
	}
	;
server_do_not_query_localhost: VAR_DO_NOT_QUERY_LOCALHOST STRING_ARG
	{
		OUTYY(("P(server_do_not_query_localhost:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->donotquery_localhost = 
			(strcmp($2, "yes")==0);
		free($2);
	}
	;
server_access_control: VAR_ACCESS_CONTROL STRING_ARG STRING_ARG
	{
		OUTYY(("P(server_access_control:%s %s)\n", $2, $3));
		if(strcmp($3, "deny")!=0 && strcmp($3, "refuse")!=0 &&
			strcmp($3, "allow")!=0 && 
			strcmp($3, "allow_snoop")!=0) {
			yyerror("expected deny, refuse, allow or allow_snoop "
				"in access control action");
		} else {
			if(!cfg_str2list_insert(&cfg_parser->cfg->acls, $2, $3))
				fatal_exit("out of memory adding acl");
		}
	}
	;
server_module_conf: VAR_MODULE_CONF STRING_ARG
	{
		OUTYY(("P(server_module_conf:%s)\n", $2));
		free(cfg_parser->cfg->module_conf);
		cfg_parser->cfg->module_conf = $2;
	}
	;
server_val_override_date: VAR_VAL_OVERRIDE_DATE STRING_ARG
	{
		OUTYY(("P(server_val_override_date:%s)\n", $2));
		if(strlen($2) == 0 || strcmp($2, "0") == 0) {
			cfg_parser->cfg->val_date_override = 0;
		} else if(strlen($2) == 14) {
			cfg_parser->cfg->val_date_override = 
				cfg_convert_timeval($2);
			if(!cfg_parser->cfg->val_date_override)
				yyerror("bad date/time specification");
		} else {
			if(atoi($2) == 0)
				yyerror("number expected");
			cfg_parser->cfg->val_date_override = atoi($2);
		}
		free($2);
	}
	;
server_val_sig_skew_min: VAR_VAL_SIG_SKEW_MIN STRING_ARG
	{
		OUTYY(("P(server_val_sig_skew_min:%s)\n", $2));
		if(strlen($2) == 0 || strcmp($2, "0") == 0) {
			cfg_parser->cfg->val_sig_skew_min = 0;
		} else {
			cfg_parser->cfg->val_sig_skew_min = atoi($2);
			if(!cfg_parser->cfg->val_sig_skew_min)
				yyerror("number expected");
		}
		free($2);
	}
	;
server_val_sig_skew_max: VAR_VAL_SIG_SKEW_MAX STRING_ARG
	{
		OUTYY(("P(server_val_sig_skew_max:%s)\n", $2));
		if(strlen($2) == 0 || strcmp($2, "0") == 0) {
			cfg_parser->cfg->val_sig_skew_max = 0;
		} else {
			cfg_parser->cfg->val_sig_skew_max = atoi($2);
			if(!cfg_parser->cfg->val_sig_skew_max)
				yyerror("number expected");
		}
		free($2);
	}
	;
server_cache_max_ttl: VAR_CACHE_MAX_TTL STRING_ARG
	{
		OUTYY(("P(server_cache_max_ttl:%s)\n", $2));
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->max_ttl = atoi($2);
		free($2);
	}
	;
server_cache_min_ttl: VAR_CACHE_MIN_TTL STRING_ARG
	{
		OUTYY(("P(server_cache_min_ttl:%s)\n", $2));
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->min_ttl = atoi($2);
		free($2);
	}
	;
server_bogus_ttl: VAR_BOGUS_TTL STRING_ARG
	{
		OUTYY(("P(server_bogus_ttl:%s)\n", $2));
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->bogus_ttl = atoi($2);
		free($2);
	}
	;
server_val_clean_additional: VAR_VAL_CLEAN_ADDITIONAL STRING_ARG
	{
		OUTYY(("P(server_val_clean_additional:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->val_clean_additional = 
			(strcmp($2, "yes")==0);
		free($2);
	}
	;
server_val_permissive_mode: VAR_VAL_PERMISSIVE_MODE STRING_ARG
	{
		OUTYY(("P(server_val_permissive_mode:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->val_permissive_mode = 
			(strcmp($2, "yes")==0);
		free($2);
	}
	;
server_val_log_level: VAR_VAL_LOG_LEVEL STRING_ARG
	{
		OUTYY(("P(server_val_log_level:%s)\n", $2));
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->val_log_level = atoi($2);
		free($2);
	}
	;
server_val_nsec3_keysize_iterations: VAR_VAL_NSEC3_KEYSIZE_ITERATIONS STRING_ARG
	{
		OUTYY(("P(server_val_nsec3_keysize_iterations:%s)\n", $2));
		free(cfg_parser->cfg->val_nsec3_key_iterations);
		cfg_parser->cfg->val_nsec3_key_iterations = $2;
	}
	;
server_add_holddown: VAR_ADD_HOLDDOWN STRING_ARG
	{
		OUTYY(("P(server_add_holddown:%s)\n", $2));
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->add_holddown = atoi($2);
		free($2);
	}
	;
server_del_holddown: VAR_DEL_HOLDDOWN STRING_ARG
	{
		OUTYY(("P(server_del_holddown:%s)\n", $2));
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->del_holddown = atoi($2);
		free($2);
	}
	;
server_keep_missing: VAR_KEEP_MISSING STRING_ARG
	{
		OUTYY(("P(server_keep_missing:%s)\n", $2));
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->cfg->keep_missing = atoi($2);
		free($2);
	}
	;
server_key_cache_size: VAR_KEY_CACHE_SIZE STRING_ARG
	{
		OUTYY(("P(server_key_cache_size:%s)\n", $2));
		if(!cfg_parse_memsize($2, &cfg_parser->cfg->key_cache_size))
			yyerror("memory size expected");
		free($2);
	}
	;
server_key_cache_slabs: VAR_KEY_CACHE_SLABS STRING_ARG
	{
		OUTYY(("P(server_key_cache_slabs:%s)\n", $2));
		if(atoi($2) == 0)
			yyerror("number expected");
		else {
			cfg_parser->cfg->key_cache_slabs = atoi($2);
			if(!is_pow2(cfg_parser->cfg->key_cache_slabs))
				yyerror("must be a power of 2");
		}
		free($2);
	}
	;
server_neg_cache_size: VAR_NEG_CACHE_SIZE STRING_ARG
	{
		OUTYY(("P(server_neg_cache_size:%s)\n", $2));
		if(!cfg_parse_memsize($2, &cfg_parser->cfg->neg_cache_size))
			yyerror("memory size expected");
		free($2);
	}
	;
server_local_zone: VAR_LOCAL_ZONE STRING_ARG STRING_ARG
	{
		OUTYY(("P(server_local_zone:%s %s)\n", $2, $3));
		if(strcmp($3, "static")!=0 && strcmp($3, "deny")!=0 &&
		   strcmp($3, "refuse")!=0 && strcmp($3, "redirect")!=0 &&
		   strcmp($3, "transparent")!=0 && strcmp($3, "nodefault")!=0
		   && strcmp($3, "typetransparent")!=0)
			yyerror("local-zone type: expected static, deny, "
				"refuse, redirect, transparent, "
				"typetransparent or nodefault");
		else if(strcmp($3, "nodefault")==0) {
			if(!cfg_strlist_insert(&cfg_parser->cfg->
				local_zones_nodefault, $2))
				fatal_exit("out of memory adding local-zone");
			free($3);
		} else {
			if(!cfg_str2list_insert(&cfg_parser->cfg->local_zones, 
				$2, $3))
				fatal_exit("out of memory adding local-zone");
		}
	}
	;
server_local_data: VAR_LOCAL_DATA STRING_ARG
	{
		OUTYY(("P(server_local_data:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->local_data, $2))
			fatal_exit("out of memory adding local-data");
	}
	;
server_local_data_ptr: VAR_LOCAL_DATA_PTR STRING_ARG
	{
		char* ptr;
		OUTYY(("P(server_local_data_ptr:%s)\n", $2));
		ptr = cfg_ptr_reverse($2);
		free($2);
		if(ptr) {
			if(!cfg_strlist_insert(&cfg_parser->cfg->
				local_data, ptr))
				fatal_exit("out of memory adding local-data");
		} else {
			yyerror("local-data-ptr could not be reversed");
		}
	}
	;
stub_name: VAR_NAME STRING_ARG
	{
		OUTYY(("P(name:%s)\n", $2));
		if(cfg_parser->cfg->stubs->name)
			yyerror("stub name override, there must be one name "
				"for one stub-zone");
		free(cfg_parser->cfg->stubs->name);
		cfg_parser->cfg->stubs->name = $2;
	}
	;
stub_host: VAR_STUB_HOST STRING_ARG
	{
		OUTYY(("P(stub-host:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->stubs->hosts, $2))
			yyerror("out of memory");
	}
	;
stub_addr: VAR_STUB_ADDR STRING_ARG
	{
		OUTYY(("P(stub-addr:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->stubs->addrs, $2))
			yyerror("out of memory");
	}
	;
stub_prime: VAR_STUB_PRIME STRING_ARG
	{
		OUTYY(("P(stub-prime:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->stubs->isprime = 
			(strcmp($2, "yes")==0);
		free($2);
	}
	;
forward_name: VAR_NAME STRING_ARG
	{
		OUTYY(("P(name:%s)\n", $2));
		if(cfg_parser->cfg->forwards->name)
			yyerror("forward name override, there must be one "
				"name for one forward-zone");
		free(cfg_parser->cfg->forwards->name);
		cfg_parser->cfg->forwards->name = $2;
	}
	;
forward_host: VAR_FORWARD_HOST STRING_ARG
	{
		OUTYY(("P(forward-host:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->forwards->hosts, $2))
			yyerror("out of memory");
	}
	;
forward_addr: VAR_FORWARD_ADDR STRING_ARG
	{
		OUTYY(("P(forward-addr:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->forwards->addrs, $2))
			yyerror("out of memory");
	}
	;
rcstart: VAR_REMOTE_CONTROL
	{ 
		OUTYY(("\nP(remote-control:)\n")); 
	}
	;
contents_rc: contents_rc content_rc 
	| ;
content_rc: rc_control_enable | rc_control_interface | rc_control_port |
	rc_server_key_file | rc_server_cert_file | rc_control_key_file |
	rc_control_cert_file
	;
rc_control_enable: VAR_CONTROL_ENABLE STRING_ARG
	{
		OUTYY(("P(control_enable:%s)\n", $2));
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->cfg->remote_control_enable = 
			(strcmp($2, "yes")==0);
		free($2);
	}
	;
rc_control_port: VAR_CONTROL_PORT STRING_ARG
	{
		OUTYY(("P(control_port:%s)\n", $2));
		if(atoi($2) == 0)
			yyerror("control port number expected");
		else cfg_parser->cfg->control_port = atoi($2);
		free($2);
	}
	;
rc_control_interface: VAR_CONTROL_INTERFACE STRING_ARG
	{
		OUTYY(("P(control_interface:%s)\n", $2));
		if(!cfg_strlist_insert(&cfg_parser->cfg->control_ifs, $2))
			yyerror("out of memory");
	}
	;
rc_server_key_file: VAR_SERVER_KEY_FILE STRING_ARG
	{
		OUTYY(("P(rc_server_key_file:%s)\n", $2));
		free(cfg_parser->cfg->server_key_file);
		cfg_parser->cfg->server_key_file = $2;
	}
	;
rc_server_cert_file: VAR_SERVER_CERT_FILE STRING_ARG
	{
		OUTYY(("P(rc_server_cert_file:%s)\n", $2));
		free(cfg_parser->cfg->server_cert_file);
		cfg_parser->cfg->server_cert_file = $2;
	}
	;
rc_control_key_file: VAR_CONTROL_KEY_FILE STRING_ARG
	{
		OUTYY(("P(rc_control_key_file:%s)\n", $2));
		free(cfg_parser->cfg->control_key_file);
		cfg_parser->cfg->control_key_file = $2;
	}
	;
rc_control_cert_file: VAR_CONTROL_CERT_FILE STRING_ARG
	{
		OUTYY(("P(rc_control_cert_file:%s)\n", $2));
		free(cfg_parser->cfg->control_cert_file);
		cfg_parser->cfg->control_cert_file = $2;
	}
	;
pythonstart: VAR_PYTHON
	{ 
		OUTYY(("\nP(python:)\n")); 
	}
	;
contents_py: contents_py content_py
	| ;
content_py: py_script
	;
py_script: VAR_PYTHON_SCRIPT STRING_ARG
	{
		OUTYY(("P(python-script:%s)\n", $2));
		free(cfg_parser->cfg->python_script);
		cfg_parser->cfg->python_script = $2;
	}
%%

/* parse helper routines could be here */
