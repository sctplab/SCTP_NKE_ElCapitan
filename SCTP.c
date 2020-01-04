/*
 * Copyright (c) 2008-2012, by Michael Tuexen. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/sysctl.h>
#include <netinet/in.h>
#include <sys/protosw.h>
#include <netinet/ip.h>
#include <sys/lock.h>
#include <sys/domain.h>
#include <net/route.h>
#include <sys/socketvar.h>
#include <netinet/in_pcb.h>
#include <netinet/sctp_os.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_timer.h>
#ifdef INET6
#include <netinet6/sctp6_var.h>
#endif
#include <netinet/sctp.h>
#if defined(APPLE_LEOPARD)
#include <netinet/udp.h>
#include <netinet/udp_var.h>

extern struct pr_usrreqs udp_usrreqs;
#ifdef INET6
extern struct pr_usrreqs udp6_usrreqs;
#endif
extern struct inpcbinfo udbinfo;
#endif

SYSCTL_DECL(_net_inet);
#ifdef INET6
SYSCTL_DECL(_net_inet6);
#endif
SYSCTL_NODE(_net_inet, IPPROTO_SCTP,    sctp,   CTLFLAG_RW, 0,  "SCTP")
#ifdef INET6
SYSCTL_NODE(_net_inet6, IPPROTO_SCTP,   sctp6,  CTLFLAG_RW, 0,  "SCTP6")
#endif

extern struct sysctl_oid sysctl__net_inet_sctp_sendspace;
extern struct sysctl_oid sysctl__net_inet_sctp_recvspace;
extern struct sysctl_oid sysctl__net_inet_sctp_auto_asconf;
extern struct sysctl_oid sysctl__net_inet_sctp_ecn_enable;
extern struct sysctl_oid sysctl__net_inet_sctp_pr_enable;
extern struct sysctl_oid sysctl__net_inet_sctp_auth_enable;
extern struct sysctl_oid sysctl__net_inet_sctp_asconf_enable;
extern struct sysctl_oid sysctl__net_inet_sctp_reconfig_enable;
extern struct sysctl_oid sysctl__net_inet_sctp_nrsack_enable;
extern struct sysctl_oid sysctl__net_inet_sctp_pktdrop_enable;
extern struct sysctl_oid sysctl__net_inet_sctp_fr_maxburst;
extern struct sysctl_oid sysctl__net_inet_sctp_loopback_nocsum;
extern struct sysctl_oid sysctl__net_inet_sctp_peer_chkoh;
extern struct sysctl_oid sysctl__net_inet_sctp_maxburst;
extern struct sysctl_oid sysctl__net_inet_sctp_maxchunks;
extern struct sysctl_oid sysctl__net_inet_sctp_delayed_sack_time;
extern struct sysctl_oid sysctl__net_inet_sctp_sack_freq;
extern struct sysctl_oid sysctl__net_inet_sctp_heartbeat_interval;
extern struct sysctl_oid sysctl__net_inet_sctp_pmtu_raise_time;
extern struct sysctl_oid sysctl__net_inet_sctp_shutdown_guard_time;
extern struct sysctl_oid sysctl__net_inet_sctp_secret_lifetime;
extern struct sysctl_oid sysctl__net_inet_sctp_rto_max;
extern struct sysctl_oid sysctl__net_inet_sctp_rto_min;
extern struct sysctl_oid sysctl__net_inet_sctp_rto_initial;
extern struct sysctl_oid sysctl__net_inet_sctp_init_rto_max;
extern struct sysctl_oid sysctl__net_inet_sctp_valid_cookie_life;
extern struct sysctl_oid sysctl__net_inet_sctp_init_rtx_max;
extern struct sysctl_oid sysctl__net_inet_sctp_assoc_rtx_max;
extern struct sysctl_oid sysctl__net_inet_sctp_path_rtx_max;
extern struct sysctl_oid sysctl__net_inet_sctp_path_pf_threshold;
extern struct sysctl_oid sysctl__net_inet_sctp_incoming_streams;
extern struct sysctl_oid sysctl__net_inet_sctp_outgoing_streams;
extern struct sysctl_oid sysctl__net_inet_sctp_cmt_on_off;
extern struct sysctl_oid sysctl__net_inet_sctp_cmt_use_dac;
extern struct sysctl_oid sysctl__net_inet_sctp_cwnd_maxburst;
extern struct sysctl_oid sysctl__net_inet_sctp_nat_friendly;
extern struct sysctl_oid sysctl__net_inet_sctp_abc_l_var;
extern struct sysctl_oid sysctl__net_inet_sctp_max_chained_mbufs;
extern struct sysctl_oid sysctl__net_inet_sctp_do_sctp_drain;
extern struct sysctl_oid sysctl__net_inet_sctp_hb_max_burst;
extern struct sysctl_oid sysctl__net_inet_sctp_abort_at_limit;
extern struct sysctl_oid sysctl__net_inet_sctp_min_residual;
extern struct sysctl_oid sysctl__net_inet_sctp_max_retran_chunk;
extern struct sysctl_oid sysctl__net_inet_sctp_log_level;
extern struct sysctl_oid sysctl__net_inet_sctp_default_cc_module;
extern struct sysctl_oid sysctl__net_inet_sctp_default_ss_module;
extern struct sysctl_oid sysctl__net_inet_sctp_default_frag_interleave;
extern struct sysctl_oid sysctl__net_inet_sctp_mobility_base;
extern struct sysctl_oid sysctl__net_inet_sctp_mobility_fasthandoff;
#if defined(SCTP_LOCAL_TRACE_BUF)
extern struct sysctl_oid sysctl__net_inet_sctp_log;
extern struct sysctl_oid sysctl__net_inet_sctp_clear_trace;
#endif
extern struct sysctl_oid sysctl__net_inet_sctp_udp_tunneling_port;
extern struct sysctl_oid sysctl__net_inet_sctp_enable_sack_immediately;
extern struct sysctl_oid sysctl__net_inet_sctp_nat_friendly_init;
extern struct sysctl_oid sysctl__net_inet_sctp_vtag_time_wait;
extern struct sysctl_oid sysctl__net_inet_sctp_buffer_splitting;
extern struct sysctl_oid sysctl__net_inet_sctp_initial_cwnd;
extern struct sysctl_oid sysctl__net_inet_sctp_rttvar_bw;
extern struct sysctl_oid sysctl__net_inet_sctp_rttvar_rtt;
extern struct sysctl_oid sysctl__net_inet_sctp_rttvar_eqret;
extern struct sysctl_oid sysctl__net_inet_sctp_rttvar_steady_step;
extern struct sysctl_oid sysctl__net_inet_sctp_use_dcccecn;
extern struct sysctl_oid sysctl__net_inet_sctp_blackhole;
extern struct sysctl_oid sysctl__net_inet_sctp_sendall_limit;
extern struct sysctl_oid sysctl__net_inet_sctp_diag_info_code;
#if defined(SCTP_DEBUG)
extern struct sysctl_oid sysctl__net_inet_sctp_debug;
#endif
extern struct sysctl_oid sysctl__net_inet_sctp_stats;
extern struct sysctl_oid sysctl__net_inet_sctp_assoclist;
extern struct sysctl_oid sysctl__net_inet_sctp_main_timer;
extern struct sysctl_oid sysctl__net_inet_sctp_ignore_vmware_interfaces;
extern struct sysctl_oid sysctl__net_inet_sctp_output_unlocked;
extern struct sysctl_oid sysctl__net_inet_sctp_addr_watchdog_limit;
extern struct sysctl_oid sysctl__net_inet_sctp_vtag_watchdog_limit;

#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
extern struct domain inetdomain;
#ifdef INET6
extern struct domain inet6domain;
#endif
#else
extern struct domain *inetdomain;
#ifdef INET6
extern struct domain *inet6domain;
#endif
#endif
extern struct protosw *ip_protox[];
#ifdef INET6
extern struct protosw *ip6_protox[];
#endif
extern struct sctp_epinfo sctppcinfo;

struct protosw sctp4_seqpacket;
struct protosw sctp4_stream;
#ifdef INET6
struct protosw sctp6_seqpacket;
struct protosw sctp6_stream;
#endif

struct protosw *old_pr4;
#ifdef INET6
struct protosw *old_pr6;
#endif

#if defined(APPLE_LEOPARD)
static int
soreceive_fix(struct socket *so, struct sockaddr **psa, struct uio *uio,  struct mbuf **mp0, struct mbuf **controlp, int *flagsp)
{
	if ((controlp) && (*controlp)) {
		m_freem(*controlp);
	}
	return (soreceive(so, psa, uio, mp0, controlp, flagsp));
}
#endif

kern_return_t 
SCTP_start(kmod_info_t * ki __attribute__((unused)), void * d __attribute__((unused)))
{
	int err;
#if !defined(APPLE_LEOPARD) && !defined(APPLE_SNOWLEOPARD) && !defined(APPLE_LION) && !defined(APPLE_MOUNTAINLION)
	domain_guard_t guard;
#endif

	old_pr4  = ip_protox [IPPROTO_SCTP];
#ifdef INET6
	old_pr6  = ip6_protox[IPPROTO_SCTP];
#endif

	memset(&sctp4_seqpacket, 0, sizeof(struct protosw));
	memset(&sctp4_stream,    0, sizeof(struct protosw));
#ifdef INET6
	memset(&sctp6_seqpacket, 0, sizeof(struct protosw));
	memset(&sctp6_stream,    0, sizeof(struct protosw));
#endif

	sctp4_seqpacket.pr_type      = SOCK_SEQPACKET;
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	sctp4_seqpacket.pr_domain    = &inetdomain;
#endif
	sctp4_seqpacket.pr_protocol  = IPPROTO_SCTP;
	sctp4_seqpacket.pr_flags     = PR_CONNREQUIRED|PR_WANTRCVD|PR_PCBLOCK|PR_PROTOLOCK;
	sctp4_seqpacket.pr_input     = sctp_input;
	sctp4_seqpacket.pr_output    = NULL;
	sctp4_seqpacket.pr_ctlinput  = sctp_ctlinput;
	sctp4_seqpacket.pr_ctloutput = sctp_ctloutput;
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	sctp4_seqpacket.pr_ousrreq   = NULL;
#endif
	sctp4_seqpacket.pr_init      = sctp_init;
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD)
	sctp4_seqpacket.pr_fasttimo  = NULL;
#endif
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	sctp4_seqpacket.pr_slowtimo  = sctp_slowtimo;
#endif
	sctp4_seqpacket.pr_drain     = sctp_drain;
	sctp4_seqpacket.pr_sysctl    = NULL;
	sctp4_seqpacket.pr_usrreqs   = &sctp_usrreqs;
	sctp4_seqpacket.pr_lock      = sctp_lock;
	sctp4_seqpacket.pr_unlock    = sctp_unlock;
	sctp4_seqpacket.pr_getlock   = sctp_getlock;

	sctp4_stream.pr_type         = SOCK_STREAM;
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	sctp4_stream.pr_domain       = &inetdomain;
#endif
	sctp4_stream.pr_protocol     = IPPROTO_SCTP;
	sctp4_stream.pr_flags        = PR_CONNREQUIRED|PR_WANTRCVD|PR_PCBLOCK|PR_PROTOLOCK;
	sctp4_stream.pr_input        = sctp_input;
	sctp4_stream.pr_output       = NULL;
	sctp4_stream.pr_ctlinput     = sctp_ctlinput;
	sctp4_stream.pr_ctloutput    = sctp_ctloutput;
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	sctp4_stream.pr_ousrreq      = NULL;
	sctp4_stream.pr_init         = NULL;
#else
	sctp4_stream.pr_init         = sctp_init;
#endif
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD)
	sctp4_stream.pr_fasttimo     = NULL;
#endif
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	sctp4_stream.pr_slowtimo     = NULL;
#endif
	sctp4_stream.pr_drain        = sctp_drain;
	sctp4_stream.pr_sysctl       = NULL;
	sctp4_stream.pr_usrreqs      = &sctp_usrreqs;
	sctp4_stream.pr_lock         = sctp_lock;
	sctp4_stream.pr_unlock       = sctp_unlock;
	sctp4_stream.pr_getlock      = sctp_getlock;

#ifdef INET6
	sctp6_seqpacket.pr_type      = SOCK_SEQPACKET;
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	sctp6_seqpacket.pr_domain    = &inet6domain;
#endif
	sctp6_seqpacket.pr_protocol  = IPPROTO_SCTP;
	sctp6_seqpacket.pr_flags     = PR_CONNREQUIRED|PR_WANTRCVD|PR_PCBLOCK|PR_PROTOLOCK;
	sctp6_seqpacket.pr_input     = (void (*) (struct mbuf *, int)) sctp6_input;
	sctp6_seqpacket.pr_output    = NULL;
	sctp6_seqpacket.pr_ctlinput  = sctp6_ctlinput;
	sctp6_seqpacket.pr_ctloutput = sctp_ctloutput;
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	sctp6_seqpacket.pr_ousrreq   = NULL;
	sctp6_seqpacket.pr_init      = NULL;
#else
	sctp6_seqpacket.pr_init      = sctp_init;
#endif
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD)
	sctp6_seqpacket.pr_fasttimo  = NULL;
#endif
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	sctp6_seqpacket.pr_slowtimo  = NULL;
#endif
	sctp6_seqpacket.pr_drain     = sctp_drain;
	sctp6_seqpacket.pr_sysctl    = NULL;
	sctp6_seqpacket.pr_usrreqs   = &sctp6_usrreqs;
	sctp6_seqpacket.pr_lock      = sctp_lock;
	sctp6_seqpacket.pr_unlock    = sctp_unlock;
	sctp6_seqpacket.pr_getlock   = sctp_getlock;

	sctp6_stream.pr_type         = SOCK_STREAM;
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	sctp6_stream.pr_domain       = &inet6domain;
#endif
	sctp6_stream.pr_protocol     = IPPROTO_SCTP;
	sctp6_stream.pr_flags        = PR_CONNREQUIRED|PR_WANTRCVD|PR_PCBLOCK|PR_PROTOLOCK;
	sctp6_stream.pr_input        = (void (*) (struct mbuf *, int)) sctp6_input;
	sctp6_stream.pr_output       = NULL;
	sctp6_stream.pr_ctlinput     = sctp6_ctlinput;
	sctp6_stream.pr_ctloutput    = sctp_ctloutput;
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	sctp6_stream.pr_ousrreq      = NULL;
	sctp6_stream.pr_init         = NULL;
#else
	sctp6_stream.pr_init         = sctp_init;
#endif
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD)
	sctp6_stream.pr_fasttimo     = NULL;
#endif
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	sctp6_stream.pr_slowtimo     = NULL;
#endif
	sctp6_stream.pr_drain        = sctp_drain;
	sctp6_stream.pr_sysctl       = NULL;
	sctp6_stream.pr_usrreqs      = &sctp6_usrreqs;
	sctp6_stream.pr_lock         = sctp_lock;
	sctp6_stream.pr_unlock       = sctp_unlock;
	sctp6_stream.pr_getlock      = sctp_getlock;
#endif

#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	lck_mtx_lock(inetdomain.dom_mtx);
#ifdef INET6
	lck_mtx_lock(inet6domain.dom_mtx);
#endif
#else
	guard = domain_guard_deploy();
#endif
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	err  = net_add_proto(&sctp4_seqpacket, &inetdomain);
	err |= net_add_proto(&sctp4_stream,    &inetdomain);
#ifdef INET6
	err |= net_add_proto(&sctp6_seqpacket, &inet6domain);
	err |= net_add_proto(&sctp6_stream,    &inet6domain);
#endif
#else
	err  = net_add_proto(&sctp4_seqpacket, inetdomain, 1);
	err |= net_add_proto(&sctp4_stream,    inetdomain, 0);
#ifdef INET6
	err |= net_add_proto(&sctp6_seqpacket, inet6domain, 0);
	err |= net_add_proto(&sctp6_stream,    inet6domain, 0);
#endif
#endif
	if (err) {
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
#ifdef INET6
		lck_mtx_unlock(inet6domain.dom_mtx);
#endif
		lck_mtx_unlock(inetdomain.dom_mtx);
#else
		domain_guard_release(guard);
#endif
		SCTP_PRINTF("SCTP NKE: Not all protocol handlers could be installed.\n");
		return (KERN_FAILURE);
	}

	ip_protox[IPPROTO_SCTP]  = &sctp4_seqpacket;
#ifdef INET6
	ip6_protox[IPPROTO_SCTP] = &sctp6_seqpacket;
#endif

#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
#ifdef INET6
	lck_mtx_unlock(inet6domain.dom_mtx);
#endif
	lck_mtx_unlock(inetdomain.dom_mtx);
#else
	domain_guard_release(guard);
#endif
	sysctl_register_oid(&sysctl__net_inet_sctp);
	sysctl_register_oid(&sysctl__net_inet_sctp_sendspace);
	sysctl_register_oid(&sysctl__net_inet_sctp_recvspace);
	sysctl_register_oid(&sysctl__net_inet_sctp_auto_asconf);
	sysctl_register_oid(&sysctl__net_inet_sctp_ecn_enable);
	sysctl_register_oid(&sysctl__net_inet_sctp_pr_enable);
	sysctl_register_oid(&sysctl__net_inet_sctp_auth_enable);
	sysctl_register_oid(&sysctl__net_inet_sctp_asconf_enable);
	sysctl_register_oid(&sysctl__net_inet_sctp_reconfig_enable);
	sysctl_register_oid(&sysctl__net_inet_sctp_nrsack_enable);
	sysctl_register_oid(&sysctl__net_inet_sctp_pktdrop_enable);
	sysctl_register_oid(&sysctl__net_inet_sctp_fr_maxburst);
	sysctl_register_oid(&sysctl__net_inet_sctp_loopback_nocsum);
	sysctl_register_oid(&sysctl__net_inet_sctp_peer_chkoh);
	sysctl_register_oid(&sysctl__net_inet_sctp_maxburst);
	sysctl_register_oid(&sysctl__net_inet_sctp_maxchunks);
	sysctl_register_oid(&sysctl__net_inet_sctp_delayed_sack_time);
	sysctl_register_oid(&sysctl__net_inet_sctp_sack_freq);
	sysctl_register_oid(&sysctl__net_inet_sctp_heartbeat_interval);
	sysctl_register_oid(&sysctl__net_inet_sctp_pmtu_raise_time);
	sysctl_register_oid(&sysctl__net_inet_sctp_shutdown_guard_time);
	sysctl_register_oid(&sysctl__net_inet_sctp_secret_lifetime);
	sysctl_register_oid(&sysctl__net_inet_sctp_rto_max);
	sysctl_register_oid(&sysctl__net_inet_sctp_rto_min);
	sysctl_register_oid(&sysctl__net_inet_sctp_rto_initial);
	sysctl_register_oid(&sysctl__net_inet_sctp_init_rto_max);
	sysctl_register_oid(&sysctl__net_inet_sctp_valid_cookie_life);
	sysctl_register_oid(&sysctl__net_inet_sctp_init_rtx_max);
	sysctl_register_oid(&sysctl__net_inet_sctp_assoc_rtx_max);
	sysctl_register_oid(&sysctl__net_inet_sctp_path_rtx_max);
	sysctl_register_oid(&sysctl__net_inet_sctp_path_pf_threshold);
	sysctl_register_oid(&sysctl__net_inet_sctp_incoming_streams);
	sysctl_register_oid(&sysctl__net_inet_sctp_outgoing_streams);
	sysctl_register_oid(&sysctl__net_inet_sctp_cmt_on_off);
	sysctl_register_oid(&sysctl__net_inet_sctp_cmt_use_dac);
	sysctl_register_oid(&sysctl__net_inet_sctp_cwnd_maxburst);
	sysctl_register_oid(&sysctl__net_inet_sctp_nat_friendly);
	sysctl_register_oid(&sysctl__net_inet_sctp_abc_l_var);
	sysctl_register_oid(&sysctl__net_inet_sctp_max_chained_mbufs);
	sysctl_register_oid(&sysctl__net_inet_sctp_do_sctp_drain);
	sysctl_register_oid(&sysctl__net_inet_sctp_hb_max_burst);
	sysctl_register_oid(&sysctl__net_inet_sctp_abort_at_limit);
	sysctl_register_oid(&sysctl__net_inet_sctp_min_residual);
	sysctl_register_oid(&sysctl__net_inet_sctp_max_retran_chunk);
	sysctl_register_oid(&sysctl__net_inet_sctp_log_level);
	sysctl_register_oid(&sysctl__net_inet_sctp_default_cc_module);
	sysctl_register_oid(&sysctl__net_inet_sctp_default_ss_module);
	sysctl_register_oid(&sysctl__net_inet_sctp_default_frag_interleave);
	sysctl_register_oid(&sysctl__net_inet_sctp_mobility_base);
	sysctl_register_oid(&sysctl__net_inet_sctp_mobility_fasthandoff);
#if defined(SCTP_LOCAL_TRACE_BUF)
	sysctl_register_oid(&sysctl__net_inet_sctp_log);
	sysctl_register_oid(&sysctl__net_inet_sctp_clear_trace);
#endif
	sysctl_register_oid(&sysctl__net_inet_sctp_udp_tunneling_port);
	sysctl_register_oid(&sysctl__net_inet_sctp_enable_sack_immediately);
	sysctl_register_oid(&sysctl__net_inet_sctp_nat_friendly_init);
	sysctl_register_oid(&sysctl__net_inet_sctp_vtag_time_wait);
	sysctl_register_oid(&sysctl__net_inet_sctp_buffer_splitting);
	sysctl_register_oid(&sysctl__net_inet_sctp_initial_cwnd);
	sysctl_register_oid(&sysctl__net_inet_sctp_rttvar_bw);
	sysctl_register_oid(&sysctl__net_inet_sctp_rttvar_rtt);
	sysctl_register_oid(&sysctl__net_inet_sctp_rttvar_eqret);
	sysctl_register_oid(&sysctl__net_inet_sctp_rttvar_steady_step);
	sysctl_register_oid(&sysctl__net_inet_sctp_use_dcccecn);
	sysctl_register_oid(&sysctl__net_inet_sctp_blackhole);
	sysctl_register_oid(&sysctl__net_inet_sctp_sendall_limit);
	sysctl_register_oid(&sysctl__net_inet_sctp_diag_info_code);
#ifdef SCTP_DEBUG
	sysctl_register_oid(&sysctl__net_inet_sctp_debug);
#endif
	sysctl_register_oid(&sysctl__net_inet_sctp_stats);
	sysctl_register_oid(&sysctl__net_inet_sctp_assoclist);
	sysctl_register_oid(&sysctl__net_inet_sctp_main_timer);
	sysctl_register_oid(&sysctl__net_inet_sctp_ignore_vmware_interfaces);
	sysctl_register_oid(&sysctl__net_inet_sctp_output_unlocked);
	sysctl_register_oid(&sysctl__net_inet_sctp_addr_watchdog_limit);
	sysctl_register_oid(&sysctl__net_inet_sctp_vtag_watchdog_limit);

#if defined(APPLE_LEOPARD)
	lck_rw_lock_exclusive(udbinfo.mtx);
	udp_usrreqs.pru_soreceive = soreceive_fix;
#ifdef INET6
	udp6_usrreqs.pru_soreceive = soreceive_fix;
#endif
	lck_rw_done(udbinfo.mtx);
#endif
	SCTP_PRINTF("SCTP NKE: NKE loaded.\n");
	return (KERN_SUCCESS);
}


kern_return_t 
SCTP_stop(kmod_info_t * ki __attribute__((unused)), void * d __attribute__((unused)))
{
	struct inpcb *inp;
	int err;
#if !defined(APPLE_LEOPARD) && !defined(APPLE_SNOWLEOPARD) && !defined(APPLE_LION) && !defined(APPLE_MOUNTAINLION)
	domain_guard_t guard;
#endif
	
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	if (!lck_rw_try_lock_exclusive(SCTP_BASE_INFO(sctbinfo).mtx)) {
#else
	if (!lck_rw_try_lock_exclusive(SCTP_BASE_INFO(sctbinfo).ipi_lock)) {
#endif
		SCTP_PRINTF("SCTP NKE: Someone else holds the lock\n");
		return (KERN_FAILURE);
	}
	if (!LIST_EMPTY(&SCTP_BASE_INFO(listhead))) {
		SCTP_PRINTF("SCTP NKE: There are still SCTP endpoints. NKE not unloaded\n");
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
		lck_rw_unlock_exclusive(SCTP_BASE_INFO(sctbinfo).mtx);
#else
		lck_rw_unlock_exclusive(SCTP_BASE_INFO(sctbinfo).ipi_lock);
#endif
		return (KERN_FAILURE);
	}

#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	if (!LIST_EMPTY(SCTP_BASE_INFO(sctbinfo).listhead)) {
#else
	if (!LIST_EMPTY(SCTP_BASE_INFO(sctbinfo).ipi_listhead)) {
#endif
		SCTP_PRINTF("SCTP NKE: There are still not deleted SCTP endpoints. NKE not unloaded\n");
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
		LIST_FOREACH(inp, SCTP_BASE_INFO(sctbinfo).listhead, inp_list) {
#else
		LIST_FOREACH(inp, SCTP_BASE_INFO(sctbinfo).ipi_listhead, inp_list) {
#endif
			SCTP_PRINTF("inp = %p: inp_wantcnt = %d, inp_state = %d, inp_socket->so_usecount = %d\n", inp, inp->inp_wantcnt, inp->inp_state, inp->inp_socket->so_usecount);
		}
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
		lck_rw_unlock_exclusive(SCTP_BASE_INFO(sctbinfo).mtx);
#else
		lck_rw_unlock_exclusive(SCTP_BASE_INFO(sctbinfo).ipi_lock);
#endif
		return (KERN_FAILURE);
	}

#if defined(APPLE_LEOPARD)
	lck_rw_lock_exclusive(udbinfo.mtx);
	udp_usrreqs.pru_soreceive = soreceive;
#ifdef INET6
	udp6_usrreqs.pru_soreceive = soreceive;
#endif
	lck_rw_done(udbinfo.mtx);
#endif
	sysctl_unregister_oid(&sysctl__net_inet_sctp_sendspace);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_recvspace);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_auto_asconf);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_ecn_enable);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_pr_enable);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_auth_enable);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_asconf_enable);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_reconfig_enable);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_nrsack_enable);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_pktdrop_enable);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_fr_maxburst);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_loopback_nocsum);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_peer_chkoh);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_maxburst);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_maxchunks);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_delayed_sack_time);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_sack_freq);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_heartbeat_interval);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_pmtu_raise_time);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_shutdown_guard_time);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_secret_lifetime);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_rto_max);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_rto_min);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_rto_initial);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_init_rto_max);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_valid_cookie_life);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_init_rtx_max);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_assoc_rtx_max);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_path_rtx_max);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_path_pf_threshold);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_incoming_streams);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_outgoing_streams);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_cmt_on_off);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_cmt_use_dac);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_cwnd_maxburst);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_nat_friendly);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_abc_l_var);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_max_chained_mbufs);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_do_sctp_drain);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_hb_max_burst);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_abort_at_limit);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_min_residual);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_max_retran_chunk);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_log_level);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_default_cc_module);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_default_ss_module);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_default_frag_interleave);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_mobility_base);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_mobility_fasthandoff);
#if defined(SCTP_LOCAL_TRACE_BUF)
	sysctl_unregister_oid(&sysctl__net_inet_sctp_log);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_clear_trace);
#endif
	sysctl_unregister_oid(&sysctl__net_inet_sctp_udp_tunneling_port);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_enable_sack_immediately);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_nat_friendly_init);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_vtag_time_wait);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_buffer_splitting);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_initial_cwnd);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_rttvar_bw);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_rttvar_rtt);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_rttvar_eqret);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_rttvar_steady_step);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_use_dcccecn);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_blackhole);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_sendall_limit);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_diag_info_code);
#ifdef SCTP_DEBUG
	sysctl_unregister_oid(&sysctl__net_inet_sctp_debug);
#endif
	sysctl_unregister_oid(&sysctl__net_inet_sctp_stats);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_assoclist);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_main_timer);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_ignore_vmware_interfaces);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_output_unlocked);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_addr_watchdog_limit);
	sysctl_unregister_oid(&sysctl__net_inet_sctp_vtag_watchdog_limit);
	sysctl_unregister_oid(&sysctl__net_inet_sctp);

#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	lck_mtx_lock(inetdomain.dom_mtx);
#ifdef INET6
	lck_mtx_lock(inet6domain.dom_mtx);
#endif
#else
	guard = domain_guard_deploy();
#endif
	ip_protox[IPPROTO_SCTP]  = old_pr4;
#ifdef INET6
	ip6_protox[IPPROTO_SCTP] = old_pr6;
#endif

#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	err  = net_del_proto(sctp4_seqpacket.pr_type, sctp4_seqpacket.pr_protocol, &inetdomain);
	err |= net_del_proto(sctp4_stream.pr_type,    sctp4_stream.pr_protocol,    &inetdomain);
#ifdef INET6
	err |= net_del_proto(sctp6_seqpacket.pr_type, sctp6_seqpacket.pr_protocol, &inet6domain);
	err |= net_del_proto(sctp6_stream.pr_type,    sctp6_stream.pr_protocol,    &inet6domain);
#endif
#else
	err  = net_del_proto(sctp4_seqpacket.pr_type, sctp4_seqpacket.pr_protocol, inetdomain);
	err |= net_del_proto(sctp4_stream.pr_type,    sctp4_stream.pr_protocol,    inetdomain);
#ifdef INET6
	err |= net_del_proto(sctp6_seqpacket.pr_type, sctp6_seqpacket.pr_protocol, inet6domain);
	err |= net_del_proto(sctp6_stream.pr_type,    sctp6_stream.pr_protocol,    inet6domain);
#endif
#endif
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	lck_rw_unlock_exclusive(SCTP_BASE_INFO(sctbinfo).mtx);
#else
	lck_rw_unlock_exclusive(SCTP_BASE_INFO(sctbinfo).ipi_lock);
#endif
	sctp_finish();
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
#ifdef INET6
	lck_mtx_unlock(inet6domain.dom_mtx);
#endif
	lck_mtx_unlock(inetdomain.dom_mtx);
#else
	domain_guard_release(guard);
#endif
	if (err) {
		SCTP_PRINTF("SCTP NKE: Not all protocol handlers could be removed.\n");
		return (KERN_FAILURE);
	} else {
		SCTP_PRINTF("SCTP NKE: NKE unloaded.\n");
		return (KERN_SUCCESS);
	}
}
