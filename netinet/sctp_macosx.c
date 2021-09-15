/*-
 * Copyright (c) 2001-2007, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2005-2012, by Michael Tuexen. All rights reserved.
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
/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License.  The rights granted to you under the
 * License may not be used to create, or enable the creation or
 * redistribution of, unlawful or unlicensed copies of an Apple operating
 * system, or to circumvent, violate, or enable the circumvention or
 * violation of, any terms of an Apple operating system software license
 * agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */


#include <sys/param.h>
#include <sys/domain.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <net/route.h>
#include <netinet/ip.h>
#include <net/if_dl.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#include <netinet/in_pcb.h>
#include <netinet/sctp.h>
#include <netinet/sctp_os.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_var.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_peeloff.h>
#include <netinet/sctp_bsd_addr.h>
#include <netinet/sctp_timer.h>
#include <netinet/sctp_input.h>
#include <net/kpi_interface.h>
#define APPLE_FILE_NO 5

/* sctp_peeloff() support via socket option */
#if defined(HAVE_SCTP_PEELOFF_SOCKOPT)
#include <sys/file.h>
#include <sys/filedesc.h>

extern struct fileops socketops;

#include <sys/proc_internal.h>
#include <sys/file_internal.h>
#if defined(APPLE_LEOPARD)
#define CONFIG_MACF_SOCKET_SUBSET 1
#else
#define CONFIG_MACF 1
#endif
#include <sys/namei.h>
#include <sys/vnode_internal.h>
#if CONFIG_MACF_SOCKET_SUBSET
#include <security/mac_framework.h>
#endif /* MAC_SOCKET_SUBSET */
#endif /* HAVE_SCTP_PEELOFF_SOCKOPT */

#if defined(HAVE_SCTP_PEELOFF_SOCKOPT)

/*
 * NOTE!! sctp_peeloff_option() MUST be kept in sync with the Apple accept()
 * call.
 */

#define f_flag f_fglob->fg_flag
#define f_type f_fglob->fg_type
#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data

int
sctp_peeloff_option(struct proc *p, struct sctp_peeloff_opt *uap)
{
	struct fileproc *fp;
	int error;
	struct socket *head, *so = NULL;
	int fd = uap->s;
	int newfd;
	short fflag;		/* type must match fp->f_flag */
	/*
	 * workaround sonewconn() issue where qlimits are checked.
	 * i.e. sonewconn() can only be done on listening sockets
	 * and it expects the SO_ACCEPTCONN flag being set.
	 */
	int old_qlimit;
	short old_so_options;

	/* AUDIT_ARG(fd, uap->s); */
	error = fp_getfsock(p, fd, &fp, &head);
	if (error) {
		if (error == EOPNOTSUPP)
			error = ENOTSOCK;
		goto out;
	}
	if (head == NULL) {
		error = EBADF;
		goto out;
	}
#if CONFIG_MACF_SOCKET_SUBSET
	if ((error = mac_socket_check_accept(kauth_cred_get(), head)) != 0)
		goto out;
#endif /* MAC_SOCKET_SUBSET */

	error = sctp_can_peel_off(head, uap->assoc_id);
	if (error) {
		goto out;
	}

        socket_unlock(head, 0); /* unlock head to avoid deadlock with select, keep a ref on head */

	fflag = fp->f_flag;
	error = falloc(p, &fp, &newfd, vfs_context_current());
	if (error) {
		/*
		 * Probably ran out of file descriptors. Put the
		 * unaccepted connection back onto the queue and
		 * do another wakeup so some other process might
		 * have a chance at it.
		 */
		/* SCTP will NOT put the connection back onto queue */
		socket_lock(head, 0);
		goto out;
	}
	uap->new_sd = newfd;	/* return the new descriptor to the caller */

	/* sctp_get_peeloff() does sonewconn() which expects head to be locked */
	socket_lock(head, 0);
	old_qlimit = head->so_qlimit;
	old_so_options	= head->so_options;
	head->so_qlimit = 1;
	head->so_options |= SO_ACCEPTCONN;
	so = sctp_get_peeloff(head, uap->assoc_id, &error);
	head->so_qlimit = old_qlimit;
	head->so_options = old_so_options;
	if (so == NULL) {
		goto release_fd;
	}
	socket_unlock(head, 0);

#if CONFIG_MACF_SOCKET_SUBSET
	/*
	 * Pass the pre-accepted socket to the MAC framework. This is
	 * cheaper than allocating a file descriptor for the socket,
	 * calling the protocol accept callback, and possibly freeing
	 * the file descriptor should the MAC check fails.
	 */
	if ((error = mac_socket_check_accepted(kauth_cred_get(), so)) != 0) {
		so->so_state &= ~(SS_NOFDREF | SS_COMP);
		so->so_head = NULL;
		soclose(so);
		/* Drop reference on listening socket */
		socket_lock(head, 0);
		goto out;
	}
#endif /* MAC_SOCKET_SUBSET */

#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
	fp->f_type = DTYPE_SOCKET;
#endif
	fp->f_flag = fflag;
	fp->f_ops = &socketops;
	fp->f_data = (caddr_t)so;
	socket_lock(head, 0);
	/* sctp_get_peeloff() returns a new locked socket */
        so->so_state &= ~SS_COMP;
        so->so_state &= ~SS_NOFDREF;
        so->so_head = NULL;
	socket_unlock(so, 1);

release_fd:
	proc_fdlock(p);
	procfdtbl_releasefd(p, newfd, NULL);
	fp_drop(p, newfd, fp, 1);
	proc_fdunlock(p);
out:
	file_drop(fd);
	return (error);
}
#endif				/* HAVE_SCTP_PEELOFF_SOCKOPT */


/* socket lock pr_xxx functions */
#if defined(APPLE_LEOPARD)
int
sctp_lock(struct socket *so, int refcount, int lr)
#else
int
sctp_lock(struct socket *so, int refcount, void *debug SCTP_UNUSED)
#endif
{
	if (so->so_pcb) {
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD)
		lck_mtx_assert(((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_NOTOWNED);
		lck_mtx_lock(((struct inpcb *)so->so_pcb)->inpcb_mtx);
#else
		lck_mtx_assert(&((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_NOTOWNED);
		lck_mtx_lock(&((struct inpcb *)so->so_pcb)->inpcb_mtx);
#endif
	} else {
		panic("sctp_lock: so=%p has so_pcb == NULL.", so);
		lck_mtx_assert(so->so_proto->pr_domain->dom_mtx, LCK_MTX_ASSERT_NOTOWNED);
		lck_mtx_lock(so->so_proto->pr_domain->dom_mtx);
	}

	if (so->so_usecount < 0)
		panic("sctp_lock: so=%p so_pcb=%p ref=%x.", so, so->so_pcb, so->so_usecount);

	if (refcount)
		so->so_usecount++;

	SAVE_CALLERS(((struct sctp_inpcb *)so->so_pcb)->lock_caller1,
	             ((struct sctp_inpcb *)so->so_pcb)->lock_caller2,
	             ((struct sctp_inpcb *)so->so_pcb)->lock_caller3);
#if defined(APPLE_LEOPARD) && defined(__ppc__)
	((struct sctp_inpcb *)so->so_pcb)->lock_caller1 = lr;
	((struct sctp_inpcb *)so->so_pcb)->lock_caller2 = refcount;
#endif
	((struct sctp_inpcb *)so->so_pcb)->lock_gen_count = ((struct sctp_inpcb *)so->so_pcb)->gen_count++;
	return (0);
}

#if defined(APPLE_LEOPARD)
int
sctp_unlock(struct socket *so, int refcount, int lr)
#else
int
sctp_unlock(struct socket *so, int refcount, void *debug SCTP_UNUSED)
#endif
{
	if (so->so_pcb) {
		SAVE_CALLERS(((struct sctp_inpcb *)so->so_pcb)->unlock_caller1,
		             ((struct sctp_inpcb *)so->so_pcb)->unlock_caller2,
		             ((struct sctp_inpcb *)so->so_pcb)->unlock_caller3);
#if defined(APPLE_LEOPARD) && defined(__ppc__)
		((struct sctp_inpcb *)so->so_pcb)->unlock_caller1 = lr;
		((struct sctp_inpcb *)so->so_pcb)->unlock_caller2 = refcount;
#endif
		((struct sctp_inpcb *)so->so_pcb)->unlock_gen_count = ((struct sctp_inpcb *)so->so_pcb)->gen_count++;
	}

	if (refcount)
		so->so_usecount--;

	if (so->so_usecount < 0)
		panic("sctp_unlock: so=%p usecount=%x.", so, so->so_usecount);

	if (so->so_pcb == NULL) {
		panic("sctp_unlock: so=%p has so_pcb == NULL.", so);
		lck_mtx_assert(so->so_proto->pr_domain->dom_mtx, LCK_MTX_ASSERT_OWNED);
		lck_mtx_unlock(so->so_proto->pr_domain->dom_mtx);
	} else {
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD)
		lck_mtx_assert(((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_OWNED);
		lck_mtx_unlock(((struct inpcb *)so->so_pcb)->inpcb_mtx);
#else
		lck_mtx_assert(&((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_OWNED);
		lck_mtx_unlock(&((struct inpcb *)so->so_pcb)->inpcb_mtx);
#endif
	}
	return (0);
}

lck_mtx_t *
sctp_getlock(struct socket *so, int locktype SCTP_UNUSED)
{
	/* WARNING: we do not own the socket lock here... */
	/* We do not have always enough callers */
	/*
	SAVE_CALLERS(((struct sctp_inpcb *)so->so_pcb)->getlock_caller1,
	             ((struct sctp_inpcb *)so->so_pcb)->getlock_caller2,
	             ((struct sctp_inpcb *)so->so_pcb)->getlock_caller3);
	((struct sctp_inpcb *)so->so_pcb)->getlock_gen_count = ((struct sctp_inpcb *)so->so_pcb)->gen_count++;
	*/
	if (so->so_pcb) {
		if (so->so_usecount < 0)
			panic("sctp_getlock: so=%p usecount=%x.", so, so->so_usecount);
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD)
		return (((struct inpcb *)so->so_pcb)->inpcb_mtx);
#else
		return (&((struct inpcb *)so->so_pcb)->inpcb_mtx);
#endif
	} else {
		panic("sctp_getlock: so=%p has so_pcb == NULL.", so);
		return (so->so_proto->pr_domain->dom_mtx);
	}
}

void
sctp_lock_assert(struct socket *so)
{
	if (so->so_pcb) {
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD)
		lck_mtx_assert(((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_OWNED);
#else
		lck_mtx_assert(&((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_OWNED);
#endif
	} else {
		panic("sctp_lock_assert: so=%p has so->so_pcb == NULL.", so);
	}
}

void
sctp_unlock_assert(struct socket *so)
{
	if (so->so_pcb) {
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD)
		lck_mtx_assert(((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_NOTOWNED);
#else
		lck_mtx_assert(&((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_NOTOWNED);
#endif
	} else {
		panic("sctp_unlock_assert: so=%p has so->so_pcb == NULL.", so);
	}
}

/*
 * locks
 */
#ifdef _KERN_LOCKS_H_
lck_rw_t *sctp_calloutq_mtx;
lck_rw_t *sctp_os_timerwait_mtx;
#else
void *sctp_calloutq_mtx;
void *sctp_os_timerwait_mtx;
#endif

/*
 * here we fix up Apple's m_prepend() and m_prepend_2().
 * See FreeBSD uipc_mbuf.c, version 1.170.
 * This is still needed for Leopard.
 */
struct mbuf *
sctp_m_prepend(struct mbuf *m, int len, int how)
{
	struct mbuf *mn;

	MGET(mn, how, m->m_type);
	if (mn == (struct mbuf *)NULL) {
		m_freem(m);
		return ((struct mbuf *)NULL);
	}
	if (m->m_flags & M_PKTHDR) {
		M_COPY_PKTHDR(mn, m);
		m->m_flags &= ~M_PKTHDR;
	}
	mn->m_next = m;
	m = mn;
	if (m->m_flags & M_PKTHDR) {
		if ((size_t)len < MHLEN)
			MH_ALIGN(m, len);
	} else {
		if ((size_t)len < MLEN)
			M_ALIGN(m, len);
	}
	m->m_len = len;
	return (m);
}

struct mbuf *
sctp_m_prepend_2(struct mbuf *m, int len, int how)
{
	if (M_LEADINGSPACE(m) >= len) {
		m->m_data -= len;
		m->m_len += len;
	} else {
		m = sctp_m_prepend(m, len, how);
	}
	if ((m) && (m->m_flags & M_PKTHDR))
		m->m_pkthdr.len += len;
	return (m);
}

#if !defined(APPLE_LEOPARD)
inline struct mbuf *
m_pulldown(struct mbuf *mbuf, int offset, int len, int *offsetp)
{
	mbuf_t result;

	result = NULL;
	*offsetp = offset;
	(void)mbuf_pulldown(mbuf, (size_t *)offsetp, len, &result);
	return (result);
}
#endif

int
timingsafe_bcmp(const void *b1, const void *b2, size_t n)
{
	const unsigned char *p1 = b1, *p2 = b2;
	int ret = 0;

	for (; n > 0; n--)
		ret |= *p1++ ^ *p2++;
	return (ret != 0);
}

static void
sctp_print_addr(struct sockaddr *sa)
{	
	switch (sa->sa_family) {
#ifdef INET6
	case AF_INET6:
	{
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)sa;
		SCTP_PRINTF("%s", ip6_sprintf(&sin6->sin6_addr));
		break;
	}
#endif
#ifdef INET
	case AF_INET:
	{
		struct sockaddr_in *sin;
		unsigned char *p;

		sin = (struct sockaddr_in *)sa;
		p = (unsigned char *)&sin->sin_addr;
		SCTP_PRINTF("%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
		break;
	}
#endif
	default:
		break;
	}
}

static void
sctp_addr_watchdog(void)
{
	struct ifnet **ifnetlist;
	struct ifaddr **ifaddrlist;
	uint32_t i, j, count;
	struct ifnet *ifn;
	struct ifaddr *ifa;
	ifaddr_t ifaddr;
	struct sockaddr *sa;
	struct sctp_vrf *vrf;
	struct sctp_ifn *sctp_ifn;
	struct sctp_ifa *sctp_ifa;

	SCTP_IPI_ADDR_RLOCK();
	vrf = sctp_find_vrf(SCTP_DEFAULT_VRFID);
	if (vrf == NULL) {
		SCTP_IPI_ADDR_RUNLOCK();
		SCTP_PRINTF("SCTP-NKE: Can't find default VRF.\n");
		return;
	}
#ifdef SCTP_DEBUG
	if (SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_PCB2) {
		SCTP_PRINTF("SCTP-NKE: Interfaces available for SCTP:\n");
	}
#endif
	LIST_FOREACH(sctp_ifn, &vrf->ifnlist, next_ifn) {
#ifdef SCTP_DEBUG
		if (SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_PCB2) {
			SCTP_PRINTF("SCTP-NKE: \tInterface %s (index %d): ", sctp_ifn->ifn_name, sctp_ifn->ifn_index);
		}
#endif
		LIST_FOREACH(sctp_ifa, &sctp_ifn->ifalist, next_ifa) {
			sa = &sctp_ifa->address.sa;
			if (sa == NULL) {
				continue;
			}
			switch (sa->sa_family) {
#ifdef INET
			case AF_INET:
#endif
#ifdef INET6
			case AF_INET6:
#endif
#ifdef SCTP_DEBUG
				if (SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_PCB2) {
					sctp_print_addr(sa);
					SCTP_PRINTF(" ");
				}
#endif
				if ((ifaddr = ifaddr_withaddr(sa)) == NULL) {
					SCTP_PRINTF("SCTP-NKE: Automatically deleting ");
					sctp_print_addr(sa);
					SCTP_PRINTF(" to interface %s (index %d).\n", sctp_ifn->ifn_name, sctp_ifn->ifn_index);
					SCTP_IPI_ADDR_RUNLOCK();
					sctp_del_addr_from_vrf(SCTP_DEFAULT_VRFID, sa, sctp_ifn->ifn_index, sctp_ifn->ifn_name);
					return;
				} else {
					ifaddr_release(ifaddr);
				}
				break;
			default:
				break;
			}
		}
#ifdef SCTP_DEBUG
		if (SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_PCB2) {
			SCTP_PRINTF("\n");
		}
#endif
	}
	SCTP_IPI_ADDR_RUNLOCK();
	
	if (ifnet_list_get(IFNET_FAMILY_ANY, &ifnetlist, &count) != 0) {
		return;
	}
#ifdef SCTP_DEBUG
	if (SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_PCB2) {
		SCTP_PRINTF("SCTP-NKE: Interfaces available on the system:\n");
	}
#endif
	for (i = 0; i < count; i++) {
		ifn = ifnetlist[i];
#ifdef SCTP_DEBUG
		if (SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_PCB2) {
			SCTP_PRINTF("SCTP-NKE: \tInterface %s%d (index %d): ", ifnet_name(ifn), ifnet_unit(ifn), ifnet_index(ifn));
		}
#endif
		if (ifnet_get_address_list(ifn, &ifaddrlist) != 0) {
			continue;
		}
		for (j = 0; ifaddrlist[j] != NULL; j++) {
			ifa = ifaddrlist[j];
			sa = ifa->ifa_addr;
			if (sa == NULL) {
				continue;
			}
			switch (sa->sa_family) {
#ifdef INET
			case AF_INET:
#endif
#ifdef INET6
			case AF_INET6:
#endif
#ifdef SCTP_DEBUG
				if (SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_PCB2) {
					sctp_print_addr(sa);
				}
#endif
				if (sctp_find_ifa_by_addr(sa, SCTP_DEFAULT_VRFID, SCTP_ADDR_NOT_LOCKED) == NULL) {
#ifdef SCTP_DEBUG
					if (SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_PCB2) {
						SCTP_PRINTF("!");
					} else {
#endif
						SCTP_PRINTF("SCTP-NKE: Automatically adding ");
						sctp_print_addr(sa);
						SCTP_PRINTF(" to interface %s%d (index %d).\n", ifnet_name(ifn), ifnet_unit(ifn), ifnet_index(ifn));
#ifdef SCTP_DEBUG
					}
#endif
					sctp_addr_change(ifa, RTM_ADD);
				}
#ifdef SCTP_DEBUG
				if (SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_PCB2) {
					SCTP_PRINTF(" ");
				}
#endif
				break;
			default:
				break;
			}
		}
		ifnet_free_address_list(ifaddrlist);
#ifdef SCTP_DEBUG
		if (SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_PCB2) {
			SCTP_PRINTF("\n");
		}
#endif
	}
	ifnet_list_free(ifnetlist);
	return;
}

static void
sctp_vtag_watchdog(void)
{
	struct timeval now;
	uint32_t i, j, free_cnt, expired_cnt, inuse_cnt, other_cnt;
	struct sctpvtaghead *chain;
	struct sctp_tagblock *twait_block;

	(void)SCTP_GETTIME_TIMEVAL(&now);
	SCTP_INP_INFO_RLOCK();
	for (i = 0; i < SCTP_STACK_VTAG_HASH_SIZE; i++) {
		chain = &SCTP_BASE_INFO(vtag_timewait)[i];
		free_cnt = 0;
		expired_cnt = 0;
		inuse_cnt = 0;
		other_cnt = 0;
		LIST_FOREACH(twait_block, chain, sctp_nxt_tagblock) {
			for (j = 0; j < SCTP_NUMBER_IN_VTAG_BLOCK; j++) {
				if ((twait_block->vtag_block[j].v_tag == 0) &&
				    (twait_block->vtag_block[j].lport == 0) &&
				    (twait_block->vtag_block[j].rport == 0) &&
				    (twait_block->vtag_block[j].tv_sec_at_expire == 0)) {
					free_cnt++;
				} else if ((twait_block->vtag_block[j].v_tag != 0) &&
					   (twait_block->vtag_block[j].tv_sec_at_expire < (uint32_t)now.tv_sec)) {
					expired_cnt++;
				} else if ((twait_block->vtag_block[j].v_tag != 0) &&
					   (twait_block->vtag_block[j].tv_sec_at_expire >= (uint32_t)now.tv_sec)) {
					inuse_cnt++;
				} else {
					other_cnt++;
				}
			}
		}
		if ((i % 16) == 0) {
			SCTP_PRINTF("SCTP-NKE: vtag_timewait[%04x] (f/e/i): ", i);
		}
		SCTP_PRINTF(" %d/%d/%d", free_cnt, expired_cnt, inuse_cnt);
		if (((i + 1) % 16) == 0) {
			SCTP_PRINTF("\n");
		}
	}
	SCTP_INP_INFO_RUNLOCK();
	return;
}

/*
 * timer functions
 */

void
sctp_start_main_timer(void) {
#if !defined(APPLE_LEOPARD) && !defined(APPLE_SNOWLEOPARD) && !defined(APPLE_LION) && !defined(APPLE_MOUNTAINLION)
	static uint32_t sctp_addr_watchdog_cnt = 0;
	static uint32_t sctp_vtag_watchdog_cnt = 0;

	if ((SCTP_BASE_SYSCTL(sctp_addr_watchdog_limit) > 0) &&
	    (++sctp_addr_watchdog_cnt >= SCTP_BASE_SYSCTL(sctp_addr_watchdog_limit))) {
		sctp_addr_watchdog_cnt = 0;
		sctp_addr_watchdog();
	}
	if ((SCTP_BASE_SYSCTL(sctp_vtag_watchdog_limit) > 0) &&
	    (++sctp_vtag_watchdog_cnt >= SCTP_BASE_SYSCTL(sctp_vtag_watchdog_limit))) {
		sctp_vtag_watchdog_cnt = 0;
		sctp_vtag_watchdog();
	}
#endif
	/* bound the timer (in msec) */
	if ((int)SCTP_BASE_SYSCTL(sctp_main_timer) < 1000/hz)
		SCTP_BASE_SYSCTL(sctp_main_timer) = 1000/hz;
	SCTP_BASE_VAR(sctp_main_timer_ticks) = sctp_msecs_to_ticks(SCTP_BASE_SYSCTL(sctp_main_timer));
	timeout(sctp_timeout, NULL, SCTP_BASE_VAR(sctp_main_timer_ticks));
}

void
sctp_stop_main_timer(void) {
	untimeout(sctp_timeout, NULL);
}

#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
void
sctp_slowtimo(void)
{
	struct inpcb *inp, *ninp;
	struct socket *so;
	static uint32_t sctp_addr_watchdog_cnt = 0;
	static uint32_t sctp_vtag_watchdog_cnt = 0;
#ifdef SCTP_DEBUG
	unsigned int n = 0;
#endif

	if ((SCTP_BASE_SYSCTL(sctp_addr_watchdog_limit) > 0) &&
	    (++sctp_addr_watchdog_cnt >= SCTP_BASE_SYSCTL(sctp_addr_watchdog_limit))) {
		sctp_addr_watchdog_cnt = 0;
		sctp_addr_watchdog();
	}
	if ((SCTP_BASE_SYSCTL(sctp_vtag_watchdog_limit) > 0) &&
	    (++sctp_vtag_watchdog_cnt >= SCTP_BASE_SYSCTL(sctp_vtag_watchdog_limit))) {
		sctp_vtag_watchdog_cnt = 0;
		sctp_vtag_watchdog();
	}

	lck_rw_lock_exclusive(SCTP_BASE_INFO(sctbinfo).mtx);
	LIST_FOREACH_SAFE(inp, SCTP_BASE_INFO(sctbinfo).listhead, inp_list, ninp) {
#ifdef SCTP_DEBUG
		if ((SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_PCB2)) {
			n++;
			SCTP_PRINTF("sctp_slowtimo: inp %p, wantcnt %u, so_usecount %d.\n",
			       inp, inp->inp_wantcnt, inp->inp_socket->so_usecount);
		}
#endif
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD)
		if ((inp->inp_wantcnt == WNT_STOPUSING) && (lck_mtx_try_lock(inp->inpcb_mtx))) {
			so = inp->inp_socket;
			if ((so->so_usecount != 0) || (inp->inp_state != INPCB_STATE_DEAD)) {
				lck_mtx_unlock(inp->inpcb_mtx);
			} else {
				LIST_REMOVE(inp, inp_list);
				inp->inp_socket = NULL;
				so->so_pcb      = NULL;
				lck_mtx_unlock(inp->inpcb_mtx);
				lck_mtx_free(inp->inpcb_mtx, SCTP_BASE_INFO(sctbinfo).ipi_lock_grp);
				SCTP_ZONE_FREE(SCTP_BASE_INFO(ipi_zone_ep), inp);
				sodealloc(so);
				SCTP_DECR_EP_COUNT();
			}
		}
#else
		if ((inp->inp_wantcnt == WNT_STOPUSING) && (lck_mtx_try_lock(&inp->inpcb_mtx))) {
			so = inp->inp_socket;
			if ((so->so_usecount != 0) || (inp->inp_state != INPCB_STATE_DEAD)) {
				lck_mtx_unlock(&inp->inpcb_mtx);
			} else {
				LIST_REMOVE(inp, inp_list);
				inp->inp_socket = NULL;
				so->so_pcb      = NULL;
				lck_mtx_unlock(&inp->inpcb_mtx);
				lck_mtx_destroy(&inp->inpcb_mtx, SCTP_BASE_INFO(sctbinfo).mtx_grp);
				SCTP_ZONE_FREE(SCTP_BASE_INFO(ipi_zone_ep), inp);
				sodealloc(so);
				SCTP_DECR_EP_COUNT();
			}
		}
#endif
	}
	lck_rw_unlock_exclusive(SCTP_BASE_INFO(sctbinfo).mtx);
#ifdef SCTP_DEBUG
	if ((SCTP_BASE_SYSCTL(sctp_debug_on) & SCTP_DEBUG_PCB2) && (n > 0)) {
		SCTP_PRINTF("sctp_slowtimo: Total number of inps: %u\n", n);
	}
#endif
}
#else
/* Garbage collection performed during most recent sctp_gc() run */
static boolean_t sctp_gc_done = FALSE;

void
sctp_gc(struct inpcbinfo *ipi)
{
	struct inpcb *inp, *ninp;
	struct socket *so;

	SCTP_PRINTF("sctp_gc() called with %p.\n", (void *)ipi);
	if (lck_rw_try_lock_exclusive(ipi->ipi_lock) == FALSE) {
		if (sctp_gc_done == TRUE) {
			sctp_gc_done = FALSE;
			/* couldn't get the lock, must lock next time */
			atomic_add_32(&ipi->ipi_gc_req.intimer_fast, 1);
			return;
		}
		lck_rw_lock_exclusive(ipi->ipi_lock);
	}

	sctp_gc_done = TRUE;
	LIST_FOREACH_SAFE(inp, ipi->ipi_listhead, inp_list, ninp) {
		/*
		 * Skip unless it's STOPUSING; garbage collector will
		 * be triggered by in_pcb_checkstate() upon setting
		 * wantcnt to that value.  If the PCB is already dead,
		 * keep gc active to anticipate wantcnt changing.
		 */
		if (inp->inp_wantcnt != WNT_STOPUSING)
			continue;

		/*
		 * Skip if busy, no hurry for cleanup.  Keep gc active
		 * and try the lock again during next round.
		 */
		if (!lck_mtx_try_lock(&inp->inpcb_mtx)) {
			atomic_add_32(&ipi->ipi_gc_req.intimer_fast, 1);
			continue;
		}

		/*
		 * Keep gc active unless usecount is 0.
		 */
		so = inp->inp_socket;
		if ((so->so_usecount != 0) || (inp->inp_state != INPCB_STATE_DEAD)) {
			lck_mtx_unlock(&inp->inpcb_mtx);
			atomic_add_32(&ipi->ipi_gc_req.intimer_fast, 1);
		} else {
			LIST_REMOVE(inp, inp_list);
			inp->inp_socket = NULL;
			so->so_pcb      = NULL;
			lck_mtx_unlock(&inp->inpcb_mtx);
			lck_mtx_destroy(&inp->inpcb_mtx, SCTP_BASE_INFO(sctbinfo).ipi_lock_grp);
			SCTP_ZONE_FREE(SCTP_BASE_INFO(ipi_zone_ep), inp);
			sodealloc(so);
			SCTP_DECR_EP_COUNT();
		}
	}
	lck_rw_done(ipi->ipi_lock);

	return;
}
#endif

socket_t sctp_address_monitor_so = NULL;

#define ROUNDUP(a, size) (((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))
#define NEXT_SA(sa) sa = (struct sockaddr *) \
	((caddr_t) sa + (sa->sa_len ? ROUNDUP(sa->sa_len, sizeof(uint32_t)) : sizeof(uint32_t)))

static void
sctp_get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int i;

	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa;
			NEXT_SA(sa);
		} else {
			rti_info[i] = NULL;
		}
	}
}

static void
sctp_handle_ifamsg(struct ifa_msghdr *ifa_msg) {
	struct ifnet **ifnetlist;
	struct ifaddr **ifaddrlist;
	uint32_t i, j, count;
	struct sockaddr *sa;
	struct sockaddr *rti_info[RTAX_MAX];
	struct ifnet *found_ifn = NULL;
	struct ifaddr *ifa, *found_ifa = NULL;

	/* handle only the types we want */
	if ((ifa_msg->ifam_type != RTM_NEWADDR) &&
	    (ifa_msg->ifam_type != RTM_DELADDR)) {
		return;
	}

	/* parse the list of addreses reported */
	sa = (struct sockaddr *)(ifa_msg + 1);
	sctp_get_rtaddrs(ifa_msg->ifam_addrs, sa, rti_info);

	/* we only want the interface address */
	sa = rti_info[RTAX_IFA];
	/*
	 * find the actual kernel ifa/ifn for this address.
	 * we need this primarily for the v6 case to get the ifa_flags.
	 */
	if (ifnet_list_get(IFNET_FAMILY_ANY, &ifnetlist, &count) != 0) {
		return;
	}
	for (i = 0; i < count; i++) {
		/* find the interface by index */
		if (ifa_msg->ifam_index == ifnet_index(ifnetlist[i])) {
			found_ifn = ifnetlist[i];
			break;
		}
	}
	if (found_ifn == NULL) {
		ifnet_list_free(ifnetlist);
		return;
	}
	/* verify the address on the interface */
	if (ifnet_get_address_list(found_ifn, &ifaddrlist) != 0) {
		ifnet_list_free(ifnetlist);
		return;
	}
	for (j = 0; ifaddrlist[j] != NULL; j++) {
		ifa = ifaddrlist[j];
		if (found_ifa) {
			break;
		}
		if (ifa->ifa_addr == NULL) {
			continue;
		}
		switch (ifa->ifa_addr->sa_family) {
#ifdef INET
		case AF_INET:
			if (((struct sockaddr_in *)sa)->sin_addr.s_addr == ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr) {
				found_ifa = ifa;
			}
			break;
#endif
#ifdef INET6
		case AF_INET6:
			if (SCTP6_ARE_ADDR_EQUAL((struct sockaddr_in6 *)sa,  (struct sockaddr_in6 *)ifa->ifa_addr)) {
				found_ifa = ifa;
			}
			break;
#endif
		default:
			break;
		}
	}
	if (found_ifa == NULL) {
		ifnet_free_address_list(ifaddrlist);
		ifnet_list_free(ifnetlist);
		return;
	}
	/* relay the appropriate address change to the base code */
	if (ifa_msg->ifam_type == RTM_NEWADDR) {
		SCTP_PRINTF("SCTP-NKE: Adding ");
		sctp_print_addr(sa);
		SCTP_PRINTF(" to interface %s%d (index %d).\n", ifnet_name(found_ifn), ifnet_unit(found_ifn), ifnet_index(found_ifn));
		sctp_addr_change(found_ifa, RTM_ADD);
	} else {
		SCTP_PRINTF("SCTP-NKE: Deleting ");
		sctp_print_addr(sa);
		SCTP_PRINTF(" from interface %s%d (index %d).\n", ifnet_name(found_ifn), ifnet_unit(found_ifn), ifnet_index(found_ifn));
		sctp_addr_change(found_ifa, RTM_DELETE);
	}
	ifnet_free_address_list(ifaddrlist);
	ifnet_list_free(ifnetlist);
}


static void
sctp_address_monitor_cb(socket_t rt_sock, void *cookie SCTP_UNUSED, int watif SCTP_UNUSED)
{
	struct msghdr msg;
	struct iovec iov;
	size_t length;
	errno_t error;
	struct rt_msghdr *rt_msg;
	char rt_buffer[1024];

	/* setup the receive iovec and msghdr */
	iov.iov_base = rt_buffer;
	iov.iov_len = sizeof(rt_buffer);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	length = 0;
	/* read the routing socket */
	error = sock_receive(rt_sock, &msg, 0, &length);
	if (error) {
		SCTP_PRINTF("Routing socket read error: length %d, errno %d\n", (int)length, error);
		return;
	}
	if (length == 0) {
		return;
	}
	/* process the routing event */
	rt_msg = (struct rt_msghdr *)rt_buffer;
	if (length != rt_msg->rtm_msglen) {
		SCTP_PRINTF("Read %d bytes from routing socket for message of length %d.\n", (int) length, rt_msg->rtm_msglen);
		return;
	}
	switch (rt_msg->rtm_type) {
	case RTM_DELADDR:
	case RTM_NEWADDR:
		sctp_handle_ifamsg((struct ifa_msghdr *)rt_buffer);
		break;
	default:
		/* ignore this routing event */
		break;
	}
	return;
}

errno_t
sctp_address_monitor_start(void)
{
	errno_t error;

	if (sctp_address_monitor_so) {
		sock_close(sctp_address_monitor_so);
		sctp_address_monitor_so = NULL;
	}

	error = sock_socket(PF_ROUTE, SOCK_RAW, 0, sctp_address_monitor_cb, NULL, &sctp_address_monitor_so);
	if (error) {
		SCTP_PRINTF("Failed to create routing socket\n");
	}
	return (error);
}

void
sctp_address_monitor_stop(void)
{
	if (sctp_address_monitor_so) {
		sock_close(sctp_address_monitor_so);
		sctp_address_monitor_so = NULL;
	}
	return;
}

#if 0
static void
sctp_print_mbuf_chain(mbuf_t m)
{
	for (; m; m = SCTP_BUF_NEXT(m)) {
		SCTP_PRINTF("%p: m_len = %ld, m_type = %x\n", m, SCTP_BUF_LEN(m), m->m_type);
		if (SCTP_BUF_IS_EXTENDED(m))
			SCTP_PRINTF("%p: extend_size = %d\n", m, SCTP_BUF_EXTEND_SIZE(m));
	}
}
#endif

static void
sctp_over_udp_ipv4_cb(socket_t udp_sock, void *cookie SCTP_UNUSED, int watif SCTP_UNUSED)
{
	errno_t error;
	size_t length;
	int offset;
	mbuf_t m;
	struct msghdr msg;
	struct sockaddr_in src, dst;
	char cmsgbuf[CMSG_SPACE(sizeof (struct in_addr))];
	struct cmsghdr *cmsg;
	struct sctphdr *sh;
	struct sctp_chunkhdr *ch;
	uint16_t port;

	memset(&msg, 0, sizeof(struct msghdr));
	memset(&src, 0, sizeof(struct sockaddr_in));
	memset(&dst, 0, sizeof(struct sockaddr_in));
	memset(cmsgbuf, 0, CMSG_SPACE(sizeof (struct in_addr)));

	msg.msg_name = (void *)&src;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_iov = NULL;
	msg.msg_iovlen = 0;
	msg.msg_control = (void *)cmsgbuf;
	msg.msg_controllen = (socklen_t)CMSG_LEN(sizeof (struct in_addr));
	msg.msg_flags = 0;

	length = (1<<16);
	error = sock_receivembuf(udp_sock, &msg, &m, 0, &length);
	if (error) {
		SCTP_PRINTF("sock_receivembuf returned error %d.\n", error);
		return;
	}
	if (length == 0) {
		return;
	}
	if ((m->m_flags & M_PKTHDR) != M_PKTHDR) {
		mbuf_freem(m);
		return;
	}
#ifdef SCTP_MBUF_LOGGING
	/* Log in any input mbufs */
	if (SCTP_BASE_SYSCTL(sctp_logging_level) & SCTP_MBUF_LOGGING_ENABLE) {
		sctp_log_mbc(m, SCTP_MBUF_INPUT);
	}
#endif
#ifdef SCTP_PACKET_LOGGING
	if (SCTP_BASE_SYSCTL(sctp_logging_level) & SCTP_LAST_PACKET_TRACING) {
		sctp_packet_log(m);
	}
#endif
	SCTP_STAT_INCR(sctps_recvpackets);
	SCTP_STAT_INCR_COUNTER64(sctps_inpackets);
	/* Get SCTP, and first chunk header together in the first mbuf. */
	offset = sizeof(struct sctphdr) + sizeof(struct sctp_chunkhdr);
	if (SCTP_BUF_LEN(m) < offset) {
		if ((m = m_pullup(m, offset)) == NULL) {
			SCTP_STAT_INCR(sctps_hdrops);
			return;
		}
	}
	sh = mtod(m, struct sctphdr *);
	ch = (struct sctp_chunkhdr *)((caddr_t)sh + sizeof(struct sctphdr));
	offset -= sizeof(struct sctp_chunkhdr);
	port = src.sin_port;
	src.sin_port = sh->src_port;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if ((cmsg->cmsg_level == IPPROTO_IP) && (cmsg->cmsg_type == IP_RECVDSTADDR)) {
			dst.sin_family = AF_INET;
			dst.sin_len = sizeof(struct sockaddr_in);
			dst.sin_port = sh->dest_port;
			memcpy((void *)&dst.sin_addr, (const void *)CMSG_DATA(cmsg), sizeof(struct in_addr));
		}
	}
	/* Validate mbuf chain length with IP payload length. */
	if (SCTP_HEADER_LEN(m) != (int)length) {
		SCTPDBG(SCTP_DEBUG_INPUT1,
		        "sctp_over_udp_ipv4_cb(): length:%d reported length:%d\n", (int)length, SCTP_HEADER_LEN(m));
		SCTP_STAT_INCR(sctps_hdrops);
		goto out;
	}
	/* SCTP does not allow broadcasts or multicasts */
	if (IN_MULTICAST(ntohl(dst.sin_addr.s_addr))) {
		goto out;
	}
	if (SCTP_IS_IT_BROADCAST(dst.sin_addr, m)) {
		goto out;
	}
	SCTP_STAT_INCR(sctps_recvswcrc);
	sctp_common_input_processing(&m, 0, offset, (int)length,
	                             (struct sockaddr *)&src,
	                             (struct sockaddr *)&dst,
	                             sh, ch,
	                             1,
	                             0,
	                             SCTP_DEFAULT_VRFID, port);
 out:
	if (m) {
		mbuf_freem(m);
	}
	return;
}

static void
sctp_over_udp_ipv6_cb(socket_t udp_sock, void *cookie SCTP_UNUSED, int watif SCTP_UNUSED)
{
	errno_t error;
	size_t length;
	int offset;
	mbuf_t m;
	struct msghdr msg;
	struct sockaddr_in6 src, dst;
	char cmsgbuf[CMSG_SPACE(sizeof (struct in6_pktinfo))];
	struct cmsghdr *cmsg;
	struct sctphdr *sh;
	struct sctp_chunkhdr *ch;
	uint16_t port;

	memset(&msg, 0, sizeof(struct msghdr));
	memset(&src, 0, sizeof(struct sockaddr_in6));
	memset(&dst, 0, sizeof(struct sockaddr_in6));
	memset(cmsgbuf, 0, CMSG_SPACE(sizeof (struct in6_pktinfo)));

	msg.msg_name = (void *)&src;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_iov = NULL;
	msg.msg_iovlen = 0;
	msg.msg_control = (void *)cmsgbuf;
	msg.msg_controllen = (socklen_t)CMSG_LEN(sizeof (struct in6_pktinfo));
	msg.msg_flags = 0;

	length = (1<<16);
	error = sock_receivembuf(udp_sock, &msg, &m, 0, &length);
	if (error) {
		SCTP_PRINTF("sock_receivembuf returned error %d.\n", error);
		return;
	}
	if (length == 0) {
		return;
	}
	if ((m->m_flags & M_PKTHDR) != M_PKTHDR) {
		mbuf_freem(m);
		return;
	}
#ifdef SCTP_MBUF_LOGGING
	/* Log in any input mbufs */
	if (SCTP_BASE_SYSCTL(sctp_logging_level) & SCTP_MBUF_LOGGING_ENABLE) {
		sctp_log_mbc(m, SCTP_MBUF_INPUT);
	}
#endif
#ifdef SCTP_PACKET_LOGGING
	if (SCTP_BASE_SYSCTL(sctp_logging_level) & SCTP_LAST_PACKET_TRACING) {
		sctp_packet_log(m);
	}
#endif
	SCTP_STAT_INCR(sctps_recvpackets);
	SCTP_STAT_INCR_COUNTER64(sctps_inpackets);
	/* Get SCTP, and first chunk header together in the first mbuf. */
	offset = sizeof(struct sctphdr) + sizeof(struct sctp_chunkhdr);
	if (SCTP_BUF_LEN(m) < offset) {
		if ((m = m_pullup(m, offset)) == NULL) {
			SCTP_STAT_INCR(sctps_hdrops);
			return;
		}
	}
	sh = mtod(m, struct sctphdr *);;
	ch = (struct sctp_chunkhdr *)((caddr_t)sh + sizeof(struct sctphdr));
	offset -= sizeof(struct sctp_chunkhdr);
	port = src.sin6_port;
	src.sin6_port = sh->src_port;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == IPV6_PKTINFO)) {
			dst.sin6_family = AF_INET6;
			dst.sin6_len = sizeof(struct sockaddr_in6);
			dst.sin6_port = sh->dest_port;
			memcpy((void *)&dst.sin6_addr, (const void *)(&((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr), sizeof(struct in6_addr));
#if 0
			if (in6_setscope(&dst.sin6_addr, m->m_pkthdr.rcvif, NULL) != 0) {
				goto out;
			}
#endif
#if defined(NFAITH) && 0 < NFAITH
			if (faithprefix(&dst.sin6_addr)) {
				goto out;
			}
#endif
		}
	}
	/* Validate mbuf chain length with IP payload length. */
	if (SCTP_HEADER_LEN(m) != (int)length) {
		SCTPDBG(SCTP_DEBUG_INPUT1,
		        "sctp_over_udp_ipv6_cb(): length:%d reported length:%d\n", (int)length, SCTP_HEADER_LEN(m));
		SCTP_STAT_INCR(sctps_hdrops);
		goto out;
	}
	/* SCTP does not allow multicasts */
	if (IN6_IS_ADDR_MULTICAST(&dst.sin6_addr)) {
		goto out;
	}
	SCTP_STAT_INCR(sctps_recvswcrc);
	sctp_common_input_processing(&m, 0, offset, (int)length,
	                             (struct sockaddr *)&src,
	                             (struct sockaddr *)&dst,
	                             sh, ch,
	                             1,
	                             0,
	                             SCTP_DEFAULT_VRFID, port);
 out:
	if (m) {
		mbuf_freem(m);
	}
	return;
}

socket_t sctp_over_udp_ipv4_so = NULL;
socket_t sctp_over_udp_ipv6_so = NULL;

errno_t
sctp_over_udp_start(void)
{
	errno_t error;
	struct sockaddr_in addr_ipv4;
	struct sockaddr_in6 addr_ipv6;
	const int on = 1;

	if (sctp_over_udp_ipv4_so) {
		sock_close(sctp_over_udp_ipv4_so);
		sctp_over_udp_ipv4_so = NULL;
	}

	if (sctp_over_udp_ipv6_so) {
		sock_close(sctp_over_udp_ipv6_so);
		sctp_over_udp_ipv6_so = NULL;
	}

	if (SCTP_BASE_SYSCTL(sctp_udp_tunneling_port) == 0) {
		return (0);
	}

	error = sock_socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP, sctp_over_udp_ipv4_cb, NULL, &sctp_over_udp_ipv4_so);
	if (error) {
		sctp_over_udp_ipv4_so = NULL;
		SCTP_PRINTF("Failed to create SCTP/UDP/IPv4 tunneling socket: errno = %d.\n", error);
		return (error);
	}

	error = sock_setsockopt(sctp_over_udp_ipv4_so, IPPROTO_IP, IP_RECVDSTADDR, (const void *)&on, (int)sizeof(int));
	if (error) {
		sock_close(sctp_over_udp_ipv4_so);
		sctp_over_udp_ipv4_so = NULL;
		SCTP_PRINTF("Failed to setsockopt() on SCTP/UDP/IPv4 tunneling socket: errno = %d.\n", error);
		return (error);
	}

	memset((void *)&addr_ipv4, 0, sizeof(struct sockaddr_in));
	addr_ipv4.sin_len         = sizeof(struct sockaddr_in);
	addr_ipv4.sin_family      = AF_INET;
	addr_ipv4.sin_port        = htons(SCTP_BASE_SYSCTL(sctp_udp_tunneling_port));
	addr_ipv4.sin_addr.s_addr = htonl(INADDR_ANY);
	error = sock_bind(sctp_over_udp_ipv4_so, (const struct sockaddr *)&addr_ipv4);
	if (error) {
		sock_close(sctp_over_udp_ipv4_so);
		sctp_over_udp_ipv4_so = NULL;
		SCTP_PRINTF("Failed to bind SCTP/UDP/IPv4 tunneling socket: errno = %d.\n", error);
		return (error);
	}

	error = sock_socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP, sctp_over_udp_ipv6_cb, NULL, &sctp_over_udp_ipv6_so);
	if (error) {
		sock_close(sctp_over_udp_ipv4_so);
		sctp_over_udp_ipv4_so = NULL;
		sctp_over_udp_ipv6_so = NULL;
		SCTP_PRINTF("Failed to create SCTP/UDP/IPv6 tunneling socket: errno = %d.\n", error);
		return (error);
	}

	error = sock_setsockopt(sctp_over_udp_ipv6_so, IPPROTO_IPV6, IPV6_V6ONLY, (const void *)&on, (int)sizeof(int));
	if (error) {
		sock_close(sctp_over_udp_ipv4_so);
		sctp_over_udp_ipv4_so = NULL;
		sock_close(sctp_over_udp_ipv6_so);
		sctp_over_udp_ipv6_so = NULL;
		SCTP_PRINTF("Failed to setsockopt() on SCTP/UDP/IPv6 tunneling socket: errno = %d.\n", error);
		return (error);
	}

#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD)
	error = sock_setsockopt(sctp_over_udp_ipv6_so, IPPROTO_IPV6, IPV6_PKTINFO, (const void *)&on, (int)sizeof(int));
#else
	error = sock_setsockopt(sctp_over_udp_ipv6_so, IPPROTO_IPV6, IPV6_RECVPKTINFO, (const void *)&on, (int)sizeof(int));
#endif
	if (error) {
		sock_close(sctp_over_udp_ipv4_so);
		sctp_over_udp_ipv4_so = NULL;
		sock_close(sctp_over_udp_ipv6_so);
		sctp_over_udp_ipv6_so = NULL;
		SCTP_PRINTF("Failed to setsockopt() on SCTP/UDP/IPv6 tunneling socket: errno = %d.\n", error);
		return (error);
	}

	memset((void *)&addr_ipv6, 0, sizeof(struct sockaddr_in6));
	addr_ipv6.sin6_len    = sizeof(struct sockaddr_in6);
	addr_ipv6.sin6_family = AF_INET6;
	addr_ipv6.sin6_port   = htons(SCTP_BASE_SYSCTL(sctp_udp_tunneling_port));
	addr_ipv6.sin6_addr   = in6addr_any;
	error = sock_bind(sctp_over_udp_ipv6_so, (const struct sockaddr *)&addr_ipv6);
	if (error) {
		sock_close(sctp_over_udp_ipv4_so);
		sctp_over_udp_ipv4_so = NULL;
		sock_close(sctp_over_udp_ipv6_so);
		sctp_over_udp_ipv6_so = NULL;
		SCTP_PRINTF("Failed to bind SCTP/UDP/IPv6 tunneling socket: errno = %d.\n", error);
		return (error);
	}

	return (0);
}

void
sctp_over_udp_stop(void)
{
	if (sctp_over_udp_ipv4_so) {
		sock_close(sctp_over_udp_ipv4_so);
		sctp_over_udp_ipv4_so = NULL;
	}
	if (sctp_over_udp_ipv6_so) {
		sock_close(sctp_over_udp_ipv6_so);
		sctp_over_udp_ipv6_so = NULL;
	}
	return;
}

void
sctp_delayed_startup(void *arg SCTP_UNUSED)
{
	sctp_over_udp_start();
	sctp_address_monitor_start();
}
