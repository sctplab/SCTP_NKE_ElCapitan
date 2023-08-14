/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2001-2007, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2012, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2012, by Michael Tuexen. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _NETINET_SCTP_LOCK_APPLE_FG_H_
#define _NETINET_SCTP_LOCK_APPLE_FG_H_

#define SCTP_STATLOG_INIT_LOCK()
#define SCTP_STATLOG_LOCK()
#define SCTP_STATLOG_UNLOCK()
#define SCTP_STATLOG_DESTROY()

/* for now, all locks use this group and attributes */
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
#define SCTP_MTX_GRP SCTP_BASE_INFO(sctbinfo).mtx_grp
#define SCTP_MTX_ATTR SCTP_BASE_INFO(sctbinfo).mtx_attr
#else
#define SCTP_MTX_GRP SCTP_BASE_INFO(sctbinfo).ipi_lock_grp
#define SCTP_MTX_ATTR SCTP_BASE_INFO(sctbinfo).ipi_lock_attr
#endif

#define SCTP_WQ_ADDR_INIT() \
	SCTP_BASE_INFO(wq_addr_mtx) = lck_mtx_alloc_init(SCTP_MTX_GRP, SCTP_MTX_ATTR)
#define SCTP_WQ_ADDR_DESTROY()  \
        lck_mtx_free(SCTP_BASE_INFO(wq_addr_mtx), SCTP_MTX_GRP)
#define SCTP_WQ_ADDR_LOCK()	lck_mtx_lock(SCTP_BASE_INFO(wq_addr_mtx))
#define SCTP_WQ_ADDR_UNLOCK() lck_mtx_unlock(SCTP_BASE_INFO(wq_addr_mtx))
#define SCTP_WQ_ADDR_LOCK_ASSERT() \
	lck_mtx_assert(SCTP_BASE_INFO(wq_addr_mtx), LCK_MTX_ASSERT_OWNED)

/* Lock for INFO stuff */
#if defined(APPLE_LEOPARD) || defined(APPLE_SNOWLEOPARD) || defined(APPLE_LION) || defined(APPLE_MOUNTAINLION)
#define SCTP_INP_INFO_LOCK_INIT() \
	SCTP_BASE_INFO(sctbinfo.mtx) = lck_rw_alloc_init(SCTP_MTX_GRP, SCTP_MTX_ATTR)
#define SCTP_INP_INFO_RLOCK() \
	lck_rw_lock_exclusive(SCTP_BASE_INFO(sctbinfo).mtx)
#define SCTP_INP_INFO_RUNLOCK() \
	lck_rw_unlock_exclusive(SCTP_BASE_INFO(sctbinfo).mtx)
#define SCTP_INP_INFO_WLOCK() \
	lck_rw_lock_exclusive(SCTP_BASE_INFO(sctbinfo).mtx)
#define SCTP_INP_INFO_WUNLOCK() \
	lck_rw_unlock_exclusive(SCTP_BASE_INFO(sctbinfo).mtx)
#define SCTP_INP_INFO_LOCK_ASSERT()
	lck_mtx_assert(SCTP_BASE_INFO(sctbinfo).mtx, LCK_RW_ASSERT_HELD)
#define SCTP_INP_INFO_RLOCK_ASSERT()
	lck_mtx_assert(SCTP_BASE_INFO(sctbinfo).mtx, LCK_RW_ASSERT_SHARED)
#define SCTP_INP_INFO_WLOCK_ASSERT()
	lck_mtx_assert(SCTP_BASE_INFO(sctbinfo).mtx, LCK_RW_ASSERT_EXCLUSIVE)
#define SCTP_INP_INFO_LOCK_DESTROY() \
        lck_rw_free(SCTP_BASE_INFO(sctbinfo).mtx, SCTP_MTX_GRP)
#else
#define SCTP_INP_INFO_LOCK_INIT() \
	SCTP_BASE_INFO(sctbinfo.ipi_lock) = lck_rw_alloc_init(SCTP_MTX_GRP, SCTP_MTX_ATTR)
#define SCTP_INP_INFO_RLOCK() \
	lck_rw_lock_exclusive(SCTP_BASE_INFO(sctbinfo).ipi_lock)
#define SCTP_INP_INFO_RUNLOCK() \
	lck_rw_unlock_exclusive(SCTP_BASE_INFO(sctbinfo).ipi_lock)
#define SCTP_INP_INFO_WLOCK() \
	lck_rw_lock_exclusive(SCTP_BASE_INFO(sctbinfo).ipi_lock)
#define SCTP_INP_INFO_WUNLOCK() \
	lck_rw_unlock_exclusive(SCTP_BASE_INFO(sctbinfo).ipi_lock)
#define SCTP_INP_INFO_LOCK_ASSERT() \
	lck_mtx_assert(SCTP_BASE_INFO(sctbinfo).ipi_lock, LCK_RW_ASSERT_HELD)
#define SCTP_INP_INFO_RLOCK_ASSERT() \
	lck_mtx_assert(SCTP_BASE_INFO(sctbinfo).ipi_lock, LCK_RW_ASSERT_SHARED)
#define SCTP_INP_INFO_WLOCK_ASSERT() \
	lck_mtx_assert(SCTP_BASE_INFO(sctbinfo).ipi_lock, LCK_RW_ASSERT_EXCLUSIVE)
#define SCTP_INP_INFO_LOCK_DESTROY() \
        lck_rw_free(SCTP_BASE_INFO(sctbinfo).ipi_lock, SCTP_MTX_GRP)
#endif
#define SCTP_IPI_COUNT_INIT() \
	SCTP_BASE_INFO(ipi_count_mtx) = lck_mtx_alloc_init(SCTP_MTX_GRP, SCTP_MTX_ATTR)
#define SCTP_IPI_COUNT_DESTROY() \
        lck_mtx_free(SCTP_BASE_INFO(ipi_count_mtx), SCTP_MTX_GRP)

#define SCTP_IPI_ADDR_INIT() \
	SCTP_BASE_INFO(ipi_addr_mtx) = lck_mtx_alloc_init(SCTP_MTX_GRP, SCTP_MTX_ATTR)
#define SCTP_IPI_ADDR_DESTROY() \
	lck_mtx_free(SCTP_BASE_INFO(ipi_addr_mtx), SCTP_MTX_GRP)
#define SCTP_IPI_ADDR_RLOCK() \
	lck_mtx_lock(SCTP_BASE_INFO(ipi_addr_mtx))
#define SCTP_IPI_ADDR_RUNLOCK() \
	lck_mtx_unlock(SCTP_BASE_INFO(ipi_addr_mtx))
#define SCTP_IPI_ADDR_WLOCK() \
	lck_mtx_lock(SCTP_BASE_INFO(ipi_addr_mtx))
#define SCTP_IPI_ADDR_WUNLOCK() \
	lck_mtx_unlock(SCTP_BASE_INFO(ipi_addr_mtx))
#define SCTP_IPI_ADDR_LOCK_ASSERT() \
	lck_mtx_assert(SCTP_BASE_INFO(ipi_addr_mtx), LCK_MTX_ASSERT_OWNED)
#define SCTP_IPI_ADDR_WLOCK_ASSERT() \
        lck_mtx_assert(SCTP_BASE_INFO(ipi_addr_mtx), LCK_MTX_ASSERT_OWNED)


/* Lock for INP */
#if defined(SCTP_INP_RWLOCK)  /* shared locking */
#define SCTP_INP_LOCK_INIT(_inp) \
	(_inp)->inp_mtx = lck_rw_alloc_init(SCTP_MTX_GRP, SCTP_MTX_ATTR)
#define SCTP_INP_LOCK_DESTROY(_inp) \
	lck_rw_free((_inp)->inp_mtx, SCTP_MTX_GRP)
#define SCTP_INP_RLOCK(_inp) \
	lck_rw_lock_exclusive((_inp)->inp_mtx)
#define SCTP_INP_RUNLOCK(_inp) \
	lck_rw_unlock_exclusive((_inp)->inp_mtx)
#define SCTP_INP_WLOCK(_inp) \
	lck_rw_lock_exclusive((_inp)->inp_mtx)
#define SCTP_INP_WUNLOCK(_inp) \
	lck_rw_unlock_exclusive((_inp)->inp_mtx)
#define SCTP_INP_RLOCK_ASSERT(_inp) \
	lck_mtx_assert((_inp)->inp_mtx, LCK_RW_ASSERT_SHARED)
#define SCTP_INP_WLOCK_ASSERT(_inp) \
	lck_mtx_assert((_inp)->inp_mtx, LCK_RW_ASSERT_EXCLUSIVE)
#else
#define SCTP_INP_LOCK_INIT(_inp) \
	(_inp)->inp_mtx = lck_mtx_alloc_init(SCTP_MTX_GRP, SCTP_MTX_ATTR)
#define SCTP_INP_LOCK_DESTROY(_inp) \
	lck_mtx_free((_inp)->inp_mtx, SCTP_MTX_GRP)
#define SCTP_INP_RLOCK(_inp) \
	lck_mtx_lock((_inp)->inp_mtx)
#define SCTP_INP_RUNLOCK(_inp) \
	lck_mtx_unlock((_inp)->inp_mtx)
#define SCTP_INP_WLOCK(_inp) \
	lck_mtx_lock((_inp)->inp_mtx)
#define SCTP_INP_WUNLOCK(_inp) \
	lck_mtx_unlock((_inp)->inp_mtx)
#define SCTP_INP_RLOCK_ASSERT(_inp) \
	lck_mtx_assert((_inp)->inp_mtx, LCK_MTX_ASSERT_OWNED)
#define SCTP_INP_WLOCK_ASSERT(_inp) \
	lck_mtx_assert((_inp)->inp_mtx, LCK_MTX_ASSERT_OWNED)
#endif
#define SCTP_INP_INCR_REF(_inp) atomic_add_int(&((_inp)->refcount), 1)
#define SCTP_INP_DECR_REF(_inp) atomic_add_int(&((_inp)->refcount), -1)

#define SCTP_ASOC_CREATE_LOCK_INIT(_inp) \
	(_inp)->inp_create_mtx = lck_mtx_alloc_init(SCTP_MTX_GRP, SCTP_MTX_ATTR)
#define SCTP_ASOC_CREATE_LOCK_DESTROY(_inp) \
	lck_mtx_free((_inp)->inp_create_mtx, SCTP_MTX_GRP)
#define SCTP_ASOC_CREATE_LOCK(_inp) \
	lck_mtx_lock((_inp)->inp_create_mtx)
#define SCTP_ASOC_CREATE_UNLOCK(_inp) \
	lck_mtx_unlock((_inp)->inp_create_mtx)


#define SCTP_INP_LOCK_CONTENDED(_inp) (0) /* Don't know if this is possible */

#define SCTP_INP_READ_CONTENDED(_inp) (0) /* Don't know if this is possible */

#define SCTP_ASOC_CREATE_LOCK_CONTENDED(_inp) (0) /* Don't know if this is possible */


#define SCTP_INP_READ_LOCK_INIT(_inp) \
	(_inp)->inp_rdata_mtx = lck_mtx_alloc_init(SCTP_MTX_GRP, SCTP_MTX_ATTR)
#define SCTP_INP_READ_LOCK_DESTROY(_inp) \
	lck_mtx_free((_inp)->inp_rdata_mtx, SCTP_MTX_GRP)
#define SCTP_INP_READ_LOCK(_inp) \
	lck_mtx_lock((_inp)->inp_rdata_mtx)
#define SCTP_INP_READ_UNLOCK(_inp) \
	lck_mtx_unlock((_inp)->inp_rdata_mtx)
#define SCTP_INP_READ_LOCK_ASSERT(_inp) \
	lck_mtx_assert((_inp)->inp_rdata_mtx, LCK_MTX_ASSERT_OWNED)

/* Lock for TCB */
#define SCTP_TCB_LOCK_INIT(_tcb) \
	(_tcb)->tcb_mtx = lck_mtx_alloc_init(SCTP_MTX_GRP, SCTP_MTX_ATTR)
#define SCTP_TCB_LOCK_DESTROY(_tcb) \
	lck_mtx_free((_tcb)->tcb_mtx, SCTP_MTX_GRP)
#define SCTP_TCB_LOCK(_tcb) \
do { \
	lck_mtx_lock((_tcb)->tcb_mtx); \
	SAVE_CALLERS_NOSKIP((_tcb)->caller1, (_tcb)->caller2, (_tcb)->caller3); \
} while (0)
#define SCTP_TCB_TRYLOCK(_tcb) \
	lck_mtx_try_lock((_tcb)->tcb_mtx)
#define SCTP_TCB_UNLOCK(_tcb) \
do { \
	SAVE_CALLERS_NOSKIP((_tcb)->caller1, (_tcb)->caller2, (_tcb)->caller3); \
	lck_mtx_unlock((_tcb)->tcb_mtx); \
} while (0)
#define SCTP_TCB_LOCK_ASSERT(_tcb) \
	lck_mtx_assert((_tcb)->tcb_mtx, LCK_MTX_ASSERT_OWNED)

/* iterator locks */
#define SCTP_ITERATOR_LOCK_INIT() \
	sctp_it_ctl.it_mtx = lck_mtx_alloc_init(SCTP_MTX_GRP, SCTP_MTX_ATTR)
#define SCTP_ITERATOR_LOCK() \
	lck_mtx_lock(sctp_it_ctl.it_mtx)
#define SCTP_ITERATOR_UNLOCK() \
	lck_mtx_unlock(sctp_it_ctl.it_mtx)
#define SCTP_ITERATOR_LOCK_DESTROY() \
	lck_mtx_free(sctp_it_ctl.it_mtx, SCTP_MTX_GRP)

#define SCTP_IPI_ITERATOR_WQ_INIT() \
	sctp_it_ctl.ipi_iterator_wq_mtx = lck_mtx_alloc_init(SCTP_MTX_GRP, SCTP_MTX_ATTR)
#define SCTP_IPI_ITERATOR_WQ_DESTROY() \
	lck_mtx_free(sctp_it_ctl.ipi_iterator_wq_mtx, SCTP_MTX_GRP)
#define SCTP_IPI_ITERATOR_WQ_LOCK() \
	lck_mtx_lock(sctp_it_ctl.ipi_iterator_wq_mtx)
#define SCTP_IPI_ITERATOR_WQ_UNLOCK() \
	lck_mtx_unlock(sctp_it_ctl.ipi_iterator_wq_mtx)


/* socket locks */
#define SOCK_LOCK(_so)
#define SOCK_UNLOCK(_so)
#define SOCKBUF_LOCK(_so_buf)
#define SOCKBUF_UNLOCK(_so_buf)
#define SOCKBUF_LOCK_ASSERT(_so_buf)


/***************BEGIN APPLE Tiger count stuff**********************/
#define I_AM_HERE \
                do { \
			SCTP_PRINTF("%s:%d at %s\n", __FILE__, __LINE__ , __func__); \
		} while (0)

#define SAVE_I_AM_HERE(_inp) \
		do { \
			(_inp)->i_am_here_file = APPLE_FILE_NO; \
			(_inp)->i_am_here_line = __LINE__; \
		} while (0)

/* save caller pc and caller's caller pc */
#if defined(__i386__)
#define SAVE_CALLERS(a, b, c) { \
	unsigned int ebp = 0; \
	unsigned int prev_ebp = 0; \
	asm("movl %%ebp, %0;" : "=r"(ebp)); \
	a = *(unsigned int *)(*(unsigned int *)ebp + 4) - 4; \
	prev_ebp = *(unsigned int *)(*(unsigned int *)ebp); \
	b = *(unsigned int *)((char *)prev_ebp + 4) - 4; \
	prev_ebp = *(unsigned int *)prev_ebp; \
	c = *(unsigned int *)((char *)prev_ebp + 4) - 4; \
}
#define SAVE_CALLERS_NOSKIP(a, b, c) { \
	unsigned int ebp = 0; \
	unsigned int prev_ebp = 0; \
	asm("movl %%ebp, %0;" : "=r"(ebp)); \
	a = *(unsigned int *)(*(unsigned int *)ebp + 4) - 4; \
	prev_ebp = *(unsigned int *)(*(unsigned int *)ebp); \
	b = *(unsigned int *)((char *)prev_ebp + 4) - 4; \
	c = 0; \
}
#else
#define SAVE_CALLERS(caller1, caller2, caller3)
#define SAVE_CALLERS_NOSKIP(caller1, caller2, caller3)
#endif

#define SBLOCKWAIT(f)   (((f) & MSG_DONTWAIT) ? M_NOWAIT : M_WAITOK)

#define SCTP_INCR_EP_COUNT() \
		do { \
			atomic_add_int(&SCTP_BASE_INFO(ipi_count_ep), 1); \
		} while (0)

#define SCTP_DECR_EP_COUNT() \
		do { \
			atomic_add_int(&SCTP_BASE_INFO(ipi_count_ep),-1); \
		} while (0)

#define SCTP_INCR_ASOC_COUNT() \
		do { \
			atomic_add_int(&SCTP_BASE_INFO(ipi_count_asoc), 1); \
		} while (0)

#define SCTP_DECR_ASOC_COUNT() \
		do { \
			atomic_subtract_int(&SCTP_BASE_INFO(ipi_count_asoc), 1); \
		} while (0)

#define SCTP_INCR_LADDR_COUNT() \
		do { \
			atomic_add_int(&SCTP_BASE_INFO(ipi_count_laddr), 1); \
		} while (0)

#define SCTP_DECR_LADDR_COUNT() \
		do { \
			atomic_subtract_int(&SCTP_BASE_INFO(ipi_count_laddr), 1); \
		} while (0)

#define SCTP_INCR_RADDR_COUNT() \
		do { \
			atomic_add_int(&SCTP_BASE_INFO(ipi_count_raddr),1); \
		} while (0)

#define SCTP_DECR_RADDR_COUNT() \
		do { \
			atomic_add_int(&SCTP_BASE_INFO(ipi_count_raddr),-1); \
		} while (0)

#define SCTP_INCR_CHK_COUNT() \
		do { \
			atomic_add_int(&SCTP_BASE_INFO(ipi_count_chunk), 1); \
		} while (0)

#ifdef INVARIANTS

#define SCTP_DECR_CHK_COUNT() \
		do { \
			if (SCTP_BASE_INFO(ipi_count_chunk) == 0) \
				panic("chunk count to 0?"); \
			atomic_add_int(&SCTP_BASE_INFO(ipi_count_chunk),-1); \
		} while (0)
#else

#define SCTP_DECR_CHK_COUNT() \
		do { \
			atomic_add_int(&SCTP_BASE_INFO(ipi_count_chunk),-1); \
		} while (0)
#endif

#define SCTP_INCR_READQ_COUNT() \
		do { \
			atomic_add_int(&SCTP_BASE_INFO(ipi_count_readq),1); \
		} while (0)

#define SCTP_DECR_READQ_COUNT() \
		do { \
			atomic_subtract_int(&SCTP_BASE_INFO(ipi_count_readq), 1); \
		} while (0)

#define SCTP_INCR_STRMOQ_COUNT() \
		do { \
			atomic_add_int(&SCTP_BASE_INFO(ipi_count_strmoq), 1); \
		} while (0)

#define SCTP_DECR_STRMOQ_COUNT() \
		do { \
			atomic_add_int(&SCTP_BASE_INFO(ipi_count_strmoq),-1); \
		} while (0)




#endif
