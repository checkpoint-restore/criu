#ifndef __CR_SPMC_QUEUE_H__
#define __CR_SPMC_QUEUE_H__

/*
 * Type-safe, lock-free Single-Producer Multi-Consumer (SPMC) queue.
 *
 * Based on the SPSC queue but with atomic CAS on dequeue to support
 * multiple consumers (work stealing).
 *
 * Uses the Michael-Scott dummy-node pattern: the head always points
 * to a "dummy" node whose ->next is the real first entry (or NULL
 * when the queue is empty). On dequeue the old dummy is freed and
 * the consumed node becomes the new dummy.
 *
 * Memory ordering:
 *   Producer publishes via RELEASE store on tail->next.
 *   Consumers use CAS with ACQUIRE/RELEASE on head.
 *   The size counter uses RELAXED - it is approximate.
 */

/**
 * DECLARE_SPMC_NODE(prefix, entry_type) - generate a wrapper node type.
 */
#define DECLARE_SPMC_NODE(prefix, entry_type)		\
struct prefix##_spmc_node {				\
	struct prefix##_spmc_node *next;		\
	entry_type *entry;				\
}

/**
 * spmc_init(head, tail, size, node_type) - allocate dummy node.
 * Returns 0 on success, -1 if allocation fails.
 */
#define spmc_init(head, tail, size, node_type)				\
({									\
	node_type *_dummy = xzalloc(sizeof(*_dummy));			\
	int _rc = -1;							\
	if (_dummy) {							\
		_dummy->next  = NULL;					\
		_dummy->entry = NULL;					\
		(head)  = _dummy;					\
		(tail)  = _dummy;					\
		(size)  = 0;						\
		_rc = 0;						\
	}								\
	_rc;								\
})

/**
 * spmc_enqueue(tail, size, entry_ptr, node_type) - append an entry.
 * Single producer - no synchronization needed on tail.
 * Returns 0 on success, -1 if node allocation fails.
 */
#define spmc_enqueue(tail, size, entry_ptr, node_type)			\
({									\
	node_type *_node = xmalloc(sizeof(*_node));			\
	int _rc = -1;							\
	if (_node) {							\
		_node->entry = (entry_ptr);				\
		_node->next  = NULL;					\
		__atomic_store_n(&(tail)->next, _node,			\
				 __ATOMIC_RELEASE);			\
		(tail) = _node;						\
		__atomic_fetch_add(&(size), 1, __ATOMIC_RELAXED);	\
		_rc = 0;						\
	}								\
	_rc;								\
})

/**
 * spmc_dequeue(head, size) - remove and return the oldest entry.
 * Multi-consumer safe using CAS on head pointer.
 * Evaluates to entry pointer or NULL if empty/contended.
 *
 * NOTE: Does NOT free the old head node to avoid use-after-free when
 * multiple consumers race. Nodes are leaked but cleaned up at drain time.
 */
#define spmc_dequeue(head, size)					\
({									\
	typeof((head)->next)  _head;					\
	typeof(_head)         _next;					\
	typeof((head)->entry) _entry = NULL;				\
	do {								\
		_head = __atomic_load_n(&(head), __ATOMIC_ACQUIRE);	\
		_next = __atomic_load_n(&_head->next, __ATOMIC_ACQUIRE);\
		if (!_next)						\
			break;  /* Queue empty */			\
		/* Try to swing head from _head to _next */		\
		if (__atomic_compare_exchange_n(&(head), &_head, _next,	\
				0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {\
			/* Won the race - extract entry */		\
			_entry = _next->entry;				\
			_next->entry = NULL;				\
			/* Don't free _head - other threads may still reference it */ \
			__atomic_fetch_sub(&(size), 1, __ATOMIC_RELAXED);\
			break;						\
		}							\
		/* Lost race, another consumer took it - retry */	\
	} while (1);							\
	_entry;								\
})

/**
 * spmc_peek(head) - non-consuming emptiness check.
 * Returns true if the queue has at least one entry.
 */
#define spmc_peek(head)							\
	(__atomic_load_n(&__atomic_load_n(&(head), __ATOMIC_ACQUIRE)->next, \
			 __ATOMIC_ACQUIRE) != NULL)

/**
 * spmc_size(size) - read the approximate queue size.
 */
#define spmc_size(size)							\
	__atomic_load_n(&(size), __ATOMIC_RELAXED)

/**
 * spmc_drain(head, free_entry_fn) - free all nodes and their entries.
 * NOT thread-safe - call only when no other threads are accessing.
 */
#define spmc_drain(head, free_entry_fn)					\
do {									\
	typeof(head) _cur = (head);					\
	while (_cur) {							\
		typeof(_cur) _nxt = _cur->next;				\
		if (_cur->entry)					\
			free_entry_fn(_cur->entry);			\
		xfree(_cur);						\
		_cur = _nxt;						\
	}								\
	(head) = NULL;							\
} while (0)

#endif /* __CR_SPMC_QUEUE_H__ */
