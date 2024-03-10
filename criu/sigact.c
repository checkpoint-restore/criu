#include "types.h"
#include "infect.h"
#include "protobuf.h"
#include "pstree.h"
#include "parasite.h"
#include "restorer.h"
#include "sigact.h"

/*
 * If parent's sigaction has blocked SIGKILL (which is non-sense),
 * this parent action is non-valid and shouldn't be inherited.
 * Used to mark parent_act* no more valid.
 */
static rt_sigaction_t parent_act[SIGMAX];
#ifdef CONFIG_COMPAT
static rt_sigaction_t_compat parent_act_compat[SIGMAX];
#endif

static bool sa_inherited(int sig, rt_sigaction_t *sa)
{
	rt_sigaction_t *pa;
	int i;

	if (current == root_item)
		return false; /* XXX -- inherit from CRIU? */

	pa = &parent_act[sig];

	/* Omitting non-valid sigaction */
	if (pa->rt_sa_mask.sig[0] & (1 << SIGKILL))
		return false;

	for (i = 0; i < _KNSIG_WORDS; i++)
		if (pa->rt_sa_mask.sig[i] != sa->rt_sa_mask.sig[i])
			return false;

	return pa->rt_sa_handler == sa->rt_sa_handler && pa->rt_sa_flags == sa->rt_sa_flags &&
	       pa->rt_sa_restorer == sa->rt_sa_restorer;
}

static void *stack32;
rt_sigaction_t sigchld_act;

#ifdef CONFIG_COMPAT
static bool sa_compat_inherited(int sig, rt_sigaction_t_compat *sa)
{
	rt_sigaction_t_compat *pa;
	int i;

	if (current == root_item)
		return false;

	pa = &parent_act_compat[sig];

	/* Omitting non-valid sigaction */
	if (pa->rt_sa_mask.sig[0] & (1 << SIGKILL))
		return false;

	for (i = 0; i < _KNSIG_WORDS; i++)
		if (pa->rt_sa_mask.sig[i] != sa->rt_sa_mask.sig[i])
			return false;

	return pa->rt_sa_handler == sa->rt_sa_handler && pa->rt_sa_flags == sa->rt_sa_flags &&
	       pa->rt_sa_restorer == sa->rt_sa_restorer;
}

static int restore_compat_sigaction(int sig, SaEntry *e)
{
	rt_sigaction_t_compat act;
	int ret;

	ASSIGN_TYPED(act.rt_sa_handler, (u32)e->sigaction);
	ASSIGN_TYPED(act.rt_sa_flags, e->flags);
	ASSIGN_TYPED(act.rt_sa_restorer, (u32)e->restorer);
	BUILD_BUG_ON(sizeof(e->mask) != sizeof(act.rt_sa_mask.sig));
	memcpy(act.rt_sa_mask.sig, &e->mask, sizeof(act.rt_sa_mask.sig));

	if (sig == SIGCHLD) {
		memcpy(&sigchld_act, &act, sizeof(rt_sigaction_t_compat));
		return 0;
	}

	if (sa_compat_inherited(sig - 1, &act))
		return 1;

	if (!stack32) {
		stack32 = alloc_compat_syscall_stack();
		if (!stack32)
			return -1;
	}

	ret = arch_compat_rt_sigaction(stack32, sig, &act);
	if (ret < 0) {
		pr_err("Can't restore compat sigaction: %d\n", ret);
		return ret;
	}

	parent_act_compat[sig - 1] = act;
	/* Mark SIGKILL blocked which makes native sigaction non-valid */
	parent_act[sig - 1].rt_sa_mask.sig[0] |= 1 << SIGKILL;

	return 1;
}
#else
static int restore_compat_sigaction(int sig, SaEntry *e)
{
	return -1;
}
#endif

static int restore_native_sigaction(int sig, SaEntry *e)
{
	rt_sigaction_t act;
	int ret;

	ASSIGN_TYPED(act.rt_sa_handler, decode_pointer(e->sigaction));
	ASSIGN_TYPED(act.rt_sa_flags, e->flags);
	ASSIGN_TYPED(act.rt_sa_restorer, decode_pointer(e->restorer));
#ifdef CONFIG_MIPS
	e->has_mask_extended = 1;
	BUILD_BUG_ON(sizeof(e->mask) * 2 != sizeof(act.rt_sa_mask.sig));

	memcpy(&(act.rt_sa_mask.sig[0]), &e->mask, sizeof(act.rt_sa_mask.sig[0]));
	memcpy(&(act.rt_sa_mask.sig[1]), &e->mask_extended, sizeof(act.rt_sa_mask.sig[1]));
#else
	BUILD_BUG_ON(sizeof(e->mask) != sizeof(act.rt_sa_mask.sig));
	memcpy(act.rt_sa_mask.sig, &e->mask, sizeof(act.rt_sa_mask.sig));
#endif
	if (sig == SIGCHLD) {
		sigchld_act = act;
		return 0;
	}

	if (sa_inherited(sig - 1, &act))
		return 1;

	/*
	 * A pure syscall is used, because glibc
	 * sigaction overwrites se_restorer.
	 */
	ret = syscall(SYS_rt_sigaction, sig, &act, NULL, sizeof(k_rtsigset_t));
	if (ret < 0) {
		pr_perror("Can't restore sigaction");
		return ret;
	}

	parent_act[sig - 1] = act;
	/* Mark SIGKILL blocked which makes compat sigaction non-valid */
#ifdef CONFIG_COMPAT
	parent_act_compat[sig - 1].rt_sa_mask.sig[0] |= 1 << SIGKILL;
#endif

	return 1;
}

static int prepare_sigactions_from_core(TaskCoreEntry *tc)
{
	int sig, i;

	if (tc->n_sigactions != SIGMAX - 2) {
		pr_err("Bad number of sigactions in the image (%d, want %d)\n", (int)tc->n_sigactions, SIGMAX - 2);
		return -1;
	}

	pr_info("Restore on-core sigactions for %d\n", vpid(current));

	for (sig = 1, i = 0; sig <= SIGMAX; sig++) {
		int ret;
		SaEntry *e;
		bool sigaction_is_compat;

		if (sig == SIGKILL || sig == SIGSTOP)
			continue;

		e = tc->sigactions[i++];
		sigaction_is_compat = e->has_compat_sigaction && e->compat_sigaction;
		if (sigaction_is_compat)
			ret = restore_compat_sigaction(sig, e);
		else
			ret = restore_native_sigaction(sig, e);

		if (ret < 0)
			return ret;
	}

	return 0;
}

/* Returns number of restored signals, -1 or negative errno on fail */
static int restore_one_sigaction(int sig, struct cr_img *img, int pid)
{
	bool sigaction_is_compat;
	SaEntry *e;
	int ret = 0;

	BUG_ON(sig == SIGKILL || sig == SIGSTOP);

	ret = pb_read_one_eof(img, &e, PB_SIGACT);
	if (ret == 0) {
		if (sig != SIGMAX_OLD + 1) { /* backward compatibility */
			pr_err("Unexpected EOF %d\n", sig);
			return -1;
		}
		pr_warn("This format of sigacts-%d.img is deprecated\n", pid);
		return -1;
	}
	if (ret < 0)
		return ret;

	sigaction_is_compat = e->has_compat_sigaction && e->compat_sigaction;
	if (sigaction_is_compat)
		ret = restore_compat_sigaction(sig, e);
	else
		ret = restore_native_sigaction(sig, e);

	sa_entry__free_unpacked(e, NULL);

	return ret;
}

static int prepare_sigactions_from_image(void)
{
	int pid = vpid(current);
	struct cr_img *img;
	int sig, rst = 0;
	int ret = 0;

	pr_info("Restore sigacts for %d\n", pid);

	img = open_image(CR_FD_SIGACT, O_RSTR, pid);
	if (!img)
		return -1;

	for (sig = 1; sig <= SIGMAX; sig++) {
		if (sig == SIGKILL || sig == SIGSTOP)
			continue;

		ret = restore_one_sigaction(sig, img, pid);
		if (ret < 0)
			break;
		if (ret)
			rst++;
	}

	pr_info("Restored %d/%d sigacts\n", rst, SIGMAX - 3 /* KILL, STOP and CHLD */);

	close_image(img);
	return ret;
}

int prepare_sigactions(CoreEntry *core)
{
	int ret;

	if (!task_alive(current))
		return 0;

	if (core->tc->n_sigactions != 0)
		ret = prepare_sigactions_from_core(core->tc);
	else
		ret = prepare_sigactions_from_image();

	if (stack32) {
		free_compat_syscall_stack(stack32);
		stack32 = NULL;
	}

	return ret;
}

int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct pstree_item *item)
{
	TaskCoreEntry *tc = item->core[0]->tc;
	struct parasite_dump_sa_args *args;
	int ret, sig;
	SaEntry *sa, **psa;

	args = compel_parasite_args(ctl, struct parasite_dump_sa_args);

	ret = compel_rpc_call_sync(PARASITE_CMD_DUMP_SIGACTS, ctl);
	if (ret < 0)
		return ret;

	psa = xmalloc((SIGMAX - 2) * (sizeof(SaEntry *) + sizeof(SaEntry)));
	if (!psa)
		return -1;

	sa = (SaEntry *)(psa + SIGMAX - 2);

	tc->n_sigactions = SIGMAX - 2;
	tc->sigactions = psa;

	for (sig = 1; sig <= SIGMAX; sig++) {
		int i = sig - 1;

		if (sig == SIGSTOP || sig == SIGKILL)
			continue;

		sa_entry__init(sa);
		ASSIGN_TYPED(sa->sigaction, encode_pointer(args->sas[i].rt_sa_handler));
		ASSIGN_TYPED(sa->flags, args->sas[i].rt_sa_flags);
		ASSIGN_TYPED(sa->restorer, encode_pointer(args->sas[i].rt_sa_restorer));
#ifdef CONFIG_MIPS
		sa->has_mask_extended = 1;
		BUILD_BUG_ON(sizeof(sa->mask) * 2 != sizeof(args->sas[0].rt_sa_mask.sig));
		memcpy(&sa->mask, &(args->sas[i].rt_sa_mask.sig[0]), sizeof(sa->mask));
		memcpy(&sa->mask_extended, &(args->sas[i].rt_sa_mask.sig[1]), sizeof(sa->mask));
#else
		BUILD_BUG_ON(sizeof(sa->mask) != sizeof(args->sas[0].rt_sa_mask.sig));
		memcpy(&sa->mask, args->sas[i].rt_sa_mask.sig, sizeof(sa->mask));
#endif
		sa->has_compat_sigaction = true;
		sa->compat_sigaction = !compel_mode_native(ctl);

		*(psa++) = sa++;
	}

	return 0;
}
