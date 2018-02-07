#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "int.h"
#include "common/config.h"
#include "common/compiler.h"
#include "cgroup-props.h"
#include "cr_options.h"
#include "xmalloc.h"
#include "string.h"
#include "util.h"
#include "common/list.h"
#include "log.h"
#include "common/bug.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "cg-prop: "

enum {
	CGP_MERGE,
	CGP_REPLACE,
};

static const char *____criu_global_props____[] = {
	"cgroup.clone_children",
	"notify_on_release",
	"cgroup.procs",
	"tasks",
};

cgp_t cgp_global = {
	.name		= "____criu_global_props____",
	.nr_props	= ARRAY_SIZE(____criu_global_props____),
	.props		= ____criu_global_props____,
};

typedef struct {
	struct list_head	list;
	cgp_t			cgp;
} cgp_list_entry_t;

static LIST_HEAD(cgp_list);

static void cgp_free(cgp_list_entry_t *p)
{
	size_t i;

	if (p) {
		for (i = 0; i < p->cgp.nr_props; i++)
			xfree((void *)p->cgp.props[i]);
		xfree((void *)p->cgp.name);
		xfree((void *)p->cgp.props);
		xfree(p);
	}
}

static int cgp_merge_props(cgp_list_entry_t *d, cgp_list_entry_t *s)
{
	size_t nr_props, i, j;

	nr_props = d->cgp.nr_props + s->cgp.nr_props;
	if (xrealloc_safe(&d->cgp.props, nr_props * sizeof(char *)))
		return -ENOMEM;

	/*
	 * FIXME: Check for duplicates in propties?
	 */
	for (i = d->cgp.nr_props, j = 0; i < nr_props; i++, j++) {
		d->cgp.props[i] = xstrdup(s->cgp.props[j]);
		if (!d->cgp.props[i])
			return -ENOMEM;
		d->cgp.nr_props++;
	}

	return 0;
}

static int cgp_handle_props(cgp_list_entry_t **p, int strategy)
{
	cgp_list_entry_t *s = *p;
	cgp_list_entry_t *t;

	list_for_each_entry(t, &cgp_list, list) {
		if (strcmp(t->cgp.name, s->cgp.name))
			continue;

		pr_debug("%s \"%s\" controller properties\n",
			 strategy == CGP_MERGE ?
			 "Merging" : "Replacing",
			 s->cgp.name);

		if (strategy == CGP_MERGE) {
			int ret;

			ret = cgp_merge_props(t, s);
			cgp_free(s);
			*p = NULL;
			return ret;
		} else if (strategy == CGP_REPLACE) {
			/*
			 * Simply drop out previous instance.
			 */
			list_del(&t->list);
			cgp_free(t);
			break;
		} else
			BUG();
	}

	/*
	 * New controller, simply add it.
	 */
	list_add(&s->list, &cgp_list);
	*p = NULL;
	return 0;
}

static char *skip_spaces(char **stream, size_t *len)
{
	if (stream && *len) {
		char *p = *stream;

		while (p && *len && *p == ' ')
			p++, (*len)--;
		if (p != *stream)
			*stream = p;
		return p;
	}

	return NULL;
}

static bool eat_symbol(char **stream, size_t *len, char sym, bool skip_ws)
{
	char *p = skip_ws ? skip_spaces(stream, len) : (stream ? *stream : NULL);

	if (!p || *p != sym || !*len)
		return false;
	(*stream) = p + 1;
	(*len)--;
	return true;
}

static bool eat_symbols(char **stream, size_t *len, char *syms, size_t n_syms, bool skip_ws)
{
	char *p = skip_ws ? skip_spaces(stream, len) : (stream ? *stream : NULL);
	size_t i;

	if (p && *len) {
		char *stream_orig = *stream;
		size_t len_orig = *len;

		for (i = 0; i < n_syms; i++) {
			if (!eat_symbol(stream, len, syms[i], false)) {
				*stream = stream_orig;
				*len = len_orig;
				goto nomatch;
			}
		}
		return true;
	}
nomatch:
	return false;
}

static bool eat_word(char **stream, size_t *len, char *word, size_t word_len, bool skip_ws)
{
	char *p = skip_ws ? skip_spaces(stream, len) : (stream ? *stream : NULL);

	if (p && *len >= word_len) {
		if (!strncmp(p, word, word_len)) {
			(*stream) += word_len;
			(*len) -= word_len;
			return true;
		}
	}

	return false;
}

static char *get_quoted(char **stream, size_t *len, bool skip_ws)
{
	char *p = skip_ws ? skip_spaces(stream, len) : (stream ? *stream : NULL);
	char *from = p + 1;
	char *dst;

	if (!p || *p != '\"')
		return NULL;

	for (p = from, (*len)--; (*len); p++, (*len)--) {
		if (*p == '\"') {
			if (p == from)
				break;
			dst = xmalloc(p - from + 1);
			if (!dst)
				break;

			memcpy(dst, from, p - from);
			dst[p - from] = '\0';

			(*stream) = p + 1;
			(*len)--;
			return dst;
		}
	}

	return NULL;
}

static int cgp_parse_stream(char *stream, size_t len)
{
	cgp_list_entry_t *cgp_entry = NULL;
	int strategy;
	int ret = 0;
	char *p;

	/*
	 * We expect the following format here
	 * (very simplified YAML!)
	 *
	 *  "cpu":
	 *   - "strategy": "replace"
	 *   - "properties": ["cpu.shares", "cpu.cfs_period_us"]
	 *  "memory":
	 *   - "strategy": "merge"
	 *   - "properties": ["memory.limit_in_bytes", "memory.memsw.limit_in_bytes"]
	 *
	 *  and etc.
	 */

	while (len) {
		/*
		 * Controller name.
		 */
		p = get_quoted(&stream, &len, false);
		if (!p) {
			pr_err("Expecting controller name\n");
			goto err_parse;
		}

		pr_info("Parsing controller \"%s\"\n", p);

		cgp_entry = xzalloc(sizeof(*cgp_entry));
		if (cgp_entry) {
			INIT_LIST_HEAD(&cgp_entry->list);
			cgp_entry->cgp.name = p;
		} else {
			pr_err("Can't allocate memory for controller %s\n", p);
			xfree(p);
			return -ENOMEM;
		}

		if (!eat_symbols(&stream, &len, ":\n - ", 5, true)) {
			pr_err("Expected \':\\n - \' sequence controller's %s stream\n",
			       cgp_entry->cgp.name);
			goto err_parse;
		}

		if (!eat_word(&stream, &len, "\"strategy\":", 11, true)) {
			pr_err("Expected \'strategy:\' keyword in controller's %s stream\n",
			       cgp_entry->cgp.name);
			goto err_parse;
		}

		p = get_quoted(&stream, &len, true);
		if (!p) {
			pr_err("Expected strategy in controller's %s stream\n",
			       cgp_entry->cgp.name);
			goto err_parse;
		};

		if (!strcmp(p, "merge")) {
			strategy = CGP_MERGE;
		} else if (!strcmp(p, "replace")) {
			strategy = CGP_REPLACE;
		} else {
			pr_err("Unknown strategy \"%s\" in controller's %s stream\n",
			       p, cgp_entry->cgp.name);
			xfree(p);
			goto err_parse;
		}

		pr_info("\tStrategy \"%s\"\n", p);
		xfree(p);

		if (!eat_symbols(&stream, &len, "\n - ", 4, true)) {
			pr_err("Expected \':\\n - \' sequence controller's %s stream\n",
			       cgp_entry->cgp.name);
			goto err_parse;
		}

		if (!eat_word(&stream, &len, "\"properties\":", 13, true)) {
			pr_err("Expected \"properties:\" keyword in controller's %s stream\n",
			       cgp_entry->cgp.name);
			goto err_parse;
		}

		if (!eat_symbol(&stream, &len, '[', true)) {
			pr_err("Expected \'[\' sequence controller's %s properties stream\n",
			       cgp_entry->cgp.name);
			goto err_parse;
		}

		while ((p = get_quoted(&stream, &len, true))) {
			if (!p) {
				pr_err("Expected property name for controller %s\n",
				       cgp_entry->cgp.name);
				goto err_parse;
			}

			if (xrealloc_safe(&cgp_entry->cgp.props,
					  (cgp_entry->cgp.nr_props + 1) * sizeof(char *))) {
				pr_err("Can't allocate property for controller %s\n",
				       cgp_entry->cgp.name);
				goto err_parse;
			}

			cgp_entry->cgp.props[cgp_entry->cgp.nr_props++] = p;
			pr_info("\tProperty \"%s\"\n", p);

			if (!eat_symbol(&stream, &len, ',', true)) {
				if (stream[0] == ']') {
					stream++, len--;
					break;
				}
				pr_err("Expected ']' in controller's %s stream\n",
				       cgp_entry->cgp.name);
				goto err_parse;
			}
		}

		if (cgp_entry->cgp.nr_props == 0 && !eat_symbol(&stream, &len, ']', true)) {
			pr_err("Expected ']' in empty property list for %s\n", cgp_entry->cgp.name);
			goto err_parse;
		}

		if (!eat_symbol(&stream, &len, '\n', true) && len) {
			pr_err("Expected \'\\n\' symbol in controller's %s stream\n",
			       cgp_entry->cgp.name);
			goto err_parse;
		}

		if (cgp_handle_props(&cgp_entry, strategy))
			goto err_parse;

		cgp_entry = NULL;
	}

	ret = 0;
out:
	return ret;

err_parse:
	cgp_free(cgp_entry);
	ret = -EINVAL;
	goto out;
}

static int cgp_parse_file(char *path)
{
	void *mem = MAP_FAILED;
	int fd = -1, ret = -1;
	struct stat st;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open file %s", path);
		goto err;
	}

	if (fstat(fd, &st)) {
		pr_perror("Can't stat file %s", path);
		goto err;
	}

	mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (mem == MAP_FAILED) {
		pr_perror("Can't mmap file %s", path);
		goto err;
	}

	if (cgp_parse_stream(mem, st.st_size)) {
		pr_err("Failed to parse file `%s'\n", path);
		goto err;
	}

	ret = 0;
err:
	if (mem != MAP_FAILED)
		munmap(mem, st.st_size);
	close_safe(&fd);
	return ret;
}

static int cgp_parse_builtins(void)
{
	static const char predefined_stream[] =
		"\"cpu\":\n"
			" - \"strategy\": \"replace\"\n"
			" - \"properties\": "
			"[ "
				"\"cpu.shares\", "
				"\"cpu.cfs_period_us\", "
				"\"cpu.cfs_quota_us\", "
				"\"cpu.rt_period_us\", "
				"\"cpu.rt_runtime_us\" "
			"]\n"
		/* limit_in_bytes and memsw.limit_in_bytes must be set in this order */
		"\"memory\":\n"
			" - \"strategy\": \"replace\"\n"
			" - \"properties\": "
			"[ "
				"\"memory.limit_in_bytes\", "
				"\"memory.memsw.limit_in_bytes\", "
				"\"memory.swappiness\", "
				"\"memory.soft_limit_in_bytes\", "
				"\"memory.move_charge_at_immigrate\", "
				"\"memory.oom_control\", "
				"\"memory.use_hierarchy\", "
				"\"memory.kmem.limit_in_bytes\", "
				"\"memory.kmem.tcp.limit_in_bytes\" "
			"]\n"
		/*
		 * cpuset.cpus and cpuset.mems must be set before the process moves
		 * into its cgroup; they are "initialized" below to whatever the root
		 * values are in copy_special_cg_props so as not to cause ENOSPC when
		 * values are restored via this code.
		 */
		"\"cpuset\":\n"
			" - \"strategy\": \"replace\"\n"
			" - \"properties\": "
			"[ "
				"\"cpuset.cpus\", "
				"\"cpuset.mems\", "
				"\"cpuset.memory_migrate\", "
				"\"cpuset.cpu_exclusive\", "
				"\"cpuset.mem_exclusive\", "
				"\"cpuset.mem_hardwall\", "
				"\"cpuset.memory_spread_page\", "
				"\"cpuset.memory_spread_slab\", "
				"\"cpuset.sched_load_balance\", "
				"\"cpuset.sched_relax_domain_level\" "
			"]\n"
		"\"blkio\":\n"
			" - \"strategy\": \"replace\"\n"
			" - \"properties\": "
			"[ "
				"\"blkio.weight\" "
			"]\n"
		"\"freezer\":\n"
			" - \"strategy\": \"replace\"\n"
			" - \"properties\": "
			"[ "
			"]\n"
		"\"perf_event\":\n"
			" - \"strategy\": \"replace\"\n"
			" - \"properties\": "
			"[ "
			"]\n"
		"\"net_cls\":\n"
			" - \"strategy\": \"replace\"\n"
			" - \"properties\": "
			"[ "
				"\"net_cls.classid\" "
			"]\n"
		"\"net_prio\":\n"
			" - \"strategy\": \"replace\"\n"
			" - \"properties\": "
			"[ "
				"\"net_prio.ifpriomap\" "
			"]\n"
		"\"pids\":\n"
			" - \"strategy\": \"replace\"\n"
			" - \"properties\": "
			"[ "
				"\"pids.max\" "
			"]\n"
		"\"devices\":\n"
			" - \"strategy\": \"replace\"\n"
			" - \"properties\": "
			"[ "
				"\"devices.list\" "
			"]\n";

	return cgp_parse_stream((void *)predefined_stream,
				strlen(predefined_stream));
}

int cgp_init(char *stream, size_t len, char *path)
{
	int ret;

	ret = cgp_parse_builtins();
	if (ret)
		goto err;

	if (stream && len) {
		ret = cgp_parse_stream(stream, len);
		if (ret)
			goto err;
	}

	if (path)
		ret = cgp_parse_file(path);
err:
	return ret;
}

static char **dump_controllers;
static size_t nr_dump_controllers;

bool cgp_add_dump_controller(const char *name)
{
	if (xrealloc_safe(&dump_controllers, (nr_dump_controllers + 1) * sizeof(char *))) {
		pr_err("Can't add controller \"%s\" to mark\n", name);
		return false;
	}

	dump_controllers[nr_dump_controllers] = xstrdup(name);
	if (!dump_controllers[nr_dump_controllers])
		return false;

	pr_debug("Mark controller \"%s\" to dump\n", name);
	nr_dump_controllers++;
	return true;
}

bool cgp_should_skip_controller(const char *name)
{
	size_t i;

	/*
	 * Dump all by default.
	 */
	if (!nr_dump_controllers)
		return false;

	for (i = 0; i < nr_dump_controllers; i++) {
		if (!strcmp(name, dump_controllers[i]))
			return false;
	}

	return true;
}

const cgp_t *cgp_get_props(const char *name)
{
	cgp_list_entry_t *p;

	list_for_each_entry(p, &cgp_list, list) {
		if (!strcmp(p->cgp.name, name))
			return &p->cgp;
	}

	return NULL;
}

void cgp_fini(void)
{
	cgp_list_entry_t *p, *t;
	size_t i;

	list_for_each_entry_safe(p, t, &cgp_list, list)
		cgp_free(p);
	INIT_LIST_HEAD(&cgp_list);

	for (i = 0; i < nr_dump_controllers; i++)
		xfree(dump_controllers[i]);
	xfree(dump_controllers);
	nr_dump_controllers = 0;
}
