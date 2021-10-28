#include <unistd.h>
#include <stdlib.h>
#include <linux/limits.h>

#include "zdtmtst.h"

#define LO_CONF_DIR_PATH   "/proc/sys/net/ipv4/conf/lo"
#define DEF_CONF_DIR_PATH  "/proc/sys/net/ipv4/conf/default"
#define ALL_CONF_DIR_PATH  "/proc/sys/net/ipv4/conf/all"
#define LO_CONF6_DIR_PATH  "/proc/sys/net/ipv6/conf/lo"
#define DEF_CONF6_DIR_PATH "/proc/sys/net/ipv6/conf/default"
#define ALL_CONF6_DIR_PATH "/proc/sys/net/ipv6/conf/all"

#define INT_MAX ((int)(~0U >> 1))
#define INT_MIN (-INT_MAX - 1)

char *devconfs4[] = {
	"accept_local",
	"accept_source_route",
	"arp_accept",
	"arp_announce",
	"arp_filter",
	"arp_ignore",
	"arp_notify",
	"bootp_relay",
	"disable_policy",
	"disable_xfrm",
	"drop_gratuitous_arp",
	"drop_unicast_in_l2_multicast",
	"force_igmp_version",
	"forwarding",
	"accept_redirects",
	"igmpv2_unsolicited_report_interval",
	"igmpv3_unsolicited_report_interval",
	"ignore_routes_with_linkdown",
	"log_martians",
	"mc_forwarding",
	"medium_id",
	"promote_secondaries",
	"proxy_arp",
	"proxy_arp_pvlan",
	"route_localnet",
	"rp_filter",
	"secure_redirects",
	"send_redirects",
	"shared_media",
	"src_valid_mark",
	"tag",
	NULL,
};

struct range {
	int min;
	int max;
};

struct range rand_range4[] = {
	{ 0, 1 },	      /* accept_local */
	{ -1, 0 },	      /* accept_source_route */
	{ 0, 1 },	      /* arp_accept */
	{ 0, 2 },	      /* arp_announce */
	{ 0, 1 },	      /* arp_filter */
	{ 0, 8 },	      /* arp_ignore */
	{ 0, 1 },	      /* arp_notify */
	{ 0, 1 },	      /* bootp_relay */
	{ 0, 1 },	      /* disable_policy */
	{ 0, 1 },	      /* disable_xfrm */
	{ 0, 1 },	      /* drop_gratuitous_arp */
	{ 0, 1 },	      /* drop_unicast_in_l2_multicast */
	{ 0, INT_MAX },	      /* force_igmp_version */
	{ 0, 1 },	      /* forwarding */
	{ 0, 1 },	      /* accept_redirects */
	{ 0, INT_MAX },	      /* igmpv2_unsolicited_report_interval */
	{ 0, INT_MAX },	      /* igmpv3_unsolicited_report_interval */
	{ 0, 1 },	      /* ignore_routes_with_linkdown */
	{ 0, 1 },	      /* log_martians */
	{ 0, 1 },	      /* mc_forwarding */
	{ -1, INT_MAX },      /* medium_id */
	{ 0, 1 },	      /* promote_secondaries */
	{ 0, 1 },	      /* proxy_arp */
	{ 0, 1 },	      /* proxy_arp_pvlan */
	{ 0, 1 },	      /* route_localnet */
	{ 0, 2 },	      /* rp_filter */
	{ 0, 1 },	      /* secure_redirects */
	{ 0, 1 },	      /* send_redirects */
	{ 0, 1 },	      /* shared_media */
	{ 0, 1 },	      /* src_valid_mark */
	{ INT_MIN, INT_MAX }, /* tag */
};

char *devconfs6[] = {
	"accept_dad",
	"accept_ra",
	"accept_ra_defrtr",
	"accept_ra_from_local",
	"accept_ra_min_hop_limit",
	"accept_ra_mtu",
	"accept_ra_pinfo",
	"accept_ra_rt_info_max_plen",
	"accept_ra_rtr_pref",
	"accept_source_route",
	"autoconf",
	"dad_transmits",
	"disable_ipv6",
	"drop_unicast_in_l2_multicast",
	"drop_unsolicited_na",
	"force_mld_version",
	"force_tllao",
	"forwarding",
	"accept_redirects",
	"hop_limit",
	"ignore_routes_with_linkdown",
	"keep_addr_on_down",
	"max_addresses",
	"max_desync_factor",
	"mldv1_unsolicited_report_interval",
	"mldv2_unsolicited_report_interval",
	"mtu",
	"ndisc_notify",
	"optimistic_dad",
	"proxy_ndp",
	"regen_max_retry",
	"router_probe_interval",
	"router_solicitation_delay",
	"router_solicitation_interval",
	"router_solicitations",
	"suppress_frag_ndisc",
	"temp_prefered_lft",
	"temp_valid_lft",
	"use_oif_addrs_only",
	"use_optimistic",
	"use_tempaddr",
	NULL,
};

#define IPV6_MIN_MTU 1280
#define ROUTER_MAX   60
/* According to kernel docs do not make max_addresses too large */
#define MAX_ADDRESSES 128

struct range rand_range6[] = {
	{ 0, 2 },			/* accept_dad */
	{ 0, 2 },			/* accept_ra */
	{ 0, 1 },			/* accept_ra_defrtr */
	{ 0, 1 },			/* accept_ra_from_local */
	{ 0, INT_MAX },			/* accept_ra_min_hop_limit */
	{ 0, 1 },			/* accept_ra_mtu */
	{ 0, 1 },			/* accept_ra_pinfo */
	{ 0, INT_MAX },			/* accept_ra_rt_info_max_plen */
	{ 0, 1 },			/* accept_ra_rtr_pref */
	{ -1, 0 },			/* accept_source_route */
	{ 0, 1 },			/* autoconf */
	{ 0, INT_MAX },			/* dad_transmits */
	{ 0, 1 },			/* disable_ipv6 */
	{ 0, 1 },			/* drop_unicast_in_l2_multicast */
	{ 0, 1 },			/* drop_unsolicited_na */
	{ 0, 2 },			/* force_mld_version */
	{ 0, 1 },			/* force_tllao */
	{ 0, 1 },			/* forwarding */
	{ 0, 1 },			/* accept_redirects */
	{ 1, 255 },			/* hop_limit */
	{ 0, 1 },			/* ignore_routes_with_linkdown */
	{ -1, 1 },			/* keep_addr_on_down */
	{ 0, MAX_ADDRESSES },		/* max_addresses */
	{ 0, INT_MAX },			/* max_desync_factor */
	{ 0, INT_MAX },			/* mldv1_unsolicited_report_interval */
	{ 0, INT_MAX },			/* mldv2_unsolicited_report_interval */
	{ IPV6_MIN_MTU, IPV6_MIN_MTU }, /* mtu */
	{ 0, 1 },			/* ndisc_notify */
	{ 0, 1 },			/* optimistic_dad */
	{ 0, 1 },			/* proxy_ndp */
	{ 0, INT_MAX },			/* regen_max_retry */
	{ 0, ROUTER_MAX },		/* router_probe_interval */
	{ 0, ROUTER_MAX },		/* router_solicitation_delay */
	{ 0, ROUTER_MAX },		/* router_solicitation_interval */
	{ 0, ROUTER_MAX },		/* router_solicitations */
	{ 0, 1 },			/* suppress_frag_ndisc */
	{ 0, INT_MAX },			/* temp_prefered_lft */
	{ 0, INT_MAX },			/* temp_valid_lft */
	{ 0, 1 },			/* use_oif_addrs_only */
	{ 0, 1 },			/* use_optimistic */
	{ 0, 2 },			/* use_tempaddr */
};

struct test_conf {
	int ipv4_conf[ARRAY_SIZE(devconfs4)];
	int ipv4_conf_rand[ARRAY_SIZE(devconfs4)];
	int ipv6_conf[ARRAY_SIZE(devconfs6)];
	int ipv6_conf_rand[ARRAY_SIZE(devconfs6)];
	char *dir4;
	char *dir6;
} lo, def, all;

static int save_conf(FILE *fp, int *conf, int *conf_rand, struct range *range, char *path)
{
	int ret;

	/*
	 * Save
	 */
	ret = fscanf(fp, "%d", conf);
	if (ret != 1) {
		pr_perror("fscanf");
		return -1;
	}

	return 0;
}

static int rand_in_small_range(struct range *r)
{
	return lrand48() % (r->max - r->min + 1) + r->min;
}

static int rand_in_range(struct range *r)
{
	struct range small;
	int mid = r->max / 2 + r->min / 2;
	int half = r->max / 2 - r->min / 2;

	if (half < INT_MAX / 2)
		return rand_in_small_range(r);

	if (lrand48() % 2) {
		small.min = r->min;
		small.max = mid;
	} else {
		small.min = mid + 1;
		small.max = r->max;
	}

	return rand_in_small_range(&small);
}

static int gen_conf(FILE *fp, int *conf, int *conf_rand, struct range *range, char *path)
{
	int ret;
	/*
	 * Set random value
	 */
	*conf_rand = rand_in_range(range);

	ret = fprintf(fp, "%d", *conf_rand);
	if (ret < 0) {
		pr_perror("fprintf");
		return -1;
	}

	return 0;
}

#define MAX_MSEC_GRANULARITY 10

static int check_conf(FILE *fp, int *conf, int *conf_rand, struct range *range, char *path)
{
	int ret;
	int val;

	/*
	 * Check opt
	 */
	ret = fscanf(fp, "%d", &val);
	if (ret != 1) {
		pr_perror("fscanf");
		return -1;
	}

	if (val != *conf_rand) {
		fail("Option \"%s\" changed from %d to %d", path, *conf_rand, val);
		if ((strstr(path, "mldv1_unsolicited_report_interval") ||
		     strstr(path, "mldv2_unsolicited_report_interval")) &&
		    val - *conf_rand < MAX_MSEC_GRANULARITY)
			return 0;
		return -1;
	}

	return 0;
}

static int restore_conf(FILE *fp, int *conf, int *conf_rand, struct range *range, char *path)
{
	int ret;
	/*
	 * Restore opt
	 */
	ret = fprintf(fp, "%d", *conf);
	if (ret < 0) {
		pr_perror("fprintf");
		return -1;
	}

	return 0;
}

static int for_each_option_do(int (*f)(FILE *fp, int *conf, int *conf_rand, struct range *range, char *path),
			      struct test_conf *tc)
{
	int ret;
	int i;

	for (i = 0; devconfs4[i]; i++) {
		FILE *fp;
		char path[PATH_MAX];

		ret = snprintf(path, sizeof(path), "%s/%s", tc->dir4, devconfs4[i]);
		if (ret < 0) {
			pr_perror("snprintf");
			return -1;
		}

		ret = access(path, W_OK);
		if (ret < 0)
			continue;

		fp = fopen(path, "r+");
		if (fp == NULL) {
			pr_perror("fopen");
			return -1;
		}

		ret = (*f)(fp, &tc->ipv4_conf[i], &tc->ipv4_conf_rand[i], &rand_range4[i], path);
		if (ret < 0)
			return -1;

		fclose(fp);
	}

	for (i = 0; devconfs6[i]; i++) {
		FILE *fp;
		char path[PATH_MAX];

		ret = snprintf(path, sizeof(path), "%s/%s", tc->dir6, devconfs6[i]);
		if (ret < 0) {
			pr_perror("snprintf");
			return -1;
		}

		ret = access(path, W_OK);
		if (ret < 0)
			continue;

		fp = fopen(path, "r+");
		if (fp == NULL) {
			pr_perror("fopen");
			return -1;
		}

		ret = (*f)(fp, &tc->ipv6_conf[i], &tc->ipv6_conf_rand[i], &rand_range6[i], path);
		if (ret < 0)
			return -1;

		fclose(fp);
	}

	return 0;
}

#define IPV6ADDR_EXAMPLE "2607:f0d0:1002:0051:0000:0000:0000:0004"
#define MAX_STR_CONF_LEN 200

static int set_stable_secret(struct test_conf *tc)
{
	int ret;
	FILE *fp;
	char path[PATH_MAX];

	ret = snprintf(path, sizeof(path), "%s/%s", tc->dir6, "stable_secret");
	if (ret < 0) {
		pr_perror("snprintf");
		return -1;
	}

	ret = access(path, W_OK);
	if (ret < 0)
		return 0;

	fp = fopen(path, "r+");
	if (fp == NULL) {
		pr_perror("fopen");
		return -1;
	}

	ret = fprintf(fp, IPV6ADDR_EXAMPLE);
	if (ret < 0) {
		pr_perror("fprintf");
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

static int check_stable_secret(struct test_conf *tc)
{
	int ret;
	FILE *fp;
	char path[PATH_MAX];
	char val[MAX_STR_CONF_LEN + 1];

	ret = snprintf(path, sizeof(path), "%s/%s", tc->dir6, "stable_secret");
	if (ret < 0) {
		pr_perror("snprintf");
		return -1;
	}

	ret = access(path, W_OK);
	if (ret < 0)
		return 0;

	fp = fopen(path, "r+");
	if (fp == NULL) {
		pr_perror("fopen");
		return -1;
	}

	ret = fscanf(fp, "%s", val);
	if (ret != 1) {
		pr_perror("fscanf");
		fclose(fp);
		return -1;
	}

	if (strcmp(val, IPV6ADDR_EXAMPLE)) {
		fail("Option \"%s\" changed from %s to %s", path, IPV6ADDR_EXAMPLE, val);
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

int main(int argc, char **argv)
{
	int ret;

	lo.dir4 = LO_CONF_DIR_PATH;
	def.dir4 = DEF_CONF_DIR_PATH;
	all.dir4 = ALL_CONF_DIR_PATH;
	lo.dir6 = LO_CONF6_DIR_PATH;
	def.dir6 = DEF_CONF6_DIR_PATH;
	all.dir6 = ALL_CONF6_DIR_PATH;

	test_init(argc, argv);

	ret = for_each_option_do(save_conf, &all);
	if (ret < 0)
		return -1;
	ret = for_each_option_do(save_conf, &def);
	if (ret < 0)
		return -1;
	ret = for_each_option_do(save_conf, &lo);
	if (ret < 0)
		return -1;

	ret = for_each_option_do(gen_conf, &all);
	if (ret < 0)
		return -1;
	ret = for_each_option_do(gen_conf, &def);
	if (ret < 0)
		return -1;
	ret = for_each_option_do(gen_conf, &lo);
	if (ret < 0)
		return -1;

	ret = set_stable_secret(&def);
	if (ret < 0)
		return -1;
	ret = set_stable_secret(&lo);
	if (ret < 0)
		return -1;

	test_daemon();
	test_waitsig();

	ret = for_each_option_do(check_conf, &all);
	if (ret < 0)
		return -1;
	ret = for_each_option_do(check_conf, &def);
	if (ret < 0)
		return -1;
	ret = for_each_option_do(check_conf, &lo);
	if (ret < 0)
		return -1;

	ret = for_each_option_do(restore_conf, &all);
	if (ret < 0)
		return -1;
	ret = for_each_option_do(restore_conf, &def);
	if (ret < 0)
		return -1;
	ret = for_each_option_do(restore_conf, &lo);
	if (ret < 0)
		return -1;

	ret = check_stable_secret(&def);
	if (ret < 0)
		return -1;
	ret = check_stable_secret(&lo);
	if (ret < 0)
		return -1;

	pass();
	return 0;
}
