#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>

#include "zdtmtst.h"

#define LO_CONF_DIR_PATH "/proc/sys/net/ipv4/conf/lo"
#define DEF_CONF_DIR_PATH "/proc/sys/net/ipv4/conf/default"

#define INT_MAX ((int)(~0U>>1))
#define INT_MIN (-INT_MAX - 1)

char *devconfs4[] = {
	"accept_local",
	"accept_redirects",
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
	{0, 1},	/* accept_local */
	{0, 1},	/* accept_redirects */
	{-1, 0},	/* accept_source_route */
	{0, 1},	/* arp_accept */
	{0, 2},	/* arp_announce */
	{0, 1},	/* arp_filter */
	{0, 8},	/* arp_ignore */
	{0, 1},	/* arp_notify */
	{0, 1},	/* bootp_relay */
	{0, 1},	/* disable_policy */
	{0, 1},	/* disable_xfrm */
	{0, 1},	/* drop_gratuitous_arp */
	{0, 1},	/* drop_unicast_in_l2_multicast */
	{0, INT_MAX},	/* force_igmp_version */
	{0, 1},	/* forwarding */
	{0, INT_MAX},	/* igmpv2_unsolicited_report_interval */
	{0, INT_MAX},	/* igmpv3_unsolicited_report_interval */
	{0, 1},	/* ignore_routes_with_linkdown */
	{0, 1},	/* log_martians */
	{0, 1},	/* mc_forwarding */
	{-1, INT_MAX},	/* medium_id */
	{0, 1},	/* promote_secondaries */
	{0, 1},	/* proxy_arp */
	{0, 1},	/* proxy_arp_pvlan */
	{0, 1},	/* route_localnet */
	{0, 2},	/* rp_filter */
	{0, 1},	/* secure_redirects */
	{0, 1},	/* send_redirects */
	{0, 1},	/* shared_media */
	{0, 1},	/* src_valid_mark */
	{INT_MIN, INT_MAX},	/* tag */
};

struct test_conf {
	int ipv4_conf[ARRAY_SIZE(devconfs4)];
	int ipv4_conf_rand[ARRAY_SIZE(devconfs4)];
	char *dir4;
} lo, def;

static int rand_in_small_range(struct range *r) {
	return lrand48() % (r->max - r->min + 1) + r->min;
}

static int rand_in_range(struct range *r) {
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

static int save_and_set(FILE *fp, int *conf, int *conf_rand,
		struct range *range, char *path) {
	int ret;

	/*
	 * Save
	 */
	ret = fscanf(fp, "%d", conf);
	if (ret != 1) {
		pr_perror("fscanf");
		return -1;
	}

	ret = fseek(fp, 0, SEEK_SET);
	if (ret) {
		pr_perror("fseek");
		return -1;
	}

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

static int check_and_restore(FILE *fp, int *conf, int *conf_rand,
		struct range *range, char *path) {
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
		fail("Option \"%s\" changed from %d to %d",
		     path, *conf_rand, val);
		return -1;
	}

	ret = fseek(fp, 0, SEEK_SET);
	if (ret) {
		pr_perror("fseek");
		return -1;
	}

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

static int for_each_option_do(int (*f)(FILE *fp, int *conf, int *conf_rand,
			struct range *range, char *path), struct test_conf *tc) {
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

	return 0;
}

int main(int argc, char **argv)
{
	int ret;

	lo.dir4 = LO_CONF_DIR_PATH;
	def.dir4 = DEF_CONF_DIR_PATH;

	test_init(argc, argv);

	ret = for_each_option_do(save_and_set, &lo);
	if (ret < 0)
		return -1;

	ret = for_each_option_do(save_and_set, &def);
	if (ret < 0)
		return -1;

	test_daemon();
	test_waitsig();

	ret = for_each_option_do(check_and_restore, &lo);
	if (ret < 0)
		return -1;

	ret = for_each_option_do(check_and_restore, &def);
	if (ret < 0)
		return -1;

	pass();
	return 0;
}
