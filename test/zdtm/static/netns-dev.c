#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>

#include "zdtmtst.h"

#define LO_CONF_DIR_PATH "/proc/sys/net/ipv4/conf/lo"
#define DEF_CONF_DIR_PATH "/proc/sys/net/ipv4/conf/default"

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

int rand_limit4[] = {
	2,	/* accept_local */
	2,	/* accept_redirects */
	2,	/* accept_source_route */
	2,	/* arp_accept */
	3,	/* arp_announce */
	2,	/* arp_filter */
	9,	/* arp_ignore */
	2,	/* arp_notify */
	2,	/* bootp_relay */
	2,	/* disable_policy */
	2,	/* disable_xfrm */
	2,	/* drop_gratuitous_arp */
	2,	/* drop_unicast_in_l2_multicast */
	0,	/* force_igmp_version */
	2,	/* forwarding */
	0,	/* igmpv2_unsolicited_report_interval */
	0,	/* igmpv3_unsolicited_report_interval */
	2,	/* ignore_routes_with_linkdown */
	2,	/* log_martians */
	2,	/* mc_forwarding */
	0,	/* medium_id */
	2,	/* promote_secondaries */
	2,	/* proxy_arp */
	2,	/* proxy_arp_pvlan */
	2,	/* route_localnet */
	3,	/* rp_filter */
	2,	/* secure_redirects */
	2,	/* send_redirects */
	2,	/* shared_media */
	0,	/* src_valid_mark */
	0,	/* tag */
};

struct test_conf {
	int ipv4_conf[ARRAY_SIZE(devconfs4)];
	int ipv4_conf_rand[ARRAY_SIZE(devconfs4)];
	char *dir4;
} lo, def;

static int save_and_set(FILE *fp, int *conf, int *conf_rand,
		int rand_limit, char *path) {
	int ret;
	int val;

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
	val = (int)lrand48();

	if (rand_limit != 0)
		*conf_rand = val % rand_limit;
	else
		*conf_rand = val;

	ret = fprintf(fp, "%d", *conf_rand);
	if (ret < 0) {
		pr_perror("fprintf");
		return -1;
	}

	return 0;
}

static int check_and_restore(FILE *fp, int *conf, int *conf_rand,
		int rand_limit, char *path) {
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
			int rand_limit, char *path), struct test_conf *tc) {
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

		ret = (*f)(fp, &tc->ipv4_conf[i], &tc->ipv4_conf_rand[i], rand_limit4[i], path);
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
