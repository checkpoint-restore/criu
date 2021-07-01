#ifndef __CR_NETFILTER_H__
#define __CR_NETFILTER_H__

struct inet_sk_desc;
extern int nf_lock_connection(struct inet_sk_desc *);
extern int nf_unlock_connection(struct inet_sk_desc *);

struct inet_sk_info;
extern int nf_unlock_connection_info(struct inet_sk_info *);

extern void preload_netfilter_modules(void);

#if defined(CONFIG_HAS_NFTABLES_LIB_API_0)
#define NFT_RUN_CMD(nft, cmd) nft_run_cmd_from_buffer(nft, cmd, strlen(cmd))
#elif defined(CONFIG_HAS_NFTABLES_LIB_API_1)
#define NFT_RUN_CMD(nft, cmd) nft_run_cmd_from_buffer(nft, cmd)
#else
#define NFT_RUN_CMD(nft, cmd) BUILD_BUG_ON(1)
#endif

#endif /* __CR_NETFILTER_H__ */
