#ifndef UAPI_COMPEL_PLUGIN_H__
#define UAPI_COMPEL_PLUGIN_H__

#define __init	__attribute__((__used__)) __attribute__ ((__section__(".compel.init")))
#define __exit	__attribute__((__used__)) __attribute__ ((__section__(".compel.exit")))

#ifndef __ASSEMBLY__

typedef struct {
	const char	*name;
	int		(*init)(void);
	void		(*exit)(void);
} plugin_init_t;

#define plugin_register(___desc)				\
	static const plugin_init_t * const			\
	___ptr__##___desc __init = &___desc;

#define PLUGIN_REGISTER(___id, ___name, ___init, ___exit)	\
	static const plugin_init_t __plugin_desc_##___id = {	\
		.name = ___name,				\
		.init = ___init,				\
		.exit = ___exit,				\
	};							\
	plugin_register(__plugin_desc_##___id);

#define PLUGIN_REGISTER_DUMMY(___id)				\
	static const plugin_init_t __plugin_desc_##___id = {	\
		.name = #___id,					\
	};							\
	plugin_register(__plugin_desc_##___id);

#endif /* __ASSEMBLY__ */

#endif /* UAPI_COMPEL_PLUGIN_H__ */
