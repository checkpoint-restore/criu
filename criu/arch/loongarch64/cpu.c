#undef LOG_PREFIX
#define LOG_PREFIX "cpu: "

int cpu_init(void)
{
	return 0;
}

int cpu_dump_cpuinfo(void)
{
	return 0;
}

int cpu_validate_cpuinfo(void)
{
	return 0;
}

int cpuinfo_dump(void)
{
	if (cpu_init())
		return -1;
	if (cpu_dump_cpuinfo())
		return -1;
	return 0;
}

int cpuinfo_check(void)
{
	return 0;
}
