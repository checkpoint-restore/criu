static int cr_errno;

int get_cr_errno(void)
{
	return cr_errno;
}

void set_cr_errno(int new_err)
{
	if (!cr_errno)
		cr_errno = new_err;
}
