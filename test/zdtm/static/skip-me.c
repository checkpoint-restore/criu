int main(int argc, char **argv)
{
	test_init(argc, argv);

	test_msg("Skipping test:" TEST_SKIP_REASON);

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
