int main(int argc, char ** argv)
{
	test_init(argc, argv);

	test_msg("Skipping test on incompatible kernel");

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
