/* Linked only into the inventory-allocation regression test's plugin. */
int __wrap_add_inventory_plugin(const char *name)
{
	(void)name;
	return -1;
}
