/* XXX Which license should be placed here? */

#include <stdio.h>

#include <rte_eal.h>

int
main(int argc, char **argv)
{
	int ret = rte_eal_init(argc, argv);
	printf("EAL initialization: %d\n", ret);
	return 0;
}
