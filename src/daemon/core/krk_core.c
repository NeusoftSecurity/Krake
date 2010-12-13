#include <config.h>
#include <krk_core.h>
#include <krk_socket.h>

static int krk_daemonize(void)
{
}

static const struct option optlong[] = {
	{"help", 0, NULL, 'h'},
	{"version", 0, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

static const char* optstring = "hv";

static void krk_usage(void)
{
	printf("Usage: krake [option]\n"
			"\t--version/-v	Show Krake version\n"
			"\t--help/-h	Show this help\n");
}

static void krk_version(void)
{
	printf("Krake ver: %s\n", PACKAGE_VERSION);
}

int main(int argc, char* argv[])
{
	int opt;
	/**
	 * 1) Handle the args;
	 * 2) Make myself a daemon;
	 * 3) enter main loop for anything.
	 */

	while (1) {
		opt = getopt_long(argc, argv, optstring, optlong, NULL);

		if (opt == -1)
			break;

		switch (opt) {
			case 'h':
				krk_usage();
				break;
			case 'v':
				krk_version();
				break;
			default:
				/* never could be here */
				break;
		}
	}
	
	return 0;
}
