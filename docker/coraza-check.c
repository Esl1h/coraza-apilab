/*
 * coraza-check: load a Coraza rules file and report whether it compiles.
 *
 * coraza-nginx parses the rules inside each worker after fork, so
 * `nginx -t` cannot see a broken rule: the master starts, every worker
 * dies, and requests hang. This tool runs the same libcoraza parser up
 * front, so a bad rule fails the container start (and CI) with the
 * parser's own error message.
 */
#include <stdio.h>
#include <coraza/coraza.h>

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <rules-file>\n", argv[0]);
		return 2;
	}

	coraza_waf_config_t cfg = coraza_new_waf_config();
	coraza_rules_add_file(cfg, argv[1]);

	char *err = NULL;
	coraza_waf_t waf = coraza_new_waf(cfg, &err);
	if (waf == 0) {
		fprintf(stderr, "coraza-check: %s: %s\n", argv[1], err ? err : "unknown error");
		coraza_free_string(err);
		return 1;
	}

	printf("coraza-check: %s: OK, %d rules loaded\n", argv[1], coraza_rules_count(waf));
	return 0;
}
