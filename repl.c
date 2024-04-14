#include <stdlib.h>
#include <stdio.h>
#include <regex.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "simpleallocator.h"

/* 
 * a buggy REPL to showcase exploitation strategies of heap buffer overflows
 *
 * Intended ONLY for education purposes.
 *
 * (c) 2024 Dimitrios Glynos (@dfunc on Twitter)
 * See LICENSE file for license information.
 *
 */

enum code_t {
	CC_EXIT=0,
	CC_VAR_VALUE,
	CC_VAR_ASSIGNMENT_VAR,
	CC_VAR_ASSIGNMENT_EXPRESSION,
	CC_UNKNOWN,
};

typedef struct {
	enum code_t code;
	char *regex;
	int (*handler)(const char *, size_t, regmatch_t *);
} command_t;

typedef struct _variable_t {
	char *name;
	void *value;
	size_t value_len;
	void (*print_value)(struct _variable_t *);
	struct _variable_t *next;
} variable_t;

variable_t *variables = NULL;

variable_t *find_var(const char *var) {
	variable_t *v = variables;
	while(v) {
		if (!strcmp(v->name, var)) {
			return v;
		}
		v = v->next;
	}
	return NULL;
}

void print_binary(variable_t *var) {
	int i;
	fprintf(stdout, "\"");
	for(i=0; i<var->value_len; i++) {
		fprintf(stdout, "\\x%.2hhx", ((unsigned char *) var->value)[i]);
	}
	fprintf(stdout, "\"");
	fprintf(stdout, "\n");
}

int cmd_var_value(const char *line, size_t nmatch, regmatch_t *matches) {
	size_t var_len;
	char *str;
	variable_t *var;

	var_len = matches[1].rm_eo - matches[1].rm_so;
	str = sa_alloc(var_len + 1);
	memcpy(str, &line[matches[1].rm_so], var_len);
	str[var_len] = '\0';

	var = find_var(str);
	if (!var) {
		fprintf(stdout, "%s variable name not found\n", str);
	} else {
		var->print_value(var);
	}

	sa_free(str);
	return 1;
}

int cmd_var_assign(const char *line, size_t nmatch, regmatch_t *matches) {
	size_t name_len, value_len;
	char *name;
	unsigned char *value;
	variable_t *var;

	name_len = matches[1].rm_eo - matches[1].rm_so;
	name = sa_alloc(name_len + 1);
	memcpy(name, &line[matches[1].rm_so], name_len);
	name[name_len] = '\0';

	value_len = (matches[2].rm_eo - matches[2].rm_so) / 4;
	value = sa_alloc(value_len);
	for(int i=0; i<value_len; i++) {
		sscanf(&line[matches[2].rm_so + 4*i + 2], "%2hhx", &value[i]);
	}

	var = find_var(name);
	if (!var) {
		variable_t *var = sa_alloc(sizeof(variable_t));
		var->name = name;
		var->value = value;
		var->print_value = print_binary;
		var->value_len = value_len;
		var->next = variables;
		variables = var;
	} else {
		sa_free(name);
		sa_free(var->value);
		var->value = value;
		// BUG #1: failure to update value_len, retaining old one
		// var->value_len = value_len;
	}

	return 1;
}

int cmd_exit(const char *line, size_t nmatch, regmatch_t *matches) {
	return 0;
}

int cmd_unknown(const char *line, size_t nmatch, regmatch_t *matches) {
	fprintf(stdout, "syntax error\n");
	return 1;
}

int cmd_var_assign_var(const char *line, size_t nmatch, regmatch_t *matches) {
	size_t var_left_len, var_right_len;
	char *var_left_name, *var_right_name;
	variable_t *var_left, *var_right;

	var_left_len = matches[1].rm_eo - matches[1].rm_so;
	var_left_name = sa_alloc(var_left_len + 1);
	memcpy(var_left_name, &line[matches[1].rm_so], var_left_len);
	var_left_name[var_left_len] = '\0';

	var_right_len = matches[2].rm_eo - matches[2].rm_so;
	var_right_name = sa_alloc(var_right_len + 1);
	memcpy(var_right_name, &line[matches[2].rm_so], var_right_len);
	var_right_name[var_right_len] = '\0';

	var_right = find_var(var_right_name);
	if (!var_right) {
		fprintf(stdout, "%s variable name not found\n", 
			var_right_name);
		sa_free(var_left_name);
		sa_free(var_right_name);
		return 1;
	}

	sa_free(var_right_name);

	var_left = find_var(var_left_name);
	if (!var_left) {
		variable_t *var_left = sa_alloc(sizeof(variable_t));
		var_left->name = var_left_name;
		// WARNING Bug #1 may cause var_right->value_len to be awfully large
		var_left->value = sa_alloc(var_right->value_len);
		memcpy(var_left->value, var_right->value, var_right->value_len);
		var_left->value_len = var_right->value_len;
		var_left->print_value = print_binary;
		var_left->next = variables;
		variables = var_left;
	} else {
		sa_free(var_left_name);
		sa_free(var_left->value);
		// BUG #2 instead of allocating var_right->value_len bytes
		// we allocate var_right_len
		var_left->value = sa_alloc(var_right_len);
		var_left->value_len = var_right->value_len;
		memcpy(var_left->value, var_right->value, var_right->value_len);
	}

	return 1;
}


command_t commands[] = {
	{ CC_EXIT, "^[[:space:]]*exit[[:space:]]*$", cmd_exit },
	{ CC_VAR_VALUE, "^[[:space:]]*([a-zA-Z][0-9a-zA-Z_]*)[[:space:]]*$", 
		        cmd_var_value },
	{ CC_VAR_ASSIGNMENT_VAR, "^[[:space:]]*([a-zA-Z][0-9a-zA-Z_]*)[[:space:]]*=[[:space:]]*([a-zA-Z][0-9a-zA-Z_]*)[[:space:]]*$", cmd_var_assign_var },
	{ CC_VAR_ASSIGNMENT_EXPRESSION, "^[[:space:]]*([a-zA-Z][0-9a-zA-Z_]*)[[:space:]]*=[[:space:]]*((\\\\x[[:xdigit:]][[:xdigit:]])+)[[:space:]]*$", cmd_var_assign },
	{ CC_UNKNOWN, NULL, cmd_unknown },
};

int handle_cmd(const char *input) {
	command_t *p;
	regmatch_t matches[3];
	int retval;

	retval = 1;

	for(p = commands; p->code != CC_UNKNOWN; p = p+1) {
		regex_t re;
		regcomp(&re, p->regex, REG_EXTENDED);
		if (regexec(&re, input, 3, matches, 0) == 0) { /* match! */
			if (p->handler(input, 3, matches) == 0) {
				retval = 0;
			}
			regfree(&re);
			break;
		}
		regfree(&re);
	}

	if (p->code == CC_UNKNOWN) {
		p->handler(input, 0, NULL);
	}

	return retval;
}

int main(int argc, char *argv[]) {
	while(1) {
		char *input = readline("> ");
		if (!input) {
			break;
		} else if (!strcmp(input, "")) {
			free(input);
			continue;
		} else if (input[strlen(input)-1] == '\n') {
			free(input);
			break;
		}

		if (!handle_cmd(input)) {
			free(input);
			break;
		}
		free(input);
	}

	return 0;
}

