#pragma once
#include <format>
#include <vector>
#include <string>

enum class action_t { copy, remove, reset, unknow, invalid };

struct fib_action_t
{
	action_t action;
	int target_fib;
	std::vector<int> multiple_fibs;
};

void init_entries();

fib_action_t parse_args(const std::vector<std::string> &args);

void print_usage();

bool copy_fib(fib_action_t &fib_action);

bool reset_fib(fib_action_t &fib_action);
