#pragma once
#include <format>
#include <vector>
#include <string>
#include <set>

enum class action_t { copy, remove, reset, unknow, invalid };

struct fib_action_t
{
	action_t action;
	int target_fib;
	std::set<int> multiple_fibs;
};

bool init_entries();

fib_action_t parse_args(const std::vector<std::string> &args);

void print_usage();

void copy_fib(fib_action_t &fib_action);

void reset_fib(fib_action_t &fib_action);
