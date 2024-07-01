#include <cstdio>
#include <iostream>

#include "fibmgr.hpp"

int main(int argc, char *argv[])
{
	init_entries();
	std::vector<std::string> arguments(argv + 1, argv + argc);
	fib_action_t fib_action = parse_args(arguments);

	switch (fib_action.action)
	{
	case action_t::unknow:
		print_usage();
		break;
	case action_t::invalid:
		std::cout << "\n";
		break;
	case action_t::copy:
		if (fib_action.multiple_fibs.empty())
		{
			std::cout << "No action is taken.\n";
		}
		else
		{
			std::cout << "Copying fib ";
			std::cout << fib_action.target_fib << " -> ";
			for (auto num : fib_action.multiple_fibs)
			{
				std::cout << num << " ";
			}
			std::cout << "\n";
			copy_fib(fib_action);
		}
		break;
	case action_t::reset:
		if (fib_action.multiple_fibs.empty())
		{
			std::cout << "No action is taken.\n";
		}
		else
		{
			std::cout << "Reseting fib ";
			for (auto num : fib_action.multiple_fibs)
			{
				std::cout << num << " ";
			}
			std::cout << "\n";
			reset_fib(fib_action);
		}
		break;
	default:
		break;
	}

    return 0;
}
