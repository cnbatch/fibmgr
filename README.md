# fibmgr(8) - FreeBSD FIB Management Tool

## NAME
**fibmgr** — A simple management tool for FreeBSD's FIB (Forwarding Information Base)

## SYNOPSIS
```bash
fibmgr [-4 | -6] copy <source_fib> to <target_fib> [<target_fib> ...] | all
fibmgr [-4 | -6] clear <target_fib> [<target_fib> ...] | all

```

## DESCRIPTION

**fibmgr** is a lightweight command-line utility designed to simplify the management of FIBs (Forwarding Information Bases / routing tables) in FreeBSD systems. It enables system administrators to quickly copy routing rules from a specific source FIB to multiple target FIBs, or bulk-clear routing data from specified FIBs.

The tool offers flexible argument passing, allowing multiple target FIBs to be specified using either comma-separated or space-separated formats, as well as supporting the special `all` keyword for global operations.

## OPTIONS

The following global options are supported by **fibmgr**:

* **`-4`**
Apply operations to IPv4 routing tables only.
* **`-6`**
Apply operations to IPv6 routing tables only.

If not specified, both IPv4 and IPv6 routing tables are processed.

## COMMANDS

### copy

Copies routing information from a source FIB (`source_fib`) to one or more target FIBs (`target_fib`).

* **Syntax**: `copy <source_fib> to <target_fib1>[,<target_fib2> ...]`
* **The `all` Argument**: When the target FIB is specified as `all`, the utility copies the source routing table to all available FIBs in the system.

### clear

Clears routing information from one or more target FIBs (`target_fib`).

* **Syntax**: `clear <target_fib1>[,<target_fib2> ...]`
* **The `all` Argument**: When the target FIB is specified as `all`, the utility clears all FIBs in the system (use with caution).

## EXAMPLES

Below are some common use cases and configuration examples:

**1. Copying FIB Data**
Copy routing table from FIB 0 to FIB 1 and FIB 2 (comma-separated):

> `fibmgr copy 0 to 1,2`

Copy routing table from FIB 0 to FIB 1, 2, and 3 (space-separated):

> `fibmgr copy 0 to 1 2 3`

Mix comma and space separators for multiple target FIBs:

> `fibmgr copy 0 to 1,2 3`

Copy the routing table from FIB 0 to all available FIBs:

> `fibmgr copy 0 to all`

Copy only the **IPv4** routing table from FIB 0 to all FIBs:

> `fibmgr -4 copy 0 to all`

**2. Clearing FIB Data**
Clear the routing tables of FIB 1 and FIB 2:

> `fibmgr clear 1,2`

Clear the routing tables of FIB 1, 2, and 3 (space-separated):

> `fibmgr clear 1 2 3`

Clear specified multiple FIBs using mixed formatting:

> `fibmgr clear 1,2 3`

Clear all FIBs in the system:

> `fibmgr clear all`

Clear only the **IPv6** routing data across all FIBs:

> `fibmgr -6 clear all`

## COMPATIBILITY

* **Version Requirement**: FreeBSD **14.2 or higher**.

Compiling the source code of this project requires FreeBSD **14.2 or higher**. The source code will fail to compile successfully on any system versions prior to 14.2.
