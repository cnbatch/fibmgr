# fibmgr(8) - FreeBSD FIB 管理工具

## 名称 (NAME)
**fibmgr** — 用于管理 FreeBSD FIB (Forwarding Information Base, 转发信息库/路由表) 的简易工具

## 语法 (SYNOPSIS)
```bash
fibmgr [-4 | -6] copy <source_fib> to <target_fib> [<target_fib> ...] | all
fibmgr [-4 | -6] clear <target_fib> [<target_fib> ...] | all

```

## 描述 (DESCRIPTION)

**fibmgr** 是一个用于简化 FreeBSD 系统中 FIB (Forwarding Information Base) 管理的轻量级命令行工具。系统管理员可以使用该工具快速地将某个 FIB 的路由规则复制到其他多个 FIB 中，或者批量清空指定 FIB 的路由数据。

该工具支持灵活的参数传递方式，允许使用逗号分隔或空格分隔的方式指定多个目标 FIB，同时支持特定的 `all` 关键字进行全局操作。

## 选项 (OPTIONS)

以下是 **fibmgr** 支持的全局选项：

* **`-4`**
仅对 IPv4 路由表生效。
* **`-6`**
仅对 IPv6 路由表生效。

若未指定此参数，则同时处理IPv4及IPv6路由表。

## 命令 (COMMANDS)

### copy

将源 FIB (`source_fib`) 的路由信息复制到一个或多个目标 FIB (`target_fib`) 中。

* **语法**: `copy <source_fib> to <target_fib1>[,<target_fib2> ...]`
* **参数 `all**`: 当目标 FIB 指定为 `all` 时，工具会将源路由表复制到系统中所有可用的 FIB。

### clear

清空一个或多个目标 FIB (`target_fib`) 的路由信息。

* **语法**: `clear <target_fib1>[,<target_fib2> ...]`
* **参数 `all**`: 当目标 FIB 指定为 `all` 时，工具会清空系统中所有的 FIB（请谨慎使用）。

## 示例 (EXAMPLES)

以下是一些常见的使用场景和示例：

**1. 复制 FIB 数据**
从 FIB 0 复制路由表到 FIB 1 和 FIB 2（使用逗号分隔）：

> `fibmgr copy 0 to 1,2`

从 FIB 0 复制路由表到 FIB 1, 2, 3（使用空格分隔）：

> `fibmgr copy 0 to 1 2 3`

混合使用逗号和空格分隔多个目标 FIB：

> `fibmgr copy 0 to 1,2 3`

将 FIB 0 的路由表复制到所有可用的 FIB：

> `fibmgr copy 0 to all`

仅将 FIB 0 的 **IPv4** 路由表复制到所有 FIB：

> `fibmgr -4 copy 0 to all`

**2. 清理 FIB 数据**
清空 FIB 1 和 FIB 2 的路由表：

> `fibmgr clear 1,2`

清空 FIB 1, 2, 3 的路由表（使用空格分隔）：

> `fibmgr clear 1 2 3`

混合格式清空指定的多个 FIB：

> `fibmgr clear 1,2 3`

清空系统中所有的 FIB：

> `fibmgr clear all`

仅清空所有 FIB 的 **IPv6** 路由数据：

> `fibmgr -6 clear all`

## 兼容性 (COMPATIBILITY)

* **操作系统版本要求**: FreeBSD **14.2 或更高版本**

本项目源码编译需要 FreeBSD **14.2 或更高版本**。在低于 14.2 的系统版本上，源码无法成功编译。
