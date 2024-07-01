#include <cstdio>
#include <iostream>
#include <vector>
#include <sstream>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/linker.h>
#include <sys/types.h>

#include <netlink/netlink.h>
#include <netlink/route/interface.h>
#include <netlink/route/common.h>

#include <netlink/netlink_snl_route.h>
#include <netlink/netlink_snl_route_parsers.h>
#include <netlink/netlink_snl_route_compat.h>

#include "fibmgr.hpp"

// from /usr.bin/netstat/common.h
struct ifmap_entry {
	char ifname[IFNAMSIZ];
	uint32_t mtu;
};

struct routing_entry
{
	sockaddr_storage destination;
	sockaddr_dl gateway;
	uint8_t mask;
	int flags;
	uint32_t mtu;
	uint32_t weight = 1;
};

routing_entry default_entries[6] = {};
int sdl_index = 0;

// orginally from /sbin/route/route_netlink.c: nl_init_socket
bool
nl_init_socket(struct snl_state *ss);

bool
nl_init_socket(struct snl_state *ss)
{
	if (snl_init(ss, NETLINK_ROUTE))
		return true;

	if (modfind("netlink") == -1 && errno == ENOENT) {
		/* Try to load */
		if (kldload("netlink") == -1)
			std::cerr << "netlink is not loaded and load attempt failed\n";
		if (snl_init(ss, NETLINK_ROUTE))
			return true;
	}

	std::cerr << "unable to open netlink socket\n";
	return false;
}

void add_defaults(int fibnum);

// orginally from /usr.bin/netstat/route_netlink.c: p_rtable_netlink
bool
routing_table_netlink_ops(int fibnum, int af, action_t action, const std::vector<int> &other_fibs = {});

// orginally from /usr.bin/netstat/route_netlink.c: prepare_ifmap_netlink
struct ifmap_entry *
prepare_ifmap_netlink(struct snl_state *ss, size_t *pifmap_size);

// orginally from /usr.bin/netstat/route_netlink.c: p_rtentry_netlink
void
routing_table_entry_netlink_ops(int cmd, const std::vector<int> &other_fib,
                                struct snl_state *ss, ifmap_entry *ifmap,
                                struct nlmsghdr *hdr);

// orginally from /sbin/route/route_netlink.c: rtmsg_nl
int
rtmsg_nl(int cmd, int rtm_flags, int fib,
         struct sockaddr *dst, uint8_t mask, struct sockaddr *gw, u_long rmx_mtu, u_long rmx_weight);

// orginally from /sbin/route/route_netlink.c: rtmsg_nl_int
int
rtmsg_nl_int(struct snl_state *ss, int cmd, int rtm_flags, int fib,
             struct sockaddr *dst, uint8_t mask, struct sockaddr *gw,
             u_long rmx_mtu, u_long rmx_weight);

int
rtmsg_nl_int(struct snl_state *ss, int cmd, int rtm_flags, int fib,
             struct sockaddr *dst, uint8_t mask, struct sockaddr *gw,
             u_long rmx_mtu, u_long rmx_weight)
{
	struct snl_writer nw;
	int nl_type = 0, nl_flags = 0;

	snl_init_writer(ss, &nw);

	switch (cmd) {
	case RTSOCK_RTM_ADD:
		nl_type = RTM_NEWROUTE;
		nl_flags = NLM_F_CREATE | NLM_F_APPEND; /* Do append by default */
		break;
	case RTSOCK_RTM_CHANGE:
		nl_type = RTM_NEWROUTE;
		nl_flags = NLM_F_REPLACE;
		break;
	case RTSOCK_RTM_DELETE:
		nl_type = RTM_DELROUTE;
		break;
	default:
		return (EINVAL);
	}

	if (dst == NULL)
		return (EINVAL);

	struct nlmsghdr *hdr = snl_create_msg_request(&nw, nl_type);
	hdr->nlmsg_flags |= nl_flags;

	int plen = 0;
	int rtm_type = RTN_UNICAST;

	switch (dst->sa_family) {
	case AF_INET:
	{
		if ((rtm_flags & RTF_HOST) == 0)
			plen = mask;
		else
			plen = 32;
		break;
	}
	case AF_INET6:
	{
		if ((rtm_flags & RTF_HOST) == 0)
			plen = mask;
		else
			plen = 128;
		break;
	}
	default:

		return (ENOTSUP);
	}

	if (rtm_flags & RTF_REJECT)
		rtm_type = RTN_PROHIBIT;
	else if (rtm_flags & RTF_BLACKHOLE)
		rtm_type = RTN_BLACKHOLE;

	struct rtmsg *rtm = snl_reserve_msg_object(&nw, struct rtmsg);
	rtm->rtm_family = dst->sa_family;
	rtm->rtm_protocol = RTPROT_STATIC;
	rtm->rtm_type = rtm_type;
	rtm->rtm_dst_len = plen;

	/* Request exact prefix match if mask is set */
	if (cmd == RTSOCK_RTM_GET)
		rtm->rtm_flags = RTM_F_PREFIX;

	snl_add_msg_attr_ip(&nw, RTA_DST, dst);
	snl_add_msg_attr_u32(&nw, RTA_TABLE, fib);

	uint32_t rta_oif = 0;

	if (gw != NULL) {
		if (rtm_flags & RTF_GATEWAY) {
			if (gw->sa_family == dst->sa_family)
				snl_add_msg_attr_ip(&nw, RTA_GATEWAY, gw);
			else
				snl_add_msg_attr_ipvia(&nw, RTA_VIA, gw);
			if (gw->sa_family == AF_INET6) {
				struct sockaddr_in6 *gw6 = (struct sockaddr_in6 *)gw;

				if (IN6_IS_ADDR_LINKLOCAL(&gw6->sin6_addr))
					rta_oif = gw6->sin6_scope_id;
			}
		}
		else {
			/* Should be AF_LINK */
			struct sockaddr_dl *sdl = (struct sockaddr_dl *)gw;
			if (sdl->sdl_index != 0)
				rta_oif = sdl->sdl_index;
		}
	}

	if (dst->sa_family == AF_INET6 && rta_oif == 0) {
		struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)dst;

		if (IN6_IS_ADDR_LINKLOCAL(&dst6->sin6_addr))
			rta_oif = dst6->sin6_scope_id;
	}

	if (rta_oif != 0)
		snl_add_msg_attr_u32(&nw, RTA_OIF, rta_oif);
	if (rtm_flags != 0)
		snl_add_msg_attr_u32(&nw, NL_RTA_RTFLAGS, rtm_flags);

	if (rmx_mtu > 0) {
		int off = snl_add_msg_attr_nested(&nw, RTA_METRICS);
		snl_add_msg_attr_u32(&nw, RTAX_MTU, rmx_mtu);
		snl_end_attr_nested(&nw, off);
	}

	if (rmx_weight > 0)
		snl_add_msg_attr_u32(&nw, NL_RTA_WEIGHT, rmx_weight);

	if ((hdr = snl_finalize_msg(&nw)) && snl_send_message(ss, hdr)) {
		struct snl_errmsg_data e = {};

		hdr = snl_read_reply(ss, hdr->nlmsg_seq);
		if (nl_type == NL_RTM_GETROUTE) {
			if (hdr->nlmsg_type == NL_RTM_NEWROUTE) {
				return (0);
			}
		}

		if (snl_parse_errmsg(ss, hdr, &e)) {
			switch (e.error) {
			case (ESRCH):
				//warnx("route has not been found");
				break;
			default:
				if (e.error == 0)
					break;
				//warnc(e.error, "message indicates error");
			}

			return (e.error);
		}
	}

	return (EINVAL);
}

int
rtmsg_nl(int cmd, int rtm_flags, int fib,
         struct sockaddr *dst, uint8_t mask, struct sockaddr *gw,
         u_long rmx_mtu, u_long rmx_weight)
{
	struct snl_state ss_cmd = {};
	if (!nl_init_socket(&ss_cmd))
		return -1;
	int error = rtmsg_nl_int(&ss_cmd, cmd, rtm_flags, fib, dst, mask, gw, rmx_mtu, rmx_weight);
	snl_free(&ss_cmd);

	return (error);
}

void
routing_table_entry_netlink_ops(int cmd, const std::vector<int> &fibnums,
                                struct snl_state *ss, ifmap_entry *ifmap, struct nlmsghdr *hdr)
{

	struct snl_parsed_route rt = {};
	if (!snl_parse_nlmsg(ss, hdr, &snl_rtm_route_parser, &rt))
		return;
	if (rt.rtax_weight == 0)
		rt.rtax_weight = 1;

	if (rt.rta_multipath.num_nhops != 0) {
		uint32_t orig_rtflags = rt.rta_rtflags;
		uint32_t orig_mtu = rt.rtax_mtu;
		for (uint32_t i = 0; i < rt.rta_multipath.num_nhops; i++) {
			struct rta_mpath_nh *nhop = rt.rta_multipath.nhops[i];

			rt.rta_gw = nhop->gw;
			rt.rta_oif = nhop->ifindex;
			rt.rtax_weight = nhop->rtnh_weight;
			rt.rta_rtflags = nhop->rta_rtflags ? nhop->rta_rtflags : orig_rtflags;
			rt.rtax_mtu = nhop->rtax_mtu ? nhop->rtax_mtu : orig_mtu;

			if (rt.rtm_family == AF_INET)
			{
				sockaddr_in* destination_addr_in = reinterpret_cast<sockaddr_in*>(rt.rta_dst);
				char buf[32] = {};
				inet_ntop(AF_INET, &destination_addr_in->sin_addr, buf, destination_addr_in->sin_len);
				if (std::string("127.0.0.1") == buf)
					sdl_index = ((sockaddr_dl*)rt.rta_gw)->sdl_index;
			}

			if (rt.rtm_family == AF_INET6)
			{
				sockaddr_in6* destination_addr_in = reinterpret_cast<sockaddr_in6*>(rt.rta_dst);
				char buf[128] = {};
				inet_ntop(AF_INET6, &destination_addr_in->sin6_addr, buf, destination_addr_in->sin6_len);
				if (std::string("::1") == buf)
					sdl_index = ((sockaddr_dl*)rt.rta_gw)->sdl_index;
			}

			for (auto fib : fibnums)
			{
				int error = rtmsg_nl(cmd, rt.rta_rtflags, fib, rt.rta_dst, rt.rtm_dst_len, rt.rta_gw, rt.rtax_mtu, rt.rtax_weight);
				if (error != 0)
				{
					if (cmd == RTSOCK_RTM_ADD)
						std::cerr << std::format("Add route to fib {} failed.\n", fib);
					if (cmd == RTSOCK_RTM_DELETE)
						std::cerr << std::format("Delete route of fib {} failed.\n", fib);
				}
			}
		}
		return;
	}

	struct sockaddr_dl sdl_gw = {
		.sdl_len = (u_char)sizeof(struct sockaddr_dl),
		.sdl_family = AF_LINK,
		.sdl_index = (u_short)rt.rta_oif,
	};
	if (rt.rta_gw == NULL)
		rt.rta_gw = (struct sockaddr *)&sdl_gw;

	if (rt.rtm_family == AF_INET)
	{
		sockaddr_in* destination_addr_in = reinterpret_cast<sockaddr_in*>(rt.rta_dst);
		char buf[32] = {};
		inet_ntop(AF_INET, &destination_addr_in->sin_addr, buf, destination_addr_in->sin_len);
		if (std::string("127.0.0.1") == buf)
			sdl_index = ((sockaddr_dl*)rt.rta_gw)->sdl_index;
	}

	if (rt.rtm_family == AF_INET6)
	{
		sockaddr_in6* destination_addr_in = reinterpret_cast<sockaddr_in6*>(rt.rta_dst);
		char buf[128] = {};
		inet_ntop(AF_INET6, &destination_addr_in->sin6_addr, buf, destination_addr_in->sin6_len);
		if (std::string("::1") == buf)
			sdl_index = ((sockaddr_dl*)rt.rta_gw)->sdl_index;
	}

	for (auto fib : fibnums)
	{
		int error = rtmsg_nl(cmd, rt.rta_rtflags, fib, rt.rta_dst, rt.rtm_dst_len, rt.rta_gw, rt.rtax_mtu, rt.rtax_weight);
		if (error != 0)
		{
			if (cmd == RTSOCK_RTM_ADD)
				std::cerr << std::format("Add route to fib {} failed.\n", fib);
			if (cmd == RTSOCK_RTM_DELETE)
				std::cerr << std::format("Delete route of fib {} failed.\n", fib);
		}
	}
}

struct ifmap_entry *
prepare_ifmap_netlink(struct snl_state *ss, size_t *pifmap_size)
{
	struct {
		struct nlmsghdr hdr;
		struct ifinfomsg ifmsg;
	} msg = {
		.hdr = {
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
			.nlmsg_seq = snl_get_seq(ss)
		}
	};
	msg.hdr.nlmsg_len = sizeof(msg);

	if (!snl_send_message(ss, &msg.hdr))
		return (NULL);

	struct ifmap_entry *ifmap = NULL;
	uint32_t ifmap_size = 0;
	struct nlmsghdr *hdr;
	struct snl_errmsg_data e = {};

	while ((hdr = snl_read_reply_multi(ss, msg.hdr.nlmsg_seq, &e)) != NULL) {
		struct snl_parsed_link_simple link = {};

		if (!snl_parse_nlmsg(ss, hdr, &snl_rtm_link_parser_simple, &link))
			continue;
		if (link.ifi_index >= ifmap_size) {
			size_t size = roundup2(link.ifi_index + 1, 32) * sizeof(struct ifmap_entry);
			if ((ifmap = (decltype(ifmap))realloc(ifmap, size)) == NULL)
				std::cerr << std::format("realloc({}) failed\n", size);
			memset(&ifmap[ifmap_size], 0,
				size - ifmap_size *
				sizeof(struct ifmap_entry));
			ifmap_size = roundup2(link.ifi_index + 1, 32);
		}
		if (*ifmap[link.ifi_index].ifname != '\0')
			continue;
		strlcpy(ifmap[link.ifi_index].ifname, link.ifla_ifname, IFNAMSIZ);
		ifmap[link.ifi_index].mtu = link.ifla_mtu;
	}
	*pifmap_size = ifmap_size;
	return (ifmap);
}

bool
routing_table_netlink_ops(int fibnum, int af, action_t action, const std::vector<int> &other_fibs)
{
	int fam = AF_UNSPEC;
	struct nlmsghdr *hdr;
	struct snl_errmsg_data e = {};
	struct snl_state ss = {};
	struct ifmap_entry *ifmap;
	size_t ifmap_size;

	if (!snl_init(&ss, NETLINK_ROUTE))
		return (false);

	ifmap = prepare_ifmap_netlink(&ss, &ifmap_size);
	if (ifmap == NULL) {
		snl_free(&ss);
		return (false);
	}

	struct
	{
		struct nlmsghdr hdr;
		struct rtmsg rtmsg;
		struct nlattr nla_fibnum;
		uint32_t fibnum;
	} msg = {
		.hdr = {
			.nlmsg_type = RTM_GETROUTE,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
			.nlmsg_seq = snl_get_seq(&ss)
		},
		.rtmsg = { .rtm_family = (unsigned char)af },
		.nla_fibnum = {
			.nla_len = sizeof(struct nlattr) + sizeof(uint32_t),
			.nla_type = RTA_TABLE
		},
		.fibnum = (uint32_t)fibnum,
	};
	msg.hdr.nlmsg_len = sizeof(msg);

	if (!snl_send_message(&ss, &msg.hdr))
	{
		snl_free(&ss);
		return (false);
	}

	while ((hdr = snl_read_reply_multi(&ss, msg.hdr.nlmsg_seq, &e)) != NULL)
	{
		struct rtmsg *rtm = (struct rtmsg *)(hdr + 1);
		if (fam != rtm->rtm_family)
			fam = rtm->rtm_family;

		if (action == action_t::copy)
		{
			routing_table_entry_netlink_ops(RTSOCK_RTM_ADD, other_fibs, &ss, ifmap, hdr);
		}

		if (action == action_t::remove)
		{
			std::vector<int> target_fib = { fibnum };
			routing_table_entry_netlink_ops(RTSOCK_RTM_DELETE, target_fib, &ss, ifmap, hdr);
		}
		snl_clear_lb(&ss);
	}
	snl_free(&ss);
	return (true);
}

void add_defaults(int fib)
{
	for (int i = 0; i < 6; i++)
	{
		default_entries[i].gateway.sdl_index = sdl_index;
		int error = rtmsg_nl(RTSOCK_RTM_ADD, default_entries[i].flags, fib, (sockaddr*)&default_entries[i].destination,
			default_entries[i].mask, (sockaddr*)&default_entries[i].gateway, default_entries[i].mtu, default_entries[i].weight);
		if (error != 0)
			std::cerr << std::format("Add route to fib {} failed.\n", fib);
	}
}

void init_entries()
{
	sockaddr_in *sin4 = nullptr;
	sockaddr_in6 *sin6 = nullptr;

	sin4 = (sockaddr_in*)&default_entries[0].destination;
	inet_pton(AF_INET, "127.0.0.1", &(sin4->sin_addr));
	default_entries[0].destination.ss_family = AF_INET;
	default_entries[0].destination.ss_len = sizeof(sockaddr_in);
	default_entries[0].gateway.sdl_family = AF_LINK;
	default_entries[0].gateway.sdl_len = sizeof(sockaddr_dl);
	default_entries[0].mask = 32;
	default_entries[0].flags =  RTF_HOST | RTF_STATIC;

	sin6 = (sockaddr_in6*)&default_entries[1].destination;
	default_entries[1].mask = 96;
	default_entries[1].flags = RTF_UP | RTF_REJECT | RTF_STATIC;

	sin6 = (sockaddr_in6*)&default_entries[2].destination;
	inet_pton(AF_INET6, "::1", &(sin6->sin6_addr));
	default_entries[2].mask = 128;
	default_entries[2].flags =  RTF_HOST | RTF_STATIC;

	sin6 = (sockaddr_in6*)&default_entries[3].destination;
	inet_pton(AF_INET6, "::ffff:0.0.0.0", &(sin6->sin6_addr));
	default_entries[3].mask = 96;
	default_entries[3].flags = RTF_UP | RTF_REJECT | RTF_STATIC;

	sin6 = (sockaddr_in6*)&default_entries[4].destination;
	inet_pton(AF_INET6, "fe80::", &(sin6->sin6_addr));
	default_entries[4].mask = 10;
	default_entries[4].flags = RTF_UP | RTF_REJECT | RTF_STATIC;

	sin6 = (sockaddr_in6*)&default_entries[5].destination;
	inet_pton(AF_INET6, "ff02::", &(sin6->sin6_addr));
	default_entries[5].mask = 16;
	default_entries[5].flags = RTF_UP | RTF_REJECT | RTF_STATIC;

	default_entries[1].destination.ss_family = default_entries[2].destination.ss_family =
		default_entries[3].destination.ss_family = default_entries[4].destination.ss_family =
		default_entries[5].destination.ss_family = AF_INET6;
	default_entries[1].destination.ss_len = default_entries[2].destination.ss_len =
		default_entries[3].destination.ss_len = default_entries[4].destination.ss_len =
		default_entries[5].destination.ss_len = sizeof(sockaddr_in6);
	default_entries[1].gateway.sdl_family = default_entries[2].gateway.sdl_family =
		default_entries[3].gateway.sdl_family = default_entries[4].gateway.sdl_family =
		default_entries[5].gateway.sdl_family = AF_LINK;
	default_entries[1].gateway.sdl_len = default_entries[2].gateway.sdl_len =
		default_entries[3].gateway.sdl_len = default_entries[4].gateway.sdl_len =
		default_entries[5].gateway.sdl_len = sizeof(sockaddr_dl);
}

fib_action_t parse_args(const std::vector<std::string> &args)
{
	fib_action_t fib_action = {};
	fib_action.action = action_t::unknow;

	int numfibs = 0;
	size_t intsize = sizeof(int);
	if (sysctlbyname("net.fibs", &numfibs, &intsize, NULL, 0) == -1)
		numfibs = 1;

	if (args.size() < 2)
		return fib_action;

	if (args[0] == "copy")
	{
		if (args.size() < 4)
			return fib_action;

		try
		{
			int copy_from_fib = std::stoi(args[1]);
			if (copy_from_fib < 0 || copy_from_fib > numfibs - 1)
			{
				std::cerr << std::format("Invalid fib: {}\n", copy_from_fib);
				fib_action.action = action_t::invalid;
				return fib_action;
			}

			if (args[2] != "to")
				return fib_action;

			fib_action.target_fib = copy_from_fib;

			for (size_t i = 3; i < args.size(); i++)
			{
				if (args[i].find(',') == std::string::npos)
				{
					try
					{
						int current_fib = std::stoi(args[i]);
						if (current_fib < 0 || current_fib > numfibs - 1)
						{
							std::cerr << std::format("Invalid fib: {}\n", current_fib);
							continue;
						}

						if (copy_from_fib == current_fib)
							continue;

						if (current_fib == 0)
						{
							std::cerr << "Replacing main table (fib 0) is not a good idea. The operation on fib 0 has skipped.\n";
							continue;
						}

						fib_action.multiple_fibs.push_back(current_fib);
					}
					catch (...)
					{
						std::cerr << args[i] << " is an invalid input\n";
						continue;
					}
				}
				else
				{
					std::stringstream sstr(args[i]);
					while (sstr.good())
					{
						std::string str;
						std::getline(sstr, str, ',');
						try
						{
							fib_action.multiple_fibs.push_back(std::stoi(str));
						}
						catch (...)
						{
							std::cerr << str << " is an invalid input\n";
							continue;
						}
					}
				}
			}

			fib_action.action = action_t::copy;
		}
		catch (...)
		{
			return fib_action;
		}
	}

	if (args[0] == "reset")
	{
		if (args.size() < 2)
			return fib_action;

		for (size_t i = 1; i < args.size(); i++)
		{
			if (args[i].find(',') == std::string::npos)
			{
				try
				{
					int current_fib = std::stoi(args[i]);
					if (current_fib < 0 || current_fib > numfibs - 1)
					{
						std::cerr << std::format("Invalid fib: {}\n", current_fib);
						continue;
					}

					if (current_fib == 0)
					{
						std::cerr << "Replacing main table (fib 0) is not a good idea. The operation on fib 0 has skipped.\n";
						continue;
					}

					fib_action.multiple_fibs.push_back(current_fib);
				}
				catch (...)
				{
					std::cerr << args[i] << " is an invalid input\n";
					continue;
				}
			}
			else
			{
				std::stringstream sstr(args[i]);
				while (sstr.good())
				{
					std::string str;
					std::getline(sstr, str, ',');
					try
					{
						int current_fib = std::stoi(str);
						if (current_fib < 0 || current_fib > numfibs - 1)
						{
							std::cerr << std::format("Invalid fib: {}\n", current_fib);
							continue;
						}

						if (current_fib == 0)
						{
							std::cerr << "Replacing main table (fib 0) is not a good idea. The operation on fib 0 has skipped.\n";
							continue;
						}
						fib_action.multiple_fibs.push_back(current_fib);
					}
					catch (...)
					{
						std::cerr << str << " is an invalid input\n";
						continue;
					}
				}
			}

			fib_action.action = action_t::reset;
		}
	}

	return fib_action;
}

void print_usage()
{
	char usage_info[] = "fibmgr: usage:\n"
		"\tfibmgr copy fibnum to fibnum1,fibnum2 fibnum3\n"
		"\tfibmgr reset fibnum fibnum1,fibnum2 fibnum3\n"
		"Examples:\n"
		"\tfibmgr copy 0 to 1,2\n"
		"\tfibmgr copy 0 to 1 2 3\n"
		"\tfibmgr copy 0 to 1,2 3\n"
		"\tfibmgr reset 1,2\n"
		"\tfibmgr reset 1 2 3\n"
		"\tfibmgr reset 1,2 3\n";

	std::cout << usage_info;
}

bool copy_fib(fib_action_t &fib_action)
{
	for (auto fib : fib_action.multiple_fibs)
	{
		routing_table_netlink_ops(fib, AF_INET, action_t::remove);
		routing_table_netlink_ops(fib, AF_INET6, action_t::remove);
	}

	routing_table_netlink_ops(fib_action.target_fib, AF_INET, action_t::copy, fib_action.multiple_fibs);
	routing_table_netlink_ops(fib_action.target_fib, AF_INET6, action_t::copy, fib_action.multiple_fibs);
	return false;
}

bool reset_fib(fib_action_t &fib_action)
{
	for (auto fib : fib_action.multiple_fibs)
	{
		routing_table_netlink_ops(fib, AF_INET, action_t::remove);
		routing_table_netlink_ops(fib, AF_INET6, action_t::remove);
		add_defaults(fib);
	}

	return false;
}
