package netfilter

// Modifier flags for Netlink messages, taken from the 'unix' package.
// Mentioned in include/uapi/linux/netlink.h.
const (
	NLNetfilter = 0xc // NETLINK_NETFILTER
	NFNLv0      = 0   // NFNETLINK_V0

	// Attribute flags.
	NLANested       uint16 = 0x8000                         // NLA_F_NESTED
	NLANetByteOrder uint16 = 0x4000                         // NLA_F_NET_BYTE_ORDER
	NLATypeMask            = ^(NLANested | NLANetByteOrder) // NLA_TYPE_MASK
)

// Subsystem specifiers for Netfilter Netlink messages
const (
	NFSubsysNone SubsystemID = iota // NFNL_SUBSYS_NONE

	NFSubsysCTNetlink        // NFNL_SUBSYS_CTNETLINK
	NFSubsysCTNetlinkExp     // NFNL_SUBSYS_CTNETLINK_EXP
	NFSubsysQueue            // NFNL_SUBSYS_QUEUE
	NFSubsysULOG             // NFNL_SUBSYS_ULOG
	NFSubsysOSF              // NFNL_SUBSYS_OSF
	NFSubsysIPSet            // NFNL_SUBSYS_IPSET
	NFSubsysAcct             // NFNL_SUBSYS_ACCT
	NFSubsysCTNetlinkTimeout // NFNL_SUBSYS_CTNETLINK_TIMEOUT
	NFSubsysCTHelper         // NFNL_SUBSYS_CTHELPER
	NFSubsysNFTables         // NFNL_SUBSYS_NFTABLES
	NFSubsysNFTCompat        // NFNL_SUBSYS_NFT_COMPAT
	NFSubsysCount            // NFNL_SUBSYS_COUNT
)

// ProtoFamily represents a protocol family in the Netfilter header (nfgenmsg).
type ProtoFamily uint8

// anonymous enum in uapi/linux/netfilter.h
const (
	ProtoUnspec ProtoFamily = 0  // NFPROTO_UNSPEC
	ProtoInet   ProtoFamily = 1  // NFPROTO_INET
	ProtoIPv4   ProtoFamily = 2  // NFPROTO_IPV4
	ProtoARP    ProtoFamily = 3  // NFPROTO_ARP
	ProtoNetDev ProtoFamily = 5  // NFPROTO_NETDEV
	ProtoBridge ProtoFamily = 7  // NFPROTO_BRIDGE
	ProtoIPv6   ProtoFamily = 10 // NFPROTO_IPV6
	ProtoDECNet ProtoFamily = 12 // NFPROTO_DECNET
)
