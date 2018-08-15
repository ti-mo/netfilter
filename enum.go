package netfilter

// Modifier flags for Netlink messages, taken from the 'unix' package.
// Mentioned in include/uapi/linux/netlink.h.
const (
	NLNetfilter = 0xc // NETLINK_NETFILTER

	// Query types.
	NLFlagRequest      = 0x1  // NLM_F_REQUEST
	NLFlagMulti        = 0x2  // NLM_F_MULTI
	NLFlagAck          = 0x4  // NLM_F_ACK
	NLFlagEcho         = 0x8  // NLM_F_ECHO
	NLFlagDumpIntr     = 0x10 // NLM_F_DUMP_INTR
	NLFlagDumpFiltered = 0x20 // NLM_F_DUMP_FILTERED

	// Modifiers to GET queries.
	NLFlagRoot   = 0x100                      // NLM_F_ROOT
	NLFlagMatch  = 0x200                      // NLM_F_MATCH
	NLFlagAtomic = 0x400                      // NLM_F_ATOMIC
	NLFlagDump   = (NLFlagRoot | NLFlagMatch) // NLM_F_DUMP

	// Modifiers to NEW queries.
	NLFlagReplace = 0x100 // NLM_F_REPLACE
	NLFlagExcl    = 0x200 // NLM_F_EXCL
	NLFlagCreate  = 0x400 // NLM_F_CREATE
	NLFlagAppend  = 0x800 // NLM_F_APPEND

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
