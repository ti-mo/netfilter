package netfilter

// Netfilter Subsystem ID definitions
// Taken from Linux/include/uapi/linux/netfilter/nfnetlink.h
//go:generate stringer -type=SubsystemID
type SubsystemID uint8

const (
	NFNL_SUBSYS_NONE SubsystemID = iota
	NFNL_SUBSYS_CTNETLINK
	NFNL_SUBSYS_CTNETLINK_EXP
	NFNL_SUBSYS_QUEUE
	NFNL_SUBSYS_ULOG
	NFNL_SUBSYS_OSF
	NFNL_SUBSYS_IPSET
	NFNL_SUBSYS_ACCT
	NFNL_SUBSYS_CTNETLINK_TIMEOUT
	NFNL_SUBSYS_CTHELPER
	NFNL_SUBSYS_NFTABLES
	NFNL_SUBSYS_NFT_COMPAT
	NFNL_SUBSYS_COUNT
)

// The Netfilter Message type
// Its meaning can only be determined after decoding the Netfilter Subsystem type
// Possible values and string representations need to be implemented in a subsystem-specific package
type MessageType uint8
