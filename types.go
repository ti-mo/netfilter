package netfilter

import (
	"github.com/mdlayher/netlink/nlenc"
)

// Modifier flags for Netlink messages, taken from the 'unix' package.
// Mentioned in include/uapi/linux/netlink.h.
const (
	// Query types.
	NLMFRequest      = 0x1  // NLM_F_REQUEST
	NLMFMulti        = 0x2  // NLM_F_MULTI
	NLMFAck          = 0x4  // NLM_F_ACK
	NLMFEcho         = 0x8  // NLM_F_ECHO
	NLMFDumpIntr     = 0x10 // NLM_F_DUMP_INTR
	NLMFDumpFiltered = 0x20 // NLM_F_DUMP_FILTERED

	// Modifiers to GET queries.
	NLMFRoot   = 0x100                  // NLM_F_ROOT
	NLMFMatch  = 0x200                  // NLM_F_MATCH
	NLMFAtomic = 0x400                  // NLM_F_ATOMIC
	NLMFDump   = (NLMFRoot | NLMFMatch) // NLM_F_DUMP

	// Modifiers to NEW queries.
	NLMFReplace = 0x100 // NLM_F_REPLACE
	NLMFExcl    = 0x200 // NLM_F_EXCL
	NLMFCreate  = 0x400 // NLM_F_CREATE
	NLMFAppend  = 0x800 // NLM_F_APPEND
)

// SubsystemID is a const representing a Netfilter Subsystem ID.
// From include/uapi/linux/netfilter/nfnetlink.h
//go:generate stringer -type=SubsystemID
type SubsystemID uint8

// Subsystem specifiers for Netfilter Netlink messages
const (
	NFNLSubsysNone SubsystemID = iota // NFNL_SUBSYS_NONE

	NFNLSubsysCTNetlink        // NFNL_SUBSYS_CTNETLINK
	NFNLSubsysCTNetlinkExp     // NFNL_SUBSYS_CTNETLINK_EXP
	NFNLSubsysQueue            // NFNL_SUBSYS_QUEUE
	NFNLSubsysULOG             // NFNL_SUBSYS_ULOG
	NFNLSubsysOSF              // NFNL_SUBSYS_OSF
	NFNLSubsysIPSet            // NFNL_SUBSYS_IPSET
	NFNLSubsysAcct             // NFNL_SUBSYS_ACCT
	NFNLSubsysCTNetlinkTimeout // NFNL_SUBSYS_CTNETLINK_TIMEOUT
	NFNLSubsysCTHelper         // NFNL_SUBSYS_CTHELPER
	NFNLSubsysNFTables         // NFNL_SUBSYS_NFTABLES
	NFNLSubsysNFTCompat        // NFNL_SUBSYS_NFT_COMPAT
	NFNLSubsysCount            // NFNL_SUBSYS_COUNT
)

// MessageType denotes the Netfilter-specific Netlink message type.
// Its meaning can only be determined after decoding the Netfilter Subsystem type.
// Possible values and string representations need to be implemented in a subsystem-specific package
type MessageType uint8

// Size of a Netfilter header (4 Bytes)
const nfHeaderLen = 4

// Header represents a Netfilter Netlink protocol header.
// Known in the Linux kernel sources as 'nfgenmsg' at Linux/include/uapi/linux/netfilter/nfnetlink.h
// Holds the family, version and resource ID of the Netfilter message.
// -----------------------------------------------------
// | Family (1B) | Version (1B) | ResourceID (2 Bytes) |
// -----------------------------------------------------
type Header struct {
	Family     uint8
	Version    uint8
	ResourceID uint16
}

// MarshalBinary marshals a netfilter.Header into a byte slice.
func (h *Header) MarshalBinary() ([]byte, error) {
	b := make([]byte, nfHeaderLen)

	b[0] = h.Family
	b[1] = h.Version
	nlenc.PutUint16(b[2:4], h.ResourceID)

	return b, nil
}

// UnmarshalBinary unmarshals the contents of the first <nfHeaderLen> bytes of a
// byte slice into a netfilter.Header.
func (h *Header) UnmarshalBinary(b []byte) error {
	if len(b) < nfHeaderLen {
		return errShortMessage
	}

	h.Family = b[0]
	h.Version = b[1]
	h.ResourceID = nlenc.Uint16(b[2:4])

	return nil
}
