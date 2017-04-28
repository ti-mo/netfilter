package netfilter

import (
	"errors"
	"github.com/mdlayher/netlink/nlenc"
)

var (
	errShortMessage = errors.New("cannot parse netfilter message because it is too short")
)

// Flag values for Netlink messages, taken from the 'unix' package.
// From Linux/include/uapi/linux/netlink.h.
const (
	// Query types.
	NLM_F_REQUEST       = 0x1
	NLM_F_MULTI         = 0x2
	NLM_F_ACK           = 0x4
	NLM_F_ECHO          = 0x8
	NLM_F_DUMP_INTR     = 0x10
	NLM_F_DUMP_FILTERED = 0x20

	// Modifiers to GET queries.
	NLM_F_ROOT   = 0x100
	NLM_F_MATCH  = 0x200
	NLM_F_ATOMIC = 0x400
	NLM_F_DUMP   = (NLM_F_ROOT | NLM_F_MATCH)

	// Modifiers to NEW queries.
	NLM_F_REPLACE = 0x100
	NLM_F_EXCL    = 0x200
	NLM_F_CREATE  = 0x400
	NLM_F_APPEND  = 0x800
)

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

// Size of a Netfilter header (4 Bytes)
const nfHeaderLen = 4

// The Netfilter Header type
// Known in the Linux kernel sources as 'nfgenmsg' at Linux/include/uapi/linux/netfilter/nfnetlink.h
// Holds the family, version and resource ID of the Netfilter message
// ------------------------------
// | Family (1B) | Version (1B) |
// ------------------------------
// |     ResourceID (2 Bytes)   |
// ------------------------------
type Header struct {
	Family     uint8
	Version    uint8
	ResourceId uint16
}

// MarshalBinary marshals a Header into a byte slice.
func (h *Header) MarshalBinary() ([]byte, error) {
	b := make([]byte, nfHeaderLen)

	b[0] = h.Family
	b[1] = h.Version
	nlenc.PutUint16(b[2:4], h.ResourceId)

	return b, nil
}

// UnmarshalBinary unmarshals the contents of a byte slice into a Header.
func (h *Header) UnmarshalBinary(b []byte) error {
	if len(b) < nfHeaderLen {
		return errShortMessage
	}

	h.Family = b[0]
	h.Version = b[1]
	h.ResourceId = nlenc.Uint16(b[2:4])

	return nil
}
