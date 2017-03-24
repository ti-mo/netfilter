package netfilter

import (
	"github.com/mdlayher/netlink/nlenc"
	"unsafe"
	"errors"
)

var (
	errShortMessage = errors.New("cannot parse netfilter message because it is too short")
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
const nfHeaderLen = int(unsafe.Sizeof(Header{}))

// The Netfilter Header type
// Known in the Linux kernel sources as 'nfgenmsg' at Linux/include/uapi/linux/netfilter/nfnetlink.h
// Holds the family, version and resource ID of the Netfilter message
// ------------------------------
// | Family (1B) | Version (1B) |
// ------------------------------
// |     ResourceID (2 Bytes)   |
// ------------------------------
type Header struct {
	Family uint8
	Version uint8
	ResourceId uint16
}

// MarshalBinary marshals a Header into a byte slice.
func (h *Header) MarshalBinary() ([]byte, error) {
	b := make([]byte, 4)

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
