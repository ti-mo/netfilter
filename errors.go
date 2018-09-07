package netfilter

import (
	"errors"
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

const (
	errWrapNetlinkUnmarshalAttrs = "error unmarshaling netlink attributes"
	errWrapNetlinkMarshalAttrs   = "error marshaling netlink attributes"

	errNetlinkQuery = "Netlink query error code: %#x"
)

var (
	// errInvalidAttributeFlags specifies if an Attribute's flag configuration is invalid.
	// From a comment in Linux/include/uapi/linux/netlink.h, Nested and NetByteOrder are mutually exclusive.
	errInvalidAttributeFlags = errors.New("invalid attribute; type cannot have both nested and net byte order flags")

	errShortMessage = errors.New("cannot parse netfilter message because it is too short")
	errExistingData = errors.New("netlink message already contains Data payload")

	errConnIsMulticast = errors.New("Conn is attached to one or more multicast groups and can no longer be used for bidirectional traffic")
)

// CheckNetlinkError takes the result of a successful Netlink query and checks if the response
// contains a Netlink error code. Returns nil unless a non-zero error code is found.
func CheckNetlinkError(nlmsgs []netlink.Message) error {

	var m netlink.Message

	// A single-message response to a Netlink message with ACK flag can be an error or an ACK.
	if len(nlmsgs) == 1 {
		m = nlmsgs[0]
	} else {
		return nil
	}

	if len(m.Data) >= 4 && m.Header.Type == netlink.HeaderTypeError {
		errCode := nlenc.Int32(m.Data[0:4])
		if errCode != 0 {
			return fmt.Errorf(errNetlinkQuery, errCode)
		}
	}

	return nil
}
