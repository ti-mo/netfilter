package netfilter

import (
	"testing"

	"github.com/pkg/errors"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

func TestMessageUnmarshalNetlink(t *testing.T) {

	tests := []struct {
		name  string
		attrs []Attribute
		h     Header
		msg   netlink.Message
		err   error
	}{
		{
			name: "netlink message too short",
			msg: netlink.Message{
				Data: make([]byte, nfHeaderLen-1),
			},
			err: errors.Wrap(errMessageLen, "unmarshaling netfilter header"),
		},
		{
			name: "simple attribute",
			msg: netlink.Message{
				Data: []byte{0, 0, 0, 0, 7, 0, 0, 0, 2, 1, 0, 0xff},
			},
			attrs: []Attribute{
				{
					Type: 0,
					Data: []byte{
						0x02, 0x01, 0x00,
					},
				},
			},
		},
		{
			name: "netfilter payload too short",
			msg: netlink.Message{
				Data: make([]byte, nfHeaderLen+1),
			},
			err: errors.New("creating attribute decoder: invalid attribute; length too short or too large"),
		},
		{
			name: "nested and byte order flags set",
			msg: netlink.Message{
				Data: append(
					[]byte{
						0, 0, 0, 0,
						4, 0},
					nlenc.Uint16Bytes(netlink.Nested|netlink.NetByteOrder)...,
				),
			},
			err: errInvalidAttributeFlags,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Extract and parse Netfilter attributes from a Netlink message.
			h, attrs, err := UnmarshalNetlink(tt.msg)

			if tt.err != nil {
				require.Error(t, err)
				require.EqualError(t, err, tt.err.Error())
				return
			}

			require.NoError(t, err)

			if diff := cmp.Diff(tt.attrs, attrs); diff != "" {
				t.Fatalf("unexpected attributes (-want, +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.h, h); diff != "" {
				t.Fatalf("unexpected header (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestAttributeMarshalNetlink(t *testing.T) {

	tests := []struct {
		name  string
		attrs []Attribute
		h     Header
		msg   netlink.Message
		err   error
	}{
		{
			name: "simple attribute w/ header",
			h: Header{
				Family:      ProtoBridge,
				Version:     2,
				ResourceID:  3,
				SubsystemID: NFSubsysIPSet,
				MessageType: 123,
				Flags:       netlink.Root,
			},
			attrs: []Attribute{
				{
					Type: 0,
					Data: []byte{
						0x0F, 0x0E, 0x0D, 0x0C,
						0x0B, 0x0A, 0x09, 0x08,
						0x07, 0x06, 0x05, 0x04,
						0x03, 0x02, 0x01, 0x00,
					},
				},
			},
			msg: netlink.Message{
				Header: netlink.Header{
					Type:  0x067b, // IPSET | 123
					Flags: 0x100,  // Root
				},
				Data: []byte{7, 2, 0, 3, 20, 0, 0, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
			},
		},
		{
			name: "propagate errors to caller",
			attrs: []Attribute{
				{
					Nested:       true,
					NetByteOrder: true,
				},
			},
			err: errInvalidAttributeFlags,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			msg, err := MarshalNetlink(tt.h, tt.attrs)
			if err != nil {
				assert.Equal(t, tt.err.Error(), err.Error())
				// Don't test payload when expecting errors
				return
			}

			if diff := cmp.Diff(tt.msg, msg); diff != "" {
				t.Fatalf("unexpected message (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestEncodeNetlink(t *testing.T) {

	_, err := EncodeNetlink(Header{}, nil)
	assert.EqualError(t, err, errNilAttributeEncoder.Error())

	// Make ae.Encode() throw an error inside EncodeNetlink.
	ae := NewAttributeEncoder()
	ae.Do(0, func() ([]byte, error) { return []byte{}, errors.New("test error") })
	_, err = EncodeNetlink(Header{}, ae)
	assert.EqualError(t, err, "test error")
}
