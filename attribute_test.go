package netfilter

import (
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
)

func TestHeader_MarshalUnmarshalMessage(t *testing.T) {
	hdr := Header{
		Family:     255,
		Version:    1,
		ResourceID: 2,
	}

	msg := netlink.Message{Data: []byte{255, 1, 2, 0}}

	var gotUnmarshal Header
	gotMarshal := netlink.Message{Data: []byte{0, 0, 0, 0}}

	// Unmarshal msg into gotUnmarshal
	if err := gotUnmarshal.UnmarshalMessage(msg); err != nil {
		t.Fatalf("failed to unmarshal message: %v", msg)
	}

	if want, got := hdr, gotUnmarshal; want != got {
		t.Fatalf("unexpected unmarshalled Netfilter header:\n- want: %v\n- got: %v\n", want, got)
	}

	// Re-marshal gotUnmarshal into gotMarshal
	if err := gotUnmarshal.MarshalMessage(&gotMarshal); err != nil {
		t.Fatalf("failed to re-marshal message: %v", gotUnmarshal)
	}

	if want, got := msg, gotMarshal; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected re-marshalled output:\n- want: %v\n- got: %v\n", want, got)
	}
}

func TestAttribute_MarshalUnmarshalAttributes(t *testing.T) {
	tests := []struct {
		name  string
		attrs []Attribute
		b     []byte
		err   error
	}{
		{
			name: "multiple nested",
			attrs: []Attribute{
				{
					Attribute: netlink.Attribute{
						Length: 44,
						Type:   123,
						Data: []byte{
							0x14, 0x00, // Depth 1,1
							0x00, 0x80, // Nested bit
							0x08, 0x00, // Depth 2,1
							0x00, 0x00,
							0x04, 0x03, 0x02, 0x01,
							0x08, 0x00, // Depth 2,2
							0x00, 0x00,
							0x09, 0x08, 0x07, 0x06,
							0x14, 0x00, // Depth 1,2
							0x00, 0x00,
							0x0F, 0x0E, 0x0D, 0x0C,
							0x0B, 0x0A, 0x09, 0x08,
							0x07, 0x06, 0x05, 0x04,
							0x03, 0x02, 0x01, 0x00,
						},
					},
					Nested: true,
					Children: []Attribute{
						{
							Attribute: netlink.Attribute{
								Length: 20,
								Type:   0,
								Data: []byte{
									0x08, 0x00, // Depth 2,1
									0x00, 0x00,
									0x04, 0x03, 0x02, 0x01,
									0x08, 0x00, // Depth 2,2
									0x00, 0x00,
									0x09, 0x08, 0x07, 0x06,
								},
							},
							Nested: true,
							Children: []Attribute{
								{
									Attribute: netlink.Attribute{
										Length: 8,
										Type:   0,
										Data: []byte{
											0x04, 0x03, 0x02, 0x01,
										},
									},
								},
								{
									Attribute: netlink.Attribute{
										Length: 8,
										Type:   0,
										Data: []byte{
											0x09, 0x08, 0x07, 0x06,
										},
									},
								},
							},
						},
						{
							Attribute: netlink.Attribute{
								Length: 20,
								Type:   0,
								Data: []byte{
									0x0F, 0x0E, 0x0D, 0x0C,
									0x0B, 0x0A, 0x09, 0x08,
									0x07, 0x06, 0x05, 0x04,
									0x03, 0x02, 0x01, 0x00,
								},
							},
						},
					},
				},
			},
			b: []byte{
				0x2C, 0x00, // Root level
				0x7B, 0x80, // type 123, Nested bit
				0x14, 0x00, // Depth 1,1
				0x00, 0x80,
				0x08, 0x00, // Depth 2,1
				0x00, 0x00,
				0x04, 0x03, 0x02, 0x01,
				0x08, 0x00, // Depth 2,2
				0x00, 0x00,
				0x09, 0x08, 0x07, 0x06,
				0x14, 0x00, // Depth 1,2
				0x00, 0x00,
				0x0F, 0x0E, 0x0D, 0x0C,
				0x0B, 0x0A, 0x09, 0x08,
				0x07, 0x06, 0x05, 0x04,
				0x03, 0x02, 0x01, 0x00,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Unmarshal binary content into nested structures
			attrs, err := UnmarshalAttributes(tt.b)
			if err != nil {
				return
			}

			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v",
					want, got)
			}

			if want, got := tt.attrs, attrs; !reflect.DeepEqual(want, got) {
				t.Fatalf("unexpected unmarshal:\n- want: %v\n-  got: %v",
					want, got)
			}

			var b []byte

			// Attempt re-marshal into binary form
			b, err = MarshalAttributes(attrs)
			if err != nil {
				return
			}

			if want, got := tt.b, b; !reflect.DeepEqual(want, got) {
				t.Fatalf("unexpected marshal:\n- want: %v\n-  got: %v",
					want, got)
			}
		})
	}
}
