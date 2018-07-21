package netfilter

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/assert"
)

func TestAttribute_ScalarPanicEmpty(t *testing.T) {

	emptyData := Attribute{}

	// All should panic on empty Data
	assert.PanicsWithValue(t, "Uint16: unexpected byte slice length: 0", func() { emptyData.Uint16() })
	assert.PanicsWithValue(t, "Uint32: unexpected byte slice length: 0", func() { emptyData.Uint32() })
	assert.PanicsWithValue(t, "Uint64: unexpected byte slice length: 0", func() { emptyData.Uint64() })
	assert.Panics(t, func() { emptyData.Int16() })
	assert.Panics(t, func() { emptyData.Int32() })
	assert.Panics(t, func() { emptyData.Int64() })

}

func TestAttribute_ScalarPanicNested(t *testing.T) {

	nestedData := Attribute{Nested: true}

	// All should panic when nested flag set
	assert.PanicsWithValue(t, "Uint16: unexpected Nested attribute", func() { nestedData.Uint16() })
	assert.PanicsWithValue(t, "Uint32: unexpected Nested attribute", func() { nestedData.Uint32() })
	assert.PanicsWithValue(t, "Uint64: unexpected Nested attribute", func() { nestedData.Uint64() })
	assert.Panics(t, func() { nestedData.Int16() })
	assert.Panics(t, func() { nestedData.Int32() })
	assert.Panics(t, func() { nestedData.Int64() })

}

func TestAttribute_ScalarUint(t *testing.T) {

	u16 := Attribute{
		Attribute: netlink.Attribute{
			Data: []byte{0xab, 0xcd},
		},
	}
	assert.Equal(t, uint16(0xabcd), u16.Uint16())

	u32 := Attribute{
		Attribute: netlink.Attribute{
			Data: []byte{0xab, 0xcd, 0xef, 0x12},
		},
	}
	assert.Equal(t, uint32(0xabcdef12), u32.Uint32())

	u64 := Attribute{
		Attribute: netlink.Attribute{
			Data: []byte{
				0x01, 0x23, 0x45, 0x67,
				0x89, 0xab, 0xcd, 0xef,
			},
		},
	}
	assert.Equal(t, uint64(0x0123456789abcdef), u64.Uint64())

}

func TestAttribute_ScalarInt(t *testing.T) {

	i16 := Attribute{
		Attribute: netlink.Attribute{
			Data: []byte{0xff, 0xff},
		},
	}
	assert.Equal(t, int16(-1), i16.Int16())

	i32 := Attribute{
		Attribute: netlink.Attribute{
			Data: []byte{0xff, 0xff, 0xff, 0xff},
		},
	}
	assert.Equal(t, int32(-1), i32.Int32())

	i64 := Attribute{
		Attribute: netlink.Attribute{
			Data: []byte{
				0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff,
			},
		},
	}
	assert.Equal(t, int64(-1), i64.Int64())

}

func TestAttribute_String(t *testing.T) {
	var tests = []struct {
		name string
		attr Attribute
		txt  string
	}{
		{
			name: "empty struct",
			attr: Attribute{},
			txt:  "<Length 0, Type 0, Nested false, NetByteOrder false, []>",
		},
		{
			name: "empty struct w/ netbyteorder set",
			attr: Attribute{NetByteOrder: true},
			txt:  "<Length 0, Type 0, Nested false, NetByteOrder true, []>",
		},
		{
			name: "attribute w/ nested attribute",
			attr: Attribute{
				Nested: true,
				Children: []Attribute{
					Attribute{},
				},
			},
			txt: "<Length 0, Type 0, Nested true, 1 Children ([<Length 0, Type 0, Nested false, NetByteOrder false, []>])>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.attr.String()

			if want := tt.txt; want != got {
				t.Fatalf("unexpected string:\n- want: %v\n-  got: %v", want, got)
			}
		})
	}
}

func TestAttribute_ToNetlink(t *testing.T) {

	tests := []struct {
		name  string
		attrs []Attribute
		msg   netlink.Message
		err   error
	}{
		{
			name: "initialize netlink.Message.Data",
			msg: netlink.Message{
				Data: []byte{0, 0, 0, 0},
			},
		},
		{
			name: "simple attribute",
			attrs: []Attribute{
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
			msg: netlink.Message{
				Data: []byte{0, 0, 0, 0, 20, 0, 0, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
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

			var gotNlMsg netlink.Message

			// Serialize netfilter.Attributes to a netlink.Message
			err := AttributesToNetlink(tt.attrs, &gotNlMsg)
			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v", want, got)
			}

			// Don't test payload when expecting errors
			if err != nil {
				return
			}

			if want, got := tt.msg, gotNlMsg; !reflect.DeepEqual(want, got) {
				t.Fatalf("unexpected string:\n- want: %v\n-  got: %v", want, got)
			}
		})
	}
}

func TestAttribute_Marshal(t *testing.T) {
	tests := []struct {
		name  string
		attrs []Attribute
		b     []byte
		err   error
	}{
		{
			name: "nested and endianness bits",
			attrs: []Attribute{
				{
					Attribute: netlink.Attribute{
						Data:   make([]byte, 0),
						Length: 4,
						Type:   0,
					},
					Nested:       true,
					NetByteOrder: true,
				},
			},
			err: errInvalidAttributeFlags,
		},
		{
			name: "nested bit, type 1, length 0",
			attrs: []Attribute{
				{
					Attribute: netlink.Attribute{
						Length: 4,
						Type:   1,
						Data:   make([]byte, 0),
					},
					Nested: true,
				},
			},
			b: []byte{
				0x04, 0x00,
				0x01, 0x80, // Nested bit
			},
		},
		{
			name: "endianness bit, type 1, length 0",
			attrs: []Attribute{
				{
					Attribute: netlink.Attribute{
						Length: 4,
						Type:   1,
						Data:   make([]byte, 0),
					},
					NetByteOrder: true,
				},
			},
			b: []byte{
				0x04, 0x00,
				0x01, 0x40, // NetByteOrder bit
			},
		},
		{
			name: "max type space, length 0",
			attrs: []Attribute{
				{
					Attribute: netlink.Attribute{
						Length: 4,
						Type:   16383,
						Data:   make([]byte, 0),
					},
					Nested:       false,
					NetByteOrder: false,
				},
			},
			b: []byte{
				0x04, 0x00,
				0xFF, 0x3F, // 14 lowest type bits up
			},
		},
		{
			name: "multiple nested attributes",
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
			b, err := MarshalAttributes(tt.attrs)

			if want, got := tt.err, err; want != got {
				t.Fatalf("unexpected error:\n- want: %v\n-  got: %v",
					want, got)
			}

			// Don't test payload when expecting errors
			if err != nil {
				return
			}

			if want, got := tt.b, b; !bytes.Equal(want, got) {
				t.Fatalf("unexpected bytes:\n- want: [%# x]\n-  got: [%# x]",
					want, got)
			}
		})
	}
}

func TestAttribute_MarshalTwoWay(t *testing.T) {
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
