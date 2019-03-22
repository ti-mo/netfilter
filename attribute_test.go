package netfilter

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttributeScalarPanicEmpty(t *testing.T) {

	emptyData := Attribute{}

	// All should panic on empty Data
	assert.PanicsWithValue(t, "Uint16: unexpected byte slice length: 0", func() { emptyData.Uint16() })
	assert.PanicsWithValue(t, "Uint32: unexpected byte slice length: 0", func() { emptyData.Uint32() })
	assert.PanicsWithValue(t, "Uint64: unexpected byte slice length: 0", func() { emptyData.Uint64() })

	assert.Panics(t, func() { emptyData.Int32() })
	assert.Panics(t, func() { emptyData.Int64() })

}

func TestAttributeScalarPanicNested(t *testing.T) {

	nestedData := Attribute{Nested: true}

	// All should panic when nested flag set
	assert.PanicsWithValue(t, "Uint16: unexpected Nested attribute", func() { nestedData.Uint16() })
	assert.PanicsWithValue(t, "Uint32: unexpected Nested attribute", func() { nestedData.Uint32() })
	assert.PanicsWithValue(t, "Uint64: unexpected Nested attribute", func() { nestedData.Uint64() })

	assert.Panics(t, func() { nestedData.Int32() })
	assert.Panics(t, func() { nestedData.Int64() })

}

func TestAttributeScalarUint(t *testing.T) {

	u16 := uint16(0xabcd)
	u32 := uint32(0xabcdef12)
	u64 := uint64(0x0123456789abcdef)

	u16b := []byte{0xab, 0xcd}
	u32b := []byte{0xab, 0xcd, 0xef, 0x12}
	u64b := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

	var attr Attribute

	attr.PutUint16(u16)
	assert.Equal(t, u16, attr.Uint16())
	assert.Equal(t, attr.Data, u16b)
	assert.Equal(t, Uint16Bytes(u16), u16b)

	attr.PutUint32(u32)
	assert.Equal(t, u32, attr.Uint32())
	assert.Equal(t, attr.Data, u32b)
	assert.Equal(t, Uint32Bytes(u32), u32b)

	attr.PutUint64(u64)
	assert.Equal(t, u64, attr.Uint64())
	assert.Equal(t, attr.Data, u64b)
	assert.Equal(t, Uint64Bytes(u64), u64b)
}

func TestAttributeScalarInt(t *testing.T) {

	i32 := Attribute{

		Data: []byte{0xff, 0xff, 0xff, 0xff},
	}
	assert.Equal(t, int32(-1), i32.Int32())

	i64 := Attribute{
		Data: []byte{
			0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff,
		},
	}
	assert.Equal(t, int64(-1), i64.Int64())

}

func TestAttributeString(t *testing.T) {
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
			assert.Equal(t, tt.txt, tt.attr.String())
		})
	}
}

func TestAttributeMarshalAttributes(t *testing.T) {
	tests := []struct {
		name  string
		attrs []Attribute
		b     []byte
	}{
		{
			name: "automatic payload length",
			attrs: []Attribute{
				{
					Data: []byte{1, 2, 3},
				},
			},
			b: []byte{
				7, 0, 0, 0,
				1, 2, 3, 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			b, err := marshalAttributes(tt.attrs)
			if err != nil {
				t.Fatalf("unexpected marshal error: %v", err)
			}

			if diff := cmp.Diff(tt.b, b); diff != "" {
				t.Fatalf("unexpected marshal (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAttributeMarshalErrors(t *testing.T) {
	tests := []struct {
		name    string
		attrs   []Attribute
		err     error
		errWrap string
	}{
		{
			name: "nested and endianness bits",
			attrs: []Attribute{
				{

					Data:         make([]byte, 0),
					Nested:       true,
					NetByteOrder: true,
				},
			},
			err: errInvalidAttributeFlags,
		},
		{
			name: "error in nested attribute",
			attrs: []Attribute{
				{
					Data:         make([]byte, 0),
					Nested:       true,
					NetByteOrder: false,
					Children: []Attribute{
						{
							Data:         make([]byte, 0),
							Nested:       true,
							NetByteOrder: true,
						},
					},
				},
			},
			err: errInvalidAttributeFlags,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := marshalAttributes(tt.attrs)
			require.Error(t, err, "marshal must error")

			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error(), "errors must match when error is expected")
			} else if tt.errWrap != "" {
				if !strings.HasPrefix(err.Error(), tt.errWrap+":") {
					t.Fatalf("unexpected wrapped error:\n- expected prefix: %v\n-    error string: %v",
						tt.errWrap, err)
				}
			}
		})
	}
}

func TestAttributeUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		err     error
		errWrap string
	}{
		{
			name:    "netlink unmarshal error",
			b:       []byte{1},
			errWrap: errWrapNetlinkUnmarshalAttrs,
		},
		{
			name: "invalid attribute flags on nested attribute",
			b: []byte{
				12, 0, 0, 128,
				8, 0, 0, 192, // 192 = nested + netByteOrder
				0, 0, 0, 0,
			},
			err: errInvalidAttributeFlags,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := unmarshalAttributes(tt.b)

			if err == nil {
				t.Fatal("unmarshal did not error")
			}

			if tt.err != nil {
				if want, got := tt.err, err; want != got {
					t.Fatalf("unexpected error:\n- want: %v\n-  got: %v",
						want, got.Error())
				}
			} else if tt.errWrap != "" {
				if !strings.HasPrefix(err.Error(), tt.errWrap+":") {
					t.Fatalf("unexpected wrapped error:\n- expected prefix: %v\n-    error string: %v",
						tt.errWrap, err)
				}
			}
		})
	}
}

func TestAttributeMarshalTwoWay(t *testing.T) {
	tests := []struct {
		name  string
		attrs []Attribute
		b     []byte
	}{
		{
			name: "nested bit, type 1, length 0",
			attrs: []Attribute{
				{
					Type:   1,
					Data:   make([]byte, 0),
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
					Type:         1,
					Data:         make([]byte, 0),
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
					Type:         16383,
					Data:         make([]byte, 0),
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
					Type: 123,
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
					Nested: true,
					Children: []Attribute{
						{
							Type: 0,
							Data: []byte{
								0x08, 0x00, // Depth 2,1
								0x00, 0x00,
								0x04, 0x03, 0x02, 0x01,
								0x08, 0x00, // Depth 2,2
								0x00, 0x00,
								0x09, 0x08, 0x07, 0x06,
							},
							Nested: true,
							Children: []Attribute{
								{
									Type: 0,
									Data: []byte{
										0x04, 0x03, 0x02, 0x01,
									},
								},
								{
									Type: 0,
									Data: []byte{
										0x09, 0x08, 0x07, 0x06,
									},
								},
							},
						},
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
			attrs, err := unmarshalAttributes(tt.b)
			require.NoError(t, err)

			assert.Empty(t, cmp.Diff(tt.attrs, attrs))

			var b []byte

			// Attempt re-marshal into binary form
			b, err = marshalAttributes(tt.attrs)
			require.NoError(t, err)

			assert.Empty(t, cmp.Diff(tt.b, b))
		})
	}
}
