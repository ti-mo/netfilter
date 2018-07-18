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

func TestHeaderType_MarshalUnmarshalNetlink(t *testing.T) {
	nlht := netlink.HeaderType(0x087B) // 0000 1000 0111 1011
	nfht := HeaderType{
		SubsystemID: SubsystemID(NFSubsysCTNetlinkTimeout),
		MessageType: MessageType(123),
	}

	var gotUnmarshal HeaderType
	var gotMarshal netlink.HeaderType

	// Unmarshal nlht into gotUnmarshal and compare the results
	gotUnmarshal.UnmarshalNetlink(nlht)

	if want, got := nfht, gotUnmarshal; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected unmarshalled Netfilter HeaderType:\n- want: %v\n- got: %v\n", want, got)
	}

	// Re-marshal gotUnmarshal into gotMarshal and compare the results
	gotMarshal = gotUnmarshal.MarshalNetlink()

	if want, got := nlht, gotMarshal; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected re-marshalled output:\n- want: %v\n- got: %v\n", want, got)
	}
}
