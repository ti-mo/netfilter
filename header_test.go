package netfilter

import (
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
)

func TestHeader_ToFromNetlink(t *testing.T) {

	nfHdr := Header{
		Family:     255,
		Version:    1,
		ResourceID: 2,
	}

	nlMsg := netlink.Message{Data: []byte{255, 1, 2, 0}}

	var gotNfHdr Header
	gotNlMsg := netlink.Message{Data: []byte{0, 0, 0, 0}}

	// Get Netfilter header from Netlink message
	if err := gotNfHdr.FromNetlinkMessage(nlMsg); err != nil {
		t.Fatalf("failed to parse message into header: %v", nlMsg)
	}

	if want, got := nfHdr, gotNfHdr; want != got {
		t.Fatalf("unexpected Netfilter header:\n- want: %v\n- got: %v\n", want, got)
	}

	// Put Netfilter headet back into Netlink message
	if err := gotNfHdr.ToNetlinkMessage(&gotNlMsg); err != nil {
		t.Fatalf("failed to put netfilter header into message: %v", gotNfHdr)
	}

	if want, got := nlMsg, gotNlMsg; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected netlink message output:\n- want: %v\n- got: %v\n", want, got)
	}
}

func TestHeaderType_ToFromNetlink(t *testing.T) {

	nlh := netlink.Header{
		Type: 0x087B, // 0000 1000 0111 1011
	}

	nfht := HeaderType{
		SubsystemID: SubsystemID(NFSubsysCTNetlinkTimeout),
		MessageType: MessageType(123),
	}

	var gotNfht HeaderType
	var gotNlh netlink.Header

	// Unmarshal netlink header into netfilter HeaderType
	gotNfht.FromNetlinkHeader(nlh)

	if want, got := nfht, gotNfht; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected unmarshalled Netfilter HeaderType:\n- want: %v\n- got: %v\n", want, got)
	}

	// Convert gotNfht back into gotNlh and compare the results
	gotNfht.ToNetlinkHeader(&gotNlh)

	if want, got := nlh, gotNlh; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected netlink header:\n- want: %v\n- got: %v\n", want, got)
	}
}

func TestHeaderType_String(t *testing.T) {
	ht := HeaderType{
		SubsystemID: NFSubsysIPSet,
		MessageType: 123,
	}

	htStr := ht.String()
	want := "NFSubsysIPSet|123"

	if got := htStr; htStr != want {
		t.Fatalf("HeaderType string mismatch:\n- want: %s\n-  got: %s", want, got)
	}
}
