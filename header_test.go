package netfilter

import (
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
)

func TestHeaderType_MarshalUnmarshalNetlink(t *testing.T) {
	nlht := netlink.HeaderType(0x087B) // 0000 1000 0111 1011
	nfht := HeaderType{
		SubsystemID: SubsystemID(NFNLSubsysCTNetlinkTimeout),
		MessageType: MessageType(123),
	}

	var gotUnmarshal HeaderType
	var gotMarshal netlink.HeaderType

	// Unmarshal nlht into gotUnmarshal and compare the results
	gotUnmarshal = UnmarshalNetlinkHeaderType(nlht)

	if want, got := nfht, gotUnmarshal; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected unmarshalled Netfilter HeaderType:\n- want: %v\n- got: %v\n", want, got)
	}

	// Re-marshal gotUnmarshal into gotMarshal and compare the results
	gotMarshal = MarshalNetlinkHeaderType(gotUnmarshal)

	if want, got := nlht, gotMarshal; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected re-marshalled output:\n- want: %v\n- got: %v\n", want, got)
	}
}
