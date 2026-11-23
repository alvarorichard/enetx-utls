// SPDX-License-Identifier: BSD-3-Clause
package tls

import (
	"errors"
	"io"
	"testing"
)

func TestEarlyDataTemplateDoesNotReuseEligibility(t *testing.T) {
	early := &EarlyDataExtension{enabled: true}
	spec := innerTestSpec()
	spec.Extensions = append(spec.Extensions, early)
	client := UClient(nil, &Config{ServerName: "example.com"}, HelloCustom)
	if err := client.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if !early.enabled {
		t.Fatal("ApplyPreset mutated caller template")
	}
	cloned := client.Extensions[len(client.Extensions)-1].(*EarlyDataExtension)
	if cloned.Len() != 0 {
		t.Fatal("new connection inherited early-data eligibility")
	}
	if n, err := cloned.Read(nil); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty extension did not end its reader: %d %v", n, err)
	}
	client.setEarlyDataExtension(true)
	data, err := io.ReadAll(cloned)
	if err != nil || len(data) != 4 || data[0] != 0 || data[1] != 42 || data[2] != 0 || data[3] != 0 {
		t.Fatalf("early_data encoding: %x %v", data, err)
	}
}

func TestEarlyDataEligibilityInsertionPreservesPSKOrder(t *testing.T) {
	for _, withPSK := range []bool{false, true} {
		t.Run(map[bool]string{false: "without-psk", true: "with-psk"}[withPSK], func(t *testing.T) {
			first := &GenericExtension{Id: 0x1234, Data: []byte{1, 2}}
			last := &GenericExtension{Id: 0x4321, Data: []byte{3}}
			client := UClient(nil, &Config{}, HelloCustom)
			client.Extensions = []TLSExtension{first, last}
			var psk *UtlsPreSharedKeyExtension
			if withPSK {
				psk = &UtlsPreSharedKeyExtension{}
				client.Extensions = append(client.Extensions, psk)
			}

			before := len(client.Extensions)
			client.setEarlyDataExtension(false)
			if len(client.Extensions) != before {
				t.Fatal("disabled early data added an extension")
			}

			client.setEarlyDataExtension(true)
			index := before
			if withPSK {
				index--
			}

			early, ok := client.Extensions[index].(*EarlyDataExtension)
			if !ok || len(client.Extensions) != before+1 || client.Extensions[0] != first || client.Extensions[1] != last {
				t.Fatal("eligibility insertion changed existing extension order")
			}

			if withPSK && client.Extensions[len(client.Extensions)-1] != psk {
				t.Fatal("pre_shared_key must remain last")
			}

			wire, err := io.ReadAll(early)
			if err != nil || string(wire) != string([]byte{0, 42, 0, 0}) {
				t.Fatalf("invalid enabled early_data offer: %x %v", wire, err)
			}

			client.setEarlyDataExtension(true)
			client.setEarlyDataExtension(false)
			if len(client.Extensions) != before+1 || early.Len() != 0 {
				t.Fatal("eligibility update duplicated the extension or retained its offer")
			}

			if n, err := early.Read(make([]byte, 4)); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("disabled early data emitted bytes: %d %v", n, err)
			}
		})
	}
}
