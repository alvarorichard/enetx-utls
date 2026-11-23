package tls

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// An entropy failure at any private PSK component must abort camouflage without
// returning partially randomized data or modifying the original offer.
func TestRandomizedECHPSKEntropyFailuresPreserveInput(t *testing.T) {
	identity := PskIdentity{Label: []byte("private-ticket"), ObfuscatedTicketAge: 0x12345678}
	binder := bytes.Repeat([]byte{0x91}, 32)
	raw := make([]byte, pskExtLen([]PskIdentity{identity}, [][]byte{binder}))
	if _, err := readPskIntoBytes(raw, []PskIdentity{identity}, [][]byte{binder}); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}

	original := bytes.Clone(raw[4:])
	for name, entropyBytes := range map[string]int{
		"identity":   0,
		"ticket-age": len(identity.Label),
		"binder":     len(identity.Label) + 4,
	} {
		t.Run(name, func(t *testing.T) {
			output, err := randomizedECHPSK(original, bytes.NewReader(make([]byte, entropyBytes)))
			if !errors.Is(err, io.EOF) || output != nil {
				t.Fatalf("entropy failure returned a placeholder: %x %v", output, err)
			}

			if !bytes.Equal(original, raw[4:]) {
				t.Fatal("entropy failure modified the original private PSK")
			}
		})
	}

	for _, malformed := range [][]byte{
		{0, 1, 0, 0, 0},
		{0, 3, 0, 1, 1, 0, 0},
	} {
		if output, err := randomizedECHPSK(malformed, bytes.NewReader(make([]byte, 100))); err == nil || output != nil {
			t.Fatalf("malformed identity accepted: %x %v", output, err)
		}
	}
}

func echPSKTestCommon() PreSharedKeyCommon {
	return PreSharedKeyCommon{
		Session:    &SessionState{version: VersionTLS13, cipherSuite: TLS_AES_128_GCM_SHA256},
		Identities: []PskIdentity{{Label: []byte("cached-ticket"), ObfuscatedTicketAge: 42}},
		Binders:    [][]byte{bytes.Repeat([]byte{0x91}, 32)},
		BinderKey:  make([]byte, 32), EarlySecret: make([]byte, 32),
	}
}

func TestECHPSKRejectsForeignAndMalformedSessionMaterial(t *testing.T) {
	for name, mutate := range map[string]func(*PreSharedKeyCommon){
		"legacy-session":     func(c *PreSharedKeyCommon) { c.Session.version = VersionTLS12 },
		"unknown-suite":      func(c *PreSharedKeyCommon) { c.Session.cipherSuite = 0xffff },
		"short-binder-key":   func(c *PreSharedKeyCommon) { c.BinderKey = make([]byte, 31) },
		"long-binder-key":    func(c *PreSharedKeyCommon) { c.BinderKey = make([]byte, 33) },
		"short-early-secret": func(c *PreSharedKeyCommon) { c.EarlySecret = make([]byte, 31) },
		"long-early-secret":  func(c *PreSharedKeyCommon) { c.EarlySecret = make([]byte, 33) },
		"multiple-identities": func(c *PreSharedKeyCommon) {
			c.Identities = append(c.Identities, PskIdentity{Label: []byte("other-ticket")})
		},
	} {
		t.Run(name, func(t *testing.T) {
			common := echPSKTestCommon()
			mutate(&common)
			client := UClient(nil, &Config{}, HelloCustom)
			client.sessionController.pskExtension = &UtlsPreSharedKeyExtension{PreSharedKeyCommon: common}
			offer, keyMaterial, err := client.echPSKExtension(new(echClientContext))
			if err == nil || offer != nil || keyMaterial != nil {
				t.Fatalf("invalid session produced an inner offer: %v %v %v", offer, keyMaterial, err)
			}
		})
	}

	client := UClient(nil, &Config{}, HelloCustom)
	client.sessionController.pskExtension = &FakePreSharedKeyExtension{
		Identities: []PskIdentity{{Label: []byte("unowned-ticket")}},
		Binders:    [][]byte{make([]byte, 32)},
	}
	if offer, common, err := client.echPSKExtension(new(echClientContext)); err == nil || offer != nil || common != nil {
		t.Fatal("a synthetic PSK without an engine-owned session was accepted")
	}
}

func TestECHPSKUsesHRRIdentityDecision(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(map[bool]string{false: "dropped", true: "retained"}[retained], func(t *testing.T) {
			common := echPSKTestCommon()
			client := UClient(nil, &Config{}, HelloCustom)
			client.sessionController.pskExtension = &UtlsPreSharedKeyExtension{PreSharedKeyCommon: common}
			inner := new(clientHelloMsg)
			if retained {
				inner.pskIdentities = []pskIdentity{{label: []byte("hrr-ticket"), obfuscatedTicketAge: 96}}
			}

			offer, material, err := client.echPSKExtension(&echClientContext{innerHello: inner})
			if err != nil || material == nil {
				t.Fatalf("HRR identity decision failed: %v", err)
			}

			if !retained {
				if offer != nil {
					t.Fatal("a PSK dropped by HRR was reintroduced")
				}
			} else {
				if offer == nil || offer.Id != extensionPreSharedKey || !bytes.Contains(offer.Data, []byte("hrr-ticket")) || bytes.Contains(offer.Data, []byte("cached-ticket")) {
					t.Fatal("inner offer did not follow the HRR identity")
				}
			}

			if string(common.Identities[0].Label) != "cached-ticket" || common.Identities[0].ObfuscatedTicketAge != 42 {
				t.Fatal("building the HRR offer modified cached session metadata")
			}
		})
	}
}

func TestECHPSKBinderRejectsWrongPlaceholderShape(t *testing.T) {
	for name, binders := range map[string][][]byte{
		"missing":  nil,
		"short":    {make([]byte, 31)},
		"long":     {make([]byte, 33)},
		"multiple": {make([]byte, 32), make([]byte, 32)},
	} {
		t.Run(name, func(t *testing.T) {
			common := echPSKTestCommon()
			inner := &clientHelloMsg{
				vers: VersionTLS12, random: make([]byte, 32),
				cipherSuites: []uint16{TLS_AES_128_GCM_SHA256}, compressionMethods: []uint8{0},
				pskIdentities: []pskIdentity{{label: []byte("ticket")}}, pskBinders: binders,
			}
			if err := patchECHPSKBinder(inner, &common, nil); err == nil {
				t.Fatal("invalid binder placeholder was accepted")
			}

			for _, binder := range binders {
				if !bytes.Equal(binder, make([]byte, len(binder))) {
					t.Fatal("failed binder construction partially overwrote the placeholder")
				}
			}
		})
	}
}
