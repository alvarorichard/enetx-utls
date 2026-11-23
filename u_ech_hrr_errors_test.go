package tls

import (
	"context"
	"errors"
	"testing"
	"time"
)

type echFailingKeyLog struct {
	calls int
	err   error
}

func (w *echFailingKeyLog) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 2 {
		return 0, w.err
	}

	return len(p), nil
}

func TestCustomECHHelloRetryRequestPreservesFailureCause(t *testing.T) {
	for _, stage := range []string{"inner-policy", "inner-key-log"} {
		t.Run(stage, func(t *testing.T) {
			sentinel := errors.New("ECH HRR construction failed")
			cfg, key := innerTestConfigPair(t)
			cfg.ServerName = testConfigClient.ServerName
			cfg.RootCAs = testRootCertPool
			cfg.Time = testTime
			calls := 0
			cfg.ECHClientHelloInner = func(info ECHClientHelloInfo) (*ECHClientHelloSpec, error) {
				calls++
				if stage == "inner-policy" && calls == 2 {
					return nil, sentinel
				}

				return innerTestPolicy(info)
			}
			keyLog := &echFailingKeyLog{err: sentinel}
			if stage == "inner-key-log" {
				cfg.KeyLogWriter = keyLog
			}

			serverConfig := testConfigServer.Clone()
			serverConfig.MinVersion = VersionTLS13
			serverConfig.NextProtos = []string{"h2"}
			serverConfig.CurvePreferences = []CurveID{CurveP384}
			serverConfig.EncryptedClientHelloKeys = []EncryptedClientHelloKey{key}
			a, b := localPipe(t)
			defer a.Close()
			defer b.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				defer a.Close()
				done <- Server(a, serverConfig).HandshakeContext(ctx)
			}()

			client := UClient(b, cfg, HelloCustom)
			spec := innerTestSpec()
			spec.Extensions[1].(*SupportedCurvesExtension).Curves = []CurveID{X25519, CurveP384}
			if err := client.ApplyPreset(spec); err != nil {
				t.Fatal(err)
			}

			err := client.HandshakeContext(ctx)
			b.Close()
			cancel()
			<-done
			if !errors.Is(err, sentinel) || calls != 2 || client.ConnectionState().HandshakeComplete {
				t.Fatalf("HRR failure lost its cause or completed TLS: calls=%d err=%v", calls, err)
			}

			if stage == "inner-key-log" && keyLog.calls != 2 {
				t.Fatalf("failure did not occur on the replacement inner: writes=%d", keyLog.calls)
			}
		})
	}
}
