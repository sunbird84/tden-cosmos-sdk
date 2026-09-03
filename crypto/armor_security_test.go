package crypto_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/crypto"
)

func TestDecodeArmorRejectsCorruptOrAmbiguousInput(t *testing.T) {
	valid := crypto.EncodeArmor("TENDERMINT PUBLIC KEY", map[string]string{
		"type":    "secp256k1",
		"version": "0.0.1",
	}, []byte("public-key-material"))

	tests := map[string]string{
		"checksum mismatch": corruptArmorBody(t, valid),
		"duplicate header":  strings.Replace(valid, "version: 0.0.1", "version: 0.0.1\nversion: 0.0.1", 1),
		"wrong end type":    strings.Replace(valid, "-----END TENDERMINT PUBLIC KEY-----", "-----END TENDERMINT PRIVATE KEY-----", 1),
		"trailing block":    valid + valid,
		"oversized input":   strings.Repeat("A", (1<<20)+1),
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := crypto.DecodeArmor(input)
			require.Error(t, err)
		})
	}
}

func TestDecodeArmorPreservesCompatibleLineEndingsAndOptionalChecksum(t *testing.T) {
	data := []byte("public-key-material")
	valid := crypto.EncodeArmor("TENDERMINT PUBLIC KEY", map[string]string{
		"type":    "secp256k1",
		"version": "0.0.1",
	}, data)

	withoutChecksum := removeArmorChecksum(t, valid)
	for name, input := range map[string]string{
		"CRLF":              strings.ReplaceAll(valid, "\n", "\r\n"),
		"optional checksum": withoutChecksum,
	} {
		t.Run(name, func(t *testing.T) {
			blockType, headers, decoded, err := crypto.DecodeArmor(input)
			require.NoError(t, err)
			require.Equal(t, "TENDERMINT PUBLIC KEY", blockType)
			require.Equal(t, "0.0.1", headers["version"])
			require.Equal(t, data, decoded)
		})
	}
}

func FuzzDecodeArmorNeverPanics(f *testing.F) {
	f.Add(crypto.EncodeArmor("TENDERMINT PUBLIC KEY", map[string]string{"version": "0.0.1"}, []byte("seed")))
	f.Add("-----BEGIN TENDERMINT PUBLIC KEY-----\n\nAA==\n=AAAA\n-----END TENDERMINT PUBLIC KEY-----")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		_, _, _, _ = crypto.DecodeArmor(input)
	})
}

func removeArmorChecksum(t *testing.T, armored string) string {
	t.Helper()
	lines := strings.Split(armored, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "=") {
			return strings.Join(append(lines[:i], lines[i+1:]...), "\n")
		}
	}
	t.Fatal("generated armor did not contain a checksum")
	return ""
}

func corruptArmorBody(t *testing.T, armored string) string {
	t.Helper()
	lines := strings.Split(armored, "\n")
	inBody := false
	for i, line := range lines {
		if line == "" {
			inBody = true
			continue
		}
		if inBody && !strings.HasPrefix(line, "=") && !strings.HasPrefix(line, "-----END ") {
			first := byte('A')
			if line[0] == first {
				first = 'B'
			}
			lines[i] = string(first) + line[1:]
			return strings.Join(lines, "\n")
		}
	}
	t.Fatal("generated armor did not contain a body")
	return ""
}
