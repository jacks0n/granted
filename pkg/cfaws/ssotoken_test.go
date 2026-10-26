package cfaws

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExportSSOTokenCache(t *testing.T) {
	for _, refreshable := range []bool{false, true} {
		name := "legacy"
		if refreshable {
			name = "refreshable session"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			cfg := config.SharedConfig{SSOStartURL: "https://example.awsapps.com/start", SSORegion: "ap-southeast-2"}
			token := securestorage.SSOToken{AccessToken: "access", Expiry: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)}
			want := map[string]string{
				"accessToken": "access", "expiresAt": "2026-10-26T12:00:00Z",
				"ssoSessionName": "", "startUrl": cfg.SSOStartURL, "region": cfg.SSORegion,
			}
			key := cfg.SSOStartURL
			if refreshable {
				cfg.SSOStartURL, cfg.SSORegion = "", ""
				cfg.SSOSessionName = "work"
				cfg.SSOSession = &config.SSOSession{Name: "work", SSOStartURL: want["startUrl"], SSORegion: want["region"]}
				refresh := "refresh"
				token.RefreshToken, token.ClientID, token.ClientSecret = &refresh, "client", "secret"
				token.RegistrationExpiresAt = token.Expiry.Add(24 * time.Hour)
				want["ssoSessionName"], key = "work", "work"
				want["refreshToken"], want["clientId"], want["clientSecret"] = refresh, "client", "secret"
				want["registrationExpiresAt"] = "2026-10-27T12:00:00Z"
			}
			require.NoError(t, CreatePlainTextSSO(cfg, &token).DumpToCacheDirectory())
			filename, err := getCacheFileName(key)
			require.NoError(t, err)
			cacheFile := filepath.Join(os.Getenv("HOME"), ".aws", "sso", "cache", filename)
			data, err := os.ReadFile(cacheFile)
			require.NoError(t, err)
			var got map[string]string
			require.NoError(t, json.Unmarshal(data, &got))
			assert.Equal(t, want, got)
			info, err := os.Stat(cacheFile)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
		})
	}
}
