package cfaws

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/fwdcloudsec/granted/internal/build"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssumeNonSSOProfiles(t *testing.T) {
	fixture := t.TempDir()
	t.Setenv("HOME", fixture)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	t.Setenv("CF_KEYRING_FILE_PASSWORD", "test-password")
	configDir := filepath.Join(fixture, build.ConfigFolderName)
	require.NoError(t, os.MkdirAll(configDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "config"), []byte("[Keyring]\nBackend = 'file'\n"), 0600))
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "AssumeRole", r.Form.Get("Action"))
		assert.Equal(t, "arn:aws:iam::123456789012:role/ReadOnly", r.Form.Get("RoleArn"))
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>role-access</AccessKeyId><SecretAccessKey>role-secret</SecretAccessKey><SessionToken>role-session</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/ReadOnly/test</Arn><AssumedRoleId>role:test</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	}))
	defer sts.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", sts.URL)
	writeSharedConfig(t, `[profile static]
region = ap-southeast-2
aws_access_key_id = static-access
aws_secret_access_key = static-secret

[profile process]
region = ap-southeast-2
credential_process = printf '%s' '{"Version":1,"AccessKeyId":"process-access","SecretAccessKey":"process-secret","SessionToken":"process-session"}'

[profile role]
region = ap-southeast-2
source_profile = static
role_arn = arn:aws:iam::123456789012:role/ReadOnly
`)
	profiles, err := LoadProfiles()
	require.NoError(t, err)
	for _, tc := range []struct {
		profile string
		kind    string
		token   string
	}{
		{"static", "AWS_IAM", ""},
		{"process", "AWS_CREDENTIAL_PROCESS", "process-session"},
		{"role", "AWS_IAM", "role-session"},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			profile, err := profiles.LoadInitialisedProfile(context.Background(), tc.profile)
			require.NoError(t, err)
			assert.Equal(t, tc.kind, profile.ProfileType)
			assert.Empty(t, profile.SSOScopes())
			creds, err := profile.AssumeTerminal(context.Background(), ConfigOpts{Duration: time.Hour})
			require.NoError(t, err)
			assert.Equal(t, tc.profile+"-access", creds.AccessKeyID)
			assert.Equal(t, tc.profile+"-secret", creds.SecretAccessKey)
			assert.Equal(t, tc.token, creds.SessionToken)
			assert.Equal(t, tc.profile == "role", creds.CanExpire)
			assert.NoError(t, ExportAccessTokenToCache(context.Background(), profile))
			assert.NoDirExists(t, filepath.Join(fixture, ".aws", "sso", "cache"))
		})
	}
	t.Run("SSO profile without a cached token", func(t *testing.T) {
		profile := &Profile{Name: "missing-token", AWSConfig: config.SharedConfig{SSOStartURL: "https://example.awsapps.com/start"}}
		assert.ErrorContains(t, ExportAccessTokenToCache(context.Background(), profile), "no valid SSO token")
	})
}
