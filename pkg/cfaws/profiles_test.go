package cfaws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSORegistrationScopes(t *testing.T) {
	writeSharedConfig(t, `[sso-session work]
sso_start_url = https://example.awsapps.com/start
sso_region = ap-southeast-2
sso_registration_scopes = sso:account:access

[profile session]
sso_session = work
sso_account_id = 123456789012
sso_role_name = ReadOnly

[profile legacy]
sso_start_url = https://example.awsapps.com/start
sso_region = ap-southeast-2
sso_account_id = 123456789012
sso_role_name = ReadOnly
`)
	profiles, err := LoadProfiles()
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"session", []string{"sso:account:access"}},
		{"legacy", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := profiles.LoadInitialisedProfile(context.Background(), tc.name)
			require.NoError(t, err)
			assert.Equal(t, tc.want, profile.SSOScopes())
		})
	}
}
