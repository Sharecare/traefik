package ipallowlist

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/config/runtime"
)

type AllowListBuilder struct{}

func (b AllowListBuilder) GetConfigs() map[string]*runtime.MiddlewareInfo {
	configs := make(map[string]*runtime.MiddlewareInfo)

	allowlist := dynamic.Middleware{IPAllowList: &dynamic.IPAllowList{SourceRange: []string{"20.20.20.20"}}}
	configs["other-allowlist"] = &runtime.MiddlewareInfo{Middleware: &allowlist}
	configs["not-allowlist"] = &runtime.MiddlewareInfo{Middleware: &dynamic.Middleware{}}

	return configs
}

func TestNewIPAllowLister(t *testing.T) {
	testCases := []struct {
		desc          string
		allowList     dynamic.IPAllowList
		expectedError bool
	}{
		{
			desc: "invalid IP",
			allowList: dynamic.IPAllowList{
				SourceRange: []string{"foo"},
			},
			expectedError: true,
		},
		{
			desc: "non-existent append allowlist",
			allowList: dynamic.IPAllowList{
				AppendAllowLists: []string{"bad-allowlist"},
			},
			expectedError: true,
		},
		{
			desc: "invalid append allowlist",
			allowList: dynamic.IPAllowList{
				AppendAllowLists: []string{"not-allowlist"},
			},
			expectedError: true,
		},
		{
			desc: "valid IP",
			allowList: dynamic.IPAllowList{
				SourceRange: []string{"10.10.10.10"},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
			allowLister, err := New(t.Context(), next, test.allowList, AllowListBuilder{}, "traefikTest")

			if test.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, allowLister)
			}
		})
	}
}

func TestIPAllowLister_ServeHTTP(t *testing.T) {
	testCases := []struct {
		desc       string
		allowList  dynamic.IPAllowList
		remoteAddr string
		expected   int
	}{
		{
			desc: "authorized with remote address",
			allowList: dynamic.IPAllowList{
				SourceRange: []string{"20.20.20.20"},
			},
			remoteAddr: "20.20.20.20:1234",
			expected:   200,
		},
		{
			desc: "authorized with append allowlist",
			allowList: dynamic.IPAllowList{
				AppendAllowLists: []string{"other-allowlist"},
			},
			remoteAddr: "20.20.20.20:1234",
			expected:   200,
		},
		{
			desc: "non authorized with remote address",
			allowList: dynamic.IPAllowList{
				SourceRange: []string{"20.20.20.20"},
			},
			remoteAddr: "20.20.20.21:1234",
			expected:   403,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
			allowLister, err := New(t.Context(), next, test.allowList, AllowListBuilder{}, "traefikTest")
			require.NoError(t, err)

			recorder := httptest.NewRecorder()

			req := httptest.NewRequest(http.MethodGet, "http://10.10.10.10", nil)

			if len(test.remoteAddr) > 0 {
				req.RemoteAddr = test.remoteAddr
			}

			allowLister.ServeHTTP(recorder, req)

			assert.Equal(t, test.expected, recorder.Code)
		})
	}
}
