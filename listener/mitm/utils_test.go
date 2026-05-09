package mitm

import "testing"

func TestIsHTTPTraffic(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		want bool
	}{
		{"empty", []byte{}, false},
		{"GET with space", []byte("GET / H"), true},
		{"POST with space", []byte("POST /"), true},
		// Methods whose length matches the peek window leave no trailing
		// space — must still be recognised as HTTP.
		{"OPTIONS no space", []byte("OPTIONS"), true},
		{"CONNECT no space", []byte("CONNECT"), true},
		{"unknown no space", []byte("HELLOXX"), false},
		{"unknown with space", []byte("HELLO /"), false},
		{"TLS handshake byte", []byte{0x16, 0x03, 0x01, 0x00, 0x05}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isHTTPTraffic(tc.buf); got != tc.want {
				t.Errorf("isHTTPTraffic(%q) = %v, want %v", tc.buf, got, tc.want)
			}
		})
	}
}
