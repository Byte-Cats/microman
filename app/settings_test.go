package app_test

import (
	"testing"

	"github.com/byte-cats/microman/app"
)

func TestCheckTitle(t *testing.T) {
	cases := []struct {
		name     string
		envValue string
		setEnv   bool
		template string
		want     string
	}{
		{"env var set", "Custom Title", true, "Default Title", "Custom Title"},
		{"env var empty falls back to default", "", true, "Default Title", "Default Title"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TITLE", tc.envValue)
			api := &app.Api{}
			app.CheckTitle(api, tc.template)
			if got := api.Settings.Title; got != tc.want {
				t.Errorf("CheckTitle() Settings.Title = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCheckHostname(t *testing.T) {
	cases := []struct {
		name     string
		envValue string
		template string
		want     string
	}{
		{"env var set", "example.com", "localhost", "example.com"},
		{"env var empty falls back to default", "", "localhost", "localhost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOSTNAME", tc.envValue)
			api := &app.Api{}
			app.CheckHostname(api, tc.template)
			if got := api.Settings.Hostname; got != tc.want {
				t.Errorf("CheckHostname() Settings.Hostname = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCheckPort(t *testing.T) {
	cases := []struct {
		name     string
		envValue string
		template string
		want     string
	}{
		{"env var set", "8080", "6969", "8080"},
		{"env var empty falls back to default", "", "6969", "6969"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PORT", tc.envValue)
			api := &app.Api{}
			app.CheckPort(api, tc.template)
			if got := api.Settings.Port; got != tc.want {
				t.Errorf("CheckPort() Settings.Port = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCheckVersion(t *testing.T) {
	cases := []struct {
		name     string
		envValue string
		template string
		want     string
	}{
		{"env var set", "1.2.3", "0.420.69", "1.2.3"},
		{"env var empty falls back to default", "", "0.420.69", "0.420.69"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VERSION", tc.envValue)
			api := &app.Api{}
			app.CheckVersion(api, tc.template)
			if got := api.Settings.Version; got != tc.want {
				t.Errorf("CheckVersion() Settings.Version = %q, want %q", got, tc.want)
			}
		})
	}
}
