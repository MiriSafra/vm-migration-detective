package inspection

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveNBDKitPlugin(t *testing.T) {
	vddkDir := t.TempDir()
	nfcPlugin := filepath.Join(t.TempDir(), "nbdkit-nfc-plugin.so")
	if err := os.WriteFile(nfcPlugin, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		vddkDir    string
		pluginPath string
		want       string
		wantErr    bool
	}{
		{name: "VDDK", vddkDir: vddkDir, want: "vddk"},
		{name: "NFC sidecar", vddkDir: filepath.Join(t.TempDir(), "missing"), pluginPath: nfcPlugin, want: nfcPlugin},
		{name: "neither transport", vddkDir: filepath.Join(t.TempDir(), "missing"), pluginPath: filepath.Join(t.TempDir(), "missing.so"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveNBDKitPluginFromPaths(tt.vddkDir, []string{tt.pluginPath})
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("plugin = %q, want %q", got, tt.want)
			}
		})
	}
}
