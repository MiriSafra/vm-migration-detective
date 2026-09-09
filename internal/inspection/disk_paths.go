package inspection

import (
	"context"
	"fmt"

	"github.com/kubev2v/vm-migration-detective/internal/vsphere"
	"github.com/sirupsen/logrus"
)

// queryBaseDiskPaths resolves every VM disk to its base VMDK. nbdkit receives
// the base path together with the VM and snapshot morefs, so it can serve the
// correct point-in-time view through either VDDK or NFC.
func queryBaseDiskPaths(ctx context.Context, vcenterURL, username, password, vmMoref string, logger *logrus.Logger) ([]string, error) {
	client, err := vsphere.NewClient(ctx, vcenterURL, username, password, true, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to vSphere: %w", err)
	}
	defer client.Close()

	paths, err := client.GetBaseDiskPaths(ctx, vmMoref)
	if err != nil {
		return nil, fmt.Errorf("failed to get base disk paths: %w", err)
	}
	return paths, nil
}
