package inspection

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/kubev2v/vm-migration-detective/internal/cmdbuilder"
	"github.com/kubev2v/vm-migration-detective/pkg/types"
	"github.com/sirupsen/logrus"
)

// VirtV2vInspector runs virt-v2v-inspector against read-only NBD exports.
// nbdkit owns VMware transport details; virt-v2v-inspector only sees disks.
type VirtV2vInspector struct {
	virtV2vInspectorPath string
	timeout              time.Duration
	logger               *logrus.Logger
}

// NewVirtV2vInspector creates a new VirtV2vInspector instance.
func NewVirtV2vInspector(virtV2vInspectorPath string, timeout time.Duration, logger *logrus.Logger) *VirtV2vInspector {
	if virtV2vInspectorPath == "" {
		virtV2vInspectorPath = "virt-v2v-inspector"
	}
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	return &VirtV2vInspector{
		virtV2vInspectorPath: virtV2vInspectorPath,
		timeout:              timeout,
		logger:               logger,
	}
}

// Inspect runs virt-v2v-inspector against all disks in the requested snapshot.
// Each disk is exported by nbdkit so the same VDDK/NFC selection is used by
// both inspection tools.
func (i *VirtV2vInspector) Inspect(
	ctx context.Context,
	vmMoref string,
	snapshotMoref string,
	vcenterURL string,
	username string,
	password string,
	diskInfo *types.SnapshotDiskInfo,
	_ string,
) (*types.VirtV2VInspectorXML, error) {
	if diskInfo == nil {
		return nil, fmt.Errorf("snapshot disk info is required")
	}
	if vmMoref == "" {
		vmMoref = diskInfo.VMMoref
	}
	if snapshotMoref == "" {
		snapshotMoref = diskInfo.SnapshotMoref
	}
	if vmMoref == "" || snapshotMoref == "" {
		return nil, fmt.Errorf("VM and snapshot morefs are required")
	}

	baseDiskPaths, err := queryBaseDiskPaths(ctx, vcenterURL, username, password, vmMoref, i.logger)
	if err != nil {
		return nil, err
	}
	if len(baseDiskPaths) == 0 {
		return nil, fmt.Errorf("no base disks found for VM %s", vmMoref)
	}

	openCtx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()

	sessions := make([]*NBDKitSession, 0, len(baseDiskPaths))
	nbdURLs := make([]string, 0, len(baseDiskPaths))
	defer func() {
		for _, session := range sessions {
			session.Close()
		}
	}()

	for index, baseDiskPath := range baseDiskPaths {
		session, openErr := OpenWithNBDKitVDDK(
			openCtx,
			vmMoref,
			snapshotMoref,
			baseDiskPath,
			vcenterURL,
			username,
			password,
			i.logger,
		)
		if openErr != nil {
			return nil, fmt.Errorf("failed to start NBD session for disk %d: %w", index, openErr)
		}
		sessions = append(sessions, session)
		if readyErr := session.WaitForReady(30 * time.Second); readyErr != nil {
			return nil, fmt.Errorf("NBD session for disk %d was not ready: %w", index, readyErr)
		}
		nbdURLs = append(nbdURLs, session.NBDURL)
	}

	if i.logger != nil {
		i.logger.WithFields(logrus.Fields{
			"vm_moref":   vmMoref,
			"snapshot":   snapshotMoref,
			"disk_count": len(nbdURLs),
		}).Info("Running virt-v2v-inspector on NBD exports")
	}

	inspectCtx, cancelInspect := context.WithTimeout(ctx, i.timeout)
	defer cancelInspect()

	diskUnlock := resolveDiskUnlock(i.logger)
	args := cmdbuilder.New().
		WithLogger(i.logger).
		UnsetEnv("LD_LIBRARY_PATH").
		SetEnv("LIBGUESTFS_DEBUG", "1").
		Add("-v", "-x").
		Flag("-i", "disk").
		Flag("-if", "raw")
	if unlockArgs := diskUnlock.Args(); len(unlockArgs) > 0 {
		args.Add(unlockArgs...)
	}
	args.Add("--")
	args.Add(nbdURLs...)

	stdout, stderr, runErr := args.RunSeparate(inspectCtx, i.virtV2vInspectorPath)
	if inspectCtx.Err() != nil {
		if inspectCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("virt-v2v-inspector command timed out after %v", i.timeout)
		}
		return nil, fmt.Errorf("virt-v2v-inspector command was cancelled: %w", inspectCtx.Err())
	}

	if len(stderr) > 0 && i.logger != nil {
		i.logger.WithField("stderr", string(stderr)).Debug("virt-v2v-inspector stderr output")
	}
	if runErr != nil {
		output := string(stdout) + string(stderr)
		return nil, i.inspectorError(runErr, output, args, diskUnlock)
	}

	result, err := parseV2VInspectionXML(extractV2VXML(stdout))
	if err != nil {
		return nil, fmt.Errorf("failed to parse virt-v2v-inspector output: %w", err)
	}
	return result, nil
}

func (i *VirtV2vInspector) inspectorError(err error, output string, args *cmdbuilder.CmdBuilder, diskUnlock diskUnlockInfo) error {
	exitCode := cmdbuilder.ExitCode(err)
	if encrypted, reason := isEncryptedDiskError(output); encrypted {
		if i.logger != nil {
			i.logger.WithFields(logrus.Fields{
				"exit_code":       exitCode,
				"args":            args.MaskedArgs(),
				"matched_pattern": reason,
			}).Error("virt-v2v-inspector failed - disk appears to be encrypted")
		}
		switch diskUnlock.method {
		case unlockClevis:
			return fmt.Errorf("disk encryption detected: virt-v2v-inspector could not unlock disk using clevis/NBDE. Exit code: %d", exitCode)
		case unlockKeyFiles:
			return fmt.Errorf("disk encryption detected: virt-v2v-inspector could not unlock disk using %d LUKS key file(s) from %s. Exit code: %d", len(diskUnlock.keys), defaultLUKSKeyDir, exitCode)
		default:
			return fmt.Errorf("disk encryption detected: virt-v2v-inspector cannot access encrypted disks. Exit code: %d", exitCode)
		}
	}
	if i.logger != nil {
		i.logger.WithFields(logrus.Fields{
			"exit_code": exitCode,
			"args":      args.MaskedArgs(),
		}).Error("virt-v2v-inspector failed")
	}
	if output != "" {
		return fmt.Errorf("virt-v2v-inspector failed (exit code %d): %w\nOutput: %s", exitCode, err, output)
	}
	return fmt.Errorf("virt-v2v-inspector failed (exit code %d): %w", exitCode, err)
}

func extractV2VXML(output []byte) []byte {
	text := string(output)
	start := strings.Index(text, "<?xml")
	if start == -1 {
		start = strings.Index(text, "<v2v-inspection")
	}
	if start == -1 {
		start = strings.Index(text, "<operatingsystem")
	}
	if start == -1 {
		return output
	}

	xmlText := text[start:]
	for _, closingTag := range []string{"</v2v-inspection>", "</operatingsystem>"} {
		if end := strings.LastIndex(xmlText, closingTag); end >= 0 {
			return []byte(xmlText[:end+len(closingTag)])
		}
	}
	return []byte(xmlText)
}

func parseV2VInspectionXML(xmlData []byte) (*types.VirtV2VInspectorXML, error) {
	var result types.VirtV2VInspectorXML
	if err := xml.Unmarshal(xmlData, &result); err != nil {
		return nil, fmt.Errorf("XML parsing error: %w", err)
	}
	return &result, nil
}
