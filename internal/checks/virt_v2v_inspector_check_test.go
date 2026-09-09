package checks

import (
	"context"
	"errors"
	"testing"

	"github.com/kubev2v/vm-migration-detective/pkg/types"
)

type fakeVirtV2VInspector struct {
	err       error
	called    bool
	sslVerify string
}

func (f *fakeVirtV2VInspector) InspectWithVirt(context.Context, string, string, *types.SnapshotDiskInfo) (*types.VirtInspectorXML, error) {
	return nil, nil
}

func (f *fakeVirtV2VInspector) InspectWithVirtV2v(_ context.Context, _ string, _ string, _ *types.SnapshotDiskInfo, sslVerify string) (*types.VirtV2VInspectorXML, error) {
	f.called = true
	f.sslVerify = sslVerify
	return nil, f.err
}

func (f *fakeVirtV2VInspector) InspectLocal(context.Context, []string) (*types.VirtInspectorXML, error) {
	return nil, nil
}

func (f *fakeVirtV2VInspector) GetDB() types.DB { return nil }

func TestVirtV2VInspectorCheck(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		wantPassed    bool
		wantConcernID string
	}{
		{name: "passes", wantPassed: true},
		{name: "reports critical concern", err: errors.New("inspection failed"), wantConcernID: "virt-v2v-inspector-failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inspector := &fakeVirtV2VInspector{err: tt.err}
			result := NewVirtV2VInspectorCheck().Run(InspectionParams{
				Ctx:           context.Background(),
				VMMoref:       "vm-1",
				SnapshotMoref: "snapshot-1",
				Inspector:     inspector,
			})

			if result.Passed != tt.wantPassed {
				t.Fatalf("Passed = %v, want %v", result.Passed, tt.wantPassed)
			}
			if tt.wantConcernID == "" {
				if len(result.Concerns) != 0 {
					t.Fatalf("Concerns = %#v, want none", result.Concerns)
				}
			} else if len(result.Concerns) != 1 || result.Concerns[0].ID != tt.wantConcernID {
				t.Fatalf("Concerns = %#v, want concern %q", result.Concerns, tt.wantConcernID)
			}
			if !inspector.called || inspector.sslVerify != "no_verify=1" {
				t.Fatalf("inspector call = called:%v sslVerify:%q", inspector.called, inspector.sslVerify)
			}
		})
	}
}
