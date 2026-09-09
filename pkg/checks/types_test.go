package checks

import "testing"

func TestAllCheckTypesRunsVirtV2VInspectorLast(t *testing.T) {
	want := []CheckType{
		CheckTypeFstab,
		CheckTypeDiskAccess,
		CheckTypeVirtV2VInspector,
	}
	got := AllCheckTypes()

	if len(got) != len(want) {
		t.Fatalf("AllCheckTypes() length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("AllCheckTypes()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
