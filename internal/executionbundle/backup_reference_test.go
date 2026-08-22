package executionbundle

import "testing"

func TestAssemblerBindsConcreteBackupReferenceIntoImmutableManifest(t *testing.T) {
	a, err := NewAssembler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	in := baseInput()
	in.BackupRequired = true
	in.BackupRef = "backup_core_immediate"

	first, err := a.Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(first)
	if err != nil {
		t.Fatal(err)
	}
	if verified.BackupRef != in.BackupRef {
		t.Fatalf("verified backup ref=%q want=%q", verified.BackupRef, in.BackupRef)
	}

	in.BackupRef = "backup_core_other"
	second, err := a.Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || first.SHA256 == second.SHA256 {
		t.Fatal("concrete backup reference was not part of immutable bundle identity")
	}
}
