// Code generated by bpf2go; DO NOT EDIT.
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadFiletop returns the embedded CollectionSpec for filetop.
func loadFiletop() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_FiletopBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load filetop: %w", err)
	}

	return spec, err
}

// loadFiletopObjects loads filetop and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *filetopObjects
//     *filetopPrograms
//     *filetopMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadFiletopObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadFiletop()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// filetopSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type filetopSpecs struct {
	filetopProgramSpecs
	filetopMapSpecs
}

// filetopSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type filetopProgramSpecs struct {
	VfsReadEntry  *ebpf.ProgramSpec `ebpf:"vfs_read_entry"`
	VfsWriteEntry *ebpf.ProgramSpec `ebpf:"vfs_write_entry"`
}

// filetopMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type filetopMapSpecs struct {
	Entries    *ebpf.MapSpec `ebpf:"entries"`
	MountNsSet *ebpf.MapSpec `ebpf:"mount_ns_set"`
}

// filetopObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadFiletopObjects or ebpf.CollectionSpec.LoadAndAssign.
type filetopObjects struct {
	filetopPrograms
	filetopMaps
}

func (o *filetopObjects) Close() error {
	return _FiletopClose(
		&o.filetopPrograms,
		&o.filetopMaps,
	)
}

// filetopMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadFiletopObjects or ebpf.CollectionSpec.LoadAndAssign.
type filetopMaps struct {
	Entries    *ebpf.Map `ebpf:"entries"`
	MountNsSet *ebpf.Map `ebpf:"mount_ns_set"`
}

func (m *filetopMaps) Close() error {
	return _FiletopClose(
		m.Entries,
		m.MountNsSet,
	)
}

// filetopPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadFiletopObjects or ebpf.CollectionSpec.LoadAndAssign.
type filetopPrograms struct {
	VfsReadEntry  *ebpf.Program `ebpf:"vfs_read_entry"`
	VfsWriteEntry *ebpf.Program `ebpf:"vfs_write_entry"`
}

func (p *filetopPrograms) Close() error {
	return _FiletopClose(
		p.VfsReadEntry,
		p.VfsWriteEntry,
	)
}

func _FiletopClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed filetop_bpfeb.o
var _FiletopBytes []byte
