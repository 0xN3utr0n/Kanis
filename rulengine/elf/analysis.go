// Copyright (C) 2020-2021,  0xN3utr0n

// Kanis is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Kanis is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Kanis. If not, see <http://www.gnu.org/licenses/>.

package elf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"math"
)

// StaticallyLinked reports whether the specified executable is a
// suspicious statically-linked ELF binary.
func (bin *Elf) StaticallyLinked() bool {
	if len(bin.Fd.Progs) < 4 {
		return true
	}

	ftype := bin.Fd.FileHeader.Type
	seg := bin.Fd.Progs[1].ProgHeader.Type

	if ftype != elf.ET_EXEC || seg == elf.PT_INTERP {
		return false
	}

	if len(bin.Fd.Sections) == 0 {
		return true
	}

	switch bin.Fd.FileHeader.Class {
	case elf.ELFCLASS64:
		if bin.Fd.FileHeader.Entry < 0x400000 {
			return true
		}
	case elf.ELFCLASS32:
		if bin.Fd.FileHeader.Entry < 0x8048000 {
			return true
		}
	}

	note := bin.getSegment(elf.PT_NOTE, elf.PF_R)
	if note == nil {
		return true
	}

	rwx := bin.getSegment(elf.PT_LOAD, (elf.PF_W | elf.PF_X))
	if rwx != nil {
		return true
	}

	return false
}

func (bin *Elf) DinamicallyLinked() bool {
	dyn := bin.getSegment(elf.PT_DYNAMIC, (elf.PF_R | elf.PF_W))
	if dyn == nil {
		return false
	}

	seg := bin.Fd.Progs[1].ProgHeader.Type
	if seg != elf.PT_INTERP {
		return true
	}

	if len(bin.Fd.Sections) == 0 {
		return true
	}

	note := bin.getSegment(elf.PT_NOTE, elf.PF_R)
	if note == nil {
		return true
	}

	rwx := bin.getSegment(elf.PT_LOAD, (elf.PF_W | elf.PF_X))
	if rwx != nil {
		return true
	}

	return false
}

// DetectControlFlowHijacking Detects if the given memory address
// points to any suspicious or unusual section.
func (bin *Elf) DetectControlFlowHijacking(addr uint64) bool {
	var myseg *elf.Prog

	// Get segment pointed by @addr
	for _, p := range bin.Fd.Progs {
		if p.Type == elf.PT_LOAD {
			if p.Vaddr <= addr &&
				(p.Vaddr+p.Memsz) >= addr {
				myseg = p
				break
			}
		}
	}

	// Does it point to a RWX segment?
	if myseg.Flags&elf.PF_W != 0 {
		return true
	}

	// Does it not point to the first TEXT segment?
	text := bin.getSegment(elf.PT_LOAD, (elf.PF_X | elf.PF_R))
	if text != nil && text.Vaddr != myseg.Vaddr {
		return true
	}

	// Does it not point to the text section?
	sec := bin.Fd.Section(".text")
	if addr < sec.Addr || addr > (sec.Addr+sec.Size) {
		return true
	}

	return false
}

func (bin *Elf) getSegment(typef elf.ProgType, priv elf.ProgFlag) *elf.Prog {
	var first *elf.Prog

	for _, p := range bin.Fd.Progs {
		if p.Type == typef && ((p.Flags & priv) == priv) {
			if first == nil || (first.Vaddr > p.Vaddr) {
				first = p
			}
		}
	}

	return first
}

// getDynEntry64 Retrieves the value within the given
// PT_DYNAMIC segment entry.
func (bin *Elf) getDynEntry64(flag elf.DynTag) uint64 {
	dyn := bin.getSegment(elf.PT_DYNAMIC, (elf.PF_R | elf.PF_W))
	if dyn == nil {
		return 0
	}

	buf := make([]byte, dyn.Filesz)

	len, err := dyn.ReadAt(buf, 0)
	if err != nil {
		return 0
	}

	var entry elf.Dyn64
	buffer := &bytes.Buffer{}
	for i := 0; i < len; i += 16 {
		err = binary.Write(buffer, binary.LittleEndian, buf[i:(i+16)])
		if err != nil {
			return 0
		}
		err = binary.Read(buffer, binary.LittleEndian, &entry)
		if err != nil {
			return 0
		}

		if entry.Tag == int64(elf.DT_NULL) {
			return 0
		} else if entry.Tag == int64(flag) {
			return entry.Val
		}
	}

	return 0
}

// GetInitArray Retrieves all the memory addresses located within
// the InitArray section.
func (bin *Elf) GetInitArray() []uint64 {
	elements := bin.getDynEntry64(elf.DT_INIT_ARRAYSZ)
	init := bin.Fd.Section(".init_array")
	if init == nil || elements == 0 {
		return nil
	}

	buf := make([]byte, init.Size)

	len, err := init.ReadAt(buf, 0)
	if err != nil {
		return nil
	}

	var (
		wordSize int
		addr     uint64
	)

	if bin.Fd.FileHeader.Class == elf.ELFCLASS64 {
		wordSize = 8
	} else {
		wordSize = 4
	}

	array := make([]uint64, 0)
	buffer := &bytes.Buffer{}

	for i := 0; i/wordSize < int(elements) && i < len; i += wordSize {
		err = binary.Write(buffer, binary.LittleEndian, buf[i:(i+wordSize)])
		if err != nil {
			return nil
		}
		err = binary.Read(buffer, binary.LittleEndian, &addr)
		if err != nil {
			return nil
		}

		array = append(array, addr)
	}

	return array
}

// PackedSegment reports if any segment from the especified ELF binary
// is packed/encrypted/compressed (Entropy higher than 6.8).
func (bin *Elf) PackedSegment() (bool, float64) {
	for _, p := range bin.Fd.Progs {
		if p.Type == elf.PT_LOAD {
			if p.Filesz > 0 {
				buf := make([]byte, p.Filesz)
				if _, err := p.ReadAt(buf, 0); err != nil {
					break
				}
				if e := dataEntropy(buf); e >= 6.8 {
					return true, e
				}
			}
		}
	}

	return false, 0
}

// dataEntropy Calculates the entropy for the given data buffer.
func dataEntropy(data []byte) float64 {
	m := map[byte]float64{}
	for _, r := range data {
		m[r]++
	}

	var hm float64
	for _, c := range m {
		hm += c * math.Log2(c)
	}

	l := float64(len(data))
	return (math.Log2(l) - hm/l)
}
