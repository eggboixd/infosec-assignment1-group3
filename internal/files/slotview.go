package files

import "strings"

// SlotView is one row of the application checklist. File is nil while the
// slot is missing.
type SlotView struct {
	Slot  Slot
	Label string
	// Types is the accepted extensions for display, for example "DOC, DOCX".
	Types string
	// Accept is the same list for the file picker's accept attribute.
	Accept string
	File   *FileView
}

// Checklist is the data behind the application documents page.
type Checklist struct {
	Slots []SlotView
	// Others holds files with no slot (uploaded before slots existed) and
	// extra files in an already filled slot, so every file stays visible
	// and deletable.
	Others   []FileView
	Uploaded int
	Total    int
}

// BuildChecklist places files (newest first, as List returns them) into the
// application slots. The newest file of a slot fills it; older ones go to
// Others.
func BuildChecklist(files []FileView) Checklist {
	cl := Checklist{Total: len(slots)}
	filled := map[Slot]*FileView{}
	for i := range files {
		f := files[i]
		if _, ok := filled[f.Slot]; f.Slot == "" || ok || !validSlot(f.Slot) {
			cl.Others = append(cl.Others, f)
			continue
		}
		filled[f.Slot] = &files[i]
	}
	for _, si := range slots {
		exts := make([]string, len(si.Exts))
		for i, e := range si.Exts {
			exts[i] = strings.ToUpper(strings.TrimPrefix(e, "."))
		}
		sv := SlotView{
			Slot:   si.Slot,
			Label:  si.Label,
			Types:  strings.Join(exts, ", "),
			Accept: strings.Join(si.Exts, ","),
			File:   filled[si.Slot],
		}
		if sv.File != nil {
			cl.Uploaded++
		}
		cl.Slots = append(cl.Slots, sv)
	}
	return cl
}

func validSlot(s Slot) bool {
	_, err := ParseSlot(string(s))
	return err == nil
}
