package views

import (
	"encoding/json"
	"fmt"
	"sebschat/globals"
	"sebschat/types"
	"sebschat/utils"
	"sort"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func ContactsUI(win fyne.Window) fyne.CanvasObject {
	var content *fyne.Container = container.NewVBox()
	showContactList(content, win)
	return content
}

func showContactList(content *fyne.Container, win fyne.Window) {
	listContainer := container.NewVBox()
	sorted := make([]types.Contact, len(globals.Contacts))
	copy(sorted, globals.Contacts)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	for idx, c := range sorted {
		i := idx
		contactBtn := widget.NewButton(c.Name, func() {
			content.Objects = []fyne.CanvasObject{
				editContactForm(win, &sorted[i], func(updated *types.Contact, deleted bool) {
					if deleted {
						for j, cc := range globals.Contacts {
							if cc.Name == sorted[i].Name && cc.PublicKey == sorted[i].PublicKey {
								globals.Contacts = append(globals.Contacts[:j], globals.Contacts[j+1:]...)
								break
							}
						}
					} else if updated != nil {
						for j, cc := range globals.Contacts {
							if cc.Name == sorted[i].Name && cc.PublicKey == sorted[i].PublicKey {
								globals.Contacts[j] = *updated
								break
							}
						}
					}
					err := utils.SaveContacts()
					if err != nil {
						dialog.ShowError(err, win)
					}
					showContactList(content, win)
				}),
			}
		})
		listContainer.Add(contactBtn)
	}

	addBtn := widget.NewButton("Add Contact", func() {
		content.Objects = []fyne.CanvasObject{addContactForm(win, func(newContact *types.Contact) {
			if newContact != nil {
				globals.Contacts = append(globals.Contacts, *newContact)
			}
			err := utils.SaveContacts()
			if err != nil {
				dialog.ShowError(err, win)
			}
			showContactList(content, win)
		}, func() {
			showContactList(content, win)
		})}
	})

	exportBtn := widget.NewButton("Export Contact", func() {
		showExportContactDialog(win)
	})

	buttonRow := container.NewGridWithColumns(2, addBtn, exportBtn)

	// I refuse to show "You have 1 contacts" or "You have 1 contact(s)"
	contactOrContacts := "contact"
	if len(sorted) != 1 {
		contactOrContacts += "s"
	}

	contactCountLabel := widget.NewLabel(fmt.Sprintf("You have %d %s", len(sorted), contactOrContacts))

	content.Objects = []fyne.CanvasObject{
		buttonRow,
		contactCountLabel,
		widget.NewSeparator(),
		listContainer,
	}
}

func showExportContactDialog(win fyne.Window) {
	fileDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, win)
			return
		}
		if writer == nil {
			return
		}
		defer writer.Close()

		kex, err := utils.ContactToJson()
		if err != nil {
			dialog.ShowError(err, win)
			return
		}

		_, wErr := writer.Write(kex)
		if wErr != nil {
			dialog.ShowError(wErr, win)
			return
		}

		dialog.ShowInformation("Export", "Contact exported successfully!", win)
	}, win)
	fileDialog.SetFileName(fmt.Sprintf("%s.imp", globals.SelfUser.Name))
	fileDialog.Show()
}

func addContactForm(win fyne.Window, onAdd func(*types.Contact), onCancel func()) fyne.CanvasObject {
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("Contact Name")
	keyEntry := widget.NewMultiLineEntry()
	keyEntry.SetPlaceHolder("Public Key")

	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("Name", nameEntry),
			widget.NewFormItem("Public Key", keyEntry),
		},
		OnSubmit: func() {
			if nameEntry.Text == "" || keyEntry.Text == "" {
				dialog.ShowError(fmt.Errorf("both fields are required"), win)
				return
			}
			onAdd(&types.Contact{Name: nameEntry.Text, PublicKey: keyEntry.Text})
		},
		SubmitText: "Add",
	}

	importBtn := widget.NewButton("Import from File", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			defer reader.Close()
			if reader.URI().Extension() != ".imp" {
				dialog.ShowError(fmt.Errorf("please select a .imp file"), win)
				return
			}
			var data types.KeyExchange
			decoder := json.NewDecoder(reader)
			if err := decoder.Decode(&data); err != nil {
				dialog.ShowError(fmt.Errorf("failed to parse file: %v", err), win)
				return
			}
			nameEntry.SetText(data.KeyFrom)
			keyEntry.SetText(data.Key)
		}, win)
	})

	cancelBtn := widget.NewButton("Cancel", func() {
		onCancel()
	})

	return container.NewVBox(
		widget.NewLabelWithStyle("Add Contact", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		form,
		importBtn,
		cancelBtn,
	)
}

func editContactForm(win fyne.Window, contact *types.Contact, onDone func(updated *types.Contact, deleted bool)) fyne.CanvasObject {
	nameEntry := widget.NewEntry()
	nameEntry.SetText(contact.Name)
	keyEntry := widget.NewMultiLineEntry()
	keyEntry.SetText(contact.PublicKey)

	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("Name", nameEntry),
			widget.NewFormItem("Public Key", keyEntry),
		},
		OnSubmit: func() {
			if nameEntry.Text == "" || keyEntry.Text == "" {
				dialog.ShowError(fmt.Errorf("both fields are required"), win)
				return
			}
			onDone(&types.Contact{Name: nameEntry.Text, PublicKey: keyEntry.Text}, false)
		},
		SubmitText: "Save",
	}

	deleteBtn := widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), func() {
		dialog.ShowConfirm("Delete Contact", "Are you sure you want to delete this contact?", func(confirm bool) {
			if confirm {
				onDone(nil, true)
			}
		}, win)
	})

	cancelBtn := widget.NewButton("Cancel", func() {
		onDone(nil, false)
	})

	return container.NewVBox(
		widget.NewLabelWithStyle("Edit Contact", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		form,
		deleteBtn,
		cancelBtn,
	)
}
