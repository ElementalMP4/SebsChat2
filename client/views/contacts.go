package views

import (
	"encoding/json"
	"fmt"
	"io"
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
	return container.NewVBox(
		utils.MakeHeaderLabel("Contacts"),
		content,
	)
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
							if cc.Name == sorted[i].Name {
								globals.Contacts = append(globals.Contacts[:j], globals.Contacts[j+1:]...)
								break
							}
						}
					} else if updated != nil {
						for j, cc := range globals.Contacts {
							if cc.Name == sorted[i].Name {
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
	x25519Entry := widget.NewMultiLineEntry()
	x25519Entry.SetPlaceHolder("X25519 Public Key (base64)")
	kyberEntry := widget.NewMultiLineEntry()
	kyberEntry.SetPlaceHolder("Kyber768 Public Key (base64)")
	ed25519Entry := widget.NewMultiLineEntry()
	ed25519Entry.SetPlaceHolder("Ed25519 Public Key (base64)")
	mldsaEntry := widget.NewMultiLineEntry()
	mldsaEntry.SetPlaceHolder("MLDSA65 Public Key (base64)")

	importBtn := widget.NewButton("Import from File", func() {
		dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, win)
				return
			}
			if reader == nil {
				return
			}
			defer reader.Close()
			data, err := io.ReadAll(reader)
			if err != nil {
				dialog.ShowError(fmt.Errorf("failed to read file: %v", err), win)
				return
			}
			var imported types.KeyExchange
			if err := json.Unmarshal(data, &imported); err != nil {
				dialog.ShowError(fmt.Errorf("invalid contact file: %v", err), win)
				return
			}
			nameEntry.SetText(imported.From)
			x25519Entry.SetText(imported.Keys.X25519Pub)
			kyberEntry.SetText(imported.Keys.PQKemPub)
			ed25519Entry.SetText(imported.Keys.EdPub)
			mldsaEntry.SetText(imported.Keys.PQSignPub)
		}, win).Show()
	})

	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("Name", nameEntry),
			widget.NewFormItem("X25519", x25519Entry),
			widget.NewFormItem("Kyber768", kyberEntry),
			widget.NewFormItem("Ed25519", ed25519Entry),
			widget.NewFormItem("MLDSA65", mldsaEntry),
		},
		OnSubmit: func() {
			if nameEntry.Text == "" || x25519Entry.Text == "" || kyberEntry.Text == "" || ed25519Entry.Text == "" || mldsaEntry.Text == "" {
				dialog.ShowError(fmt.Errorf("all fields are required"), win)
				return
			}

			onAdd(&types.Contact{
				Name: nameEntry.Text,
				Keys: types.HybridPublicKeys{
					X25519Pub: x25519Entry.Text,
					PQKemPub:  kyberEntry.Text,
					EdPub:     ed25519Entry.Text,
					PQSignPub: mldsaEntry.Text,
				},
			})
		},
		SubmitText: "Add",
	}

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
	x25519Entry := widget.NewMultiLineEntry()
	x25519Entry.SetText(contact.Keys.X25519Pub)
	kyberEntry := widget.NewMultiLineEntry()
	kyberEntry.SetText(contact.Keys.PQKemPub)
	ed25519Entry := widget.NewMultiLineEntry()
	ed25519Entry.SetText(contact.Keys.EdPub)
	mldsaEntry := widget.NewMultiLineEntry()
	mldsaEntry.SetText(contact.Keys.PQSignPub)

	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("Name", nameEntry),
			widget.NewFormItem("X25519", x25519Entry),
			widget.NewFormItem("Kyber768", kyberEntry),
			widget.NewFormItem("Ed25519", ed25519Entry),
			widget.NewFormItem("MLDSA65", mldsaEntry),
		},
		OnSubmit: func() {
			if nameEntry.Text == "" || x25519Entry.Text == "" || kyberEntry.Text == "" || ed25519Entry.Text == "" || mldsaEntry.Text == "" {
				dialog.ShowError(fmt.Errorf("all fields are required"), win)
				return
			}

			onDone(&types.Contact{
				Name: nameEntry.Text,
				Keys: types.HybridPublicKeys{
					X25519Pub: x25519Entry.Text,
					PQKemPub:  kyberEntry.Text,
					EdPub:     ed25519Entry.Text,
					PQSignPub: mldsaEntry.Text,
				},
			}, false)
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
