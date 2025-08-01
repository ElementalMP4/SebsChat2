package views

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sebschat/globals"
	"sebschat/net"
	"sebschat/types"
	"sebschat/utils"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/atotto/clipboard"
	"github.com/skip2/go-qrcode"
)

func AccountUI(win fyne.Window) fyne.CanvasObject {
	registerBtn := widget.NewButton("Register", func() {
		if globals.SelfUser.Server.Address == "" {
			dialog.ShowError(fmt.Errorf("server URL has not been set"), win)
			return
		}

		passwordEntry := widget.NewPasswordEntry()
		confirmEntry := widget.NewPasswordEntry()
		showPassword := widget.NewCheck("Show Passwords", func(checked bool) {
			passwordEntry.Password = !checked
			confirmEntry.Password = !checked
			passwordEntry.Refresh()
			confirmEntry.Refresh()
		})

		form := widget.NewForm(
			widget.NewFormItem("Password", passwordEntry),
			widget.NewFormItem("Confirm Password", confirmEntry),
			widget.NewFormItem("", showPassword),
		)

		dialog.ShowCustomConfirm("Register", "Register", "Cancel", form, func(confirmed bool) {
			if !confirmed {
				return
			}
			if passwordEntry.Text != confirmEntry.Text {
				dialog.ShowError(fmt.Errorf("passwords do not match"), win)
				return
			}
			if passwordEntry.Text == "" {
				dialog.ShowError(fmt.Errorf("password cannot be empty"), win)
				return
			}

			body := types.RegisterRequest{
				Username: globals.SelfUser.Name,
				Password: passwordEntry.Text,
			}
			jsonBody, err := json.Marshal(body)
			if err != nil {
				dialog.ShowError(fmt.Errorf("failed to encode request: %v", err), win)
				return
			}

			req, err := http.NewRequest("POST", globals.SelfUser.Server.GetApiAddress()+"/api/register", bytes.NewReader(jsonBody))
			if err != nil {
				dialog.ShowError(fmt.Errorf("failed to create request: %v", err), win)
				return
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := net.PerformRequest(req)
			if err != nil {
				dialog.ShowError(fmt.Errorf("registration failed: %v", err), win)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				dialog.ShowError(fmt.Errorf("registration failed: %s", resp.Status), win)
				return
			}

			var result types.RegisterResponse
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				dialog.ShowError(fmt.Errorf("failed to decode server response: %v", err), win)
				return
			}

			// Construct TOTP URL
			totpURL := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=SebsChat", globals.SelfUser.Name, result.TOTPSecret)

			// Generate QR code
			qr, err := qrcode.New(totpURL, qrcode.Medium)
			if err != nil {
				dialog.ShowError(fmt.Errorf("failed to generate QR code: %v", err), win)
				return
			}

			qrPng, err := qr.PNG(512)
			if err != nil {
				dialog.ShowError(fmt.Errorf("failed to convert QR code to image: %v", err), win)
				return
			}

			qrImg := canvas.NewImageFromReader(bytes.NewReader(qrPng), "qr.png")
			qrImg.FillMode = canvas.ImageFillContain
			qrImg.SetMinSize(fyne.NewSize(256, 256))

			// Copy button
			copyBtn := widget.NewButton("Copy TOTP URL", func() {
				clipboard.WriteAll(totpURL)
			})

			// Show dialog with QR code and copy button
			content := container.NewVBox(
				widget.NewLabel("Scan this QR code with your TOTP app:"),
				qrImg,
				widget.NewLabel("Or copy the URL below:"),
				copyBtn,
			)
			dialog.ShowCustom("Registration Successful", "OK", content, win)
		}, win)
	})

	loginBtn := widget.NewButton("Authenticate", func() {
		if globals.SelfUser.Server.Address == "" {
			dialog.ShowError(fmt.Errorf("server URL has not been set"), win)
			return
		}

		passwordEntry := widget.NewPasswordEntry()
		totpEntry := widget.NewEntry()
		totpEntry.SetPlaceHolder("123456")

		form := widget.NewForm(
			widget.NewFormItem("Password", passwordEntry),
			widget.NewFormItem("TOTP Code", totpEntry),
		)

		dialog.ShowCustomConfirm("Authenticate", "Authenticate", "Cancel", form, func(confirmed bool) {
			if !confirmed {
				return
			}
			if passwordEntry.Text == "" || totpEntry.Text == "" {
				dialog.ShowError(fmt.Errorf("password and TOTP code are required"), win)
				return
			}

			reqBody := types.LoginRequest{
				Username: globals.SelfUser.Name,
				Password: passwordEntry.Text,
				TOTPCode: totpEntry.Text,
			}
			jsonBody, err := json.Marshal(reqBody)
			if err != nil {
				dialog.ShowError(fmt.Errorf("failed to encode request: %v", err), win)
				return
			}

			req, err := http.NewRequest("POST", globals.SelfUser.Server.GetApiAddress()+"/api/login", bytes.NewReader(jsonBody))
			if err != nil {
				dialog.ShowError(fmt.Errorf("failed to create request: %v", err), win)
				return
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := net.PerformRequest(req)
			if err != nil {
				dialog.ShowError(fmt.Errorf("login failed: %v", err), win)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				dialog.ShowError(fmt.Errorf("login failed: %s", resp.Status), win)
				return
			}

			var result types.LoginResponse
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				dialog.ShowError(fmt.Errorf("failed to decode server response: %v", err), win)
				return
			}

			globals.SelfUser.Server.Token = result.Token
			utils.SaveUser()

			// Parse JWT expiry
			expiryMsg := "Unknown"
			type jwtClaims struct {
				Exp int64 `json:"exp"`
			}
			parts := bytes.Split([]byte(result.Token), []byte("."))
			if len(parts) == 3 {
				decodedBytes, err := utils.Base64ToBytes(string(parts[1]))
				if err == nil {
					var claims jwtClaims
					if err := json.Unmarshal(decodedBytes, &claims); err == nil && claims.Exp > 0 {
						expiry := time.Unix(claims.Exp, 0)
						expiryMsg = expiry.Format("2006-01-02 15:04:05 MST")
					}
				}
			}

			dialog.ShowInformation("Authentication Successful", fmt.Sprintf("Your authentication token will expire at:\n%s", expiryMsg), win)
		}, win)
	})

	registerBtn.Alignment = widget.ButtonAlignCenter
	loginBtn.Alignment = widget.ButtonAlignCenter

	return container.NewVBox(
		utils.MakeHeaderLabel(fmt.Sprintf("%s's Account", globals.SelfUser.Name)),
		container.NewVBox(registerBtn, loginBtn),
	)
}
