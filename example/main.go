package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	authon "github.com/authonpro/sdk-go"
)

func main() {
	// ============ SETUP ============
	auth := authon.New("your-app-id", "your-api-key")

	// ============ CONNECT ============
	ok, err := auth.Init()
	if !ok || err != nil {
		fmt.Printf("[-] Failed to connect: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Connected: %s v%s\n", auth.AppName, auth.AppVersion)

	// ============ AUTHENTICATE ============
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("\n[1] Login (Username + Password)")
	fmt.Println("[2] License Key")
	fmt.Print("\n> ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	var result *authon.ApiResponse
	if choice == "1" {
		fmt.Print("Username: ")
		username, _ := reader.ReadString('\n')
		fmt.Print("Password: ")
		password, _ := reader.ReadString('\n')
		result, err = auth.Login(strings.TrimSpace(username), strings.TrimSpace(password))
	} else {
		fmt.Print("License Key: ")
		key, _ := reader.ReadString('\n')
		result, err = auth.License(strings.TrimSpace(key))
	}

	if err != nil || !result.Success {
		msg := "Unknown error"
		if err != nil {
			msg = err.Error()
		} else {
			msg = result.Message
		}
		fmt.Printf("\n[-] %s\n", msg)
		os.Exit(1)
	}

	fmt.Println("\n[+] Authenticated!")
	fmt.Printf("    Level: %d\n", auth.Level)
	fmt.Printf("    Subscription: %s\n", ifEmpty(auth.Subscription, "None"))
	fmt.Printf("    Expires: %s\n", ifEmpty(auth.ExpiresAt, "Lifetime"))

	// ============ USE FEATURES ============
	msg, _ := auth.GetVar("welcome_message")
	if msg != "" {
		fmt.Printf("\n[*] %s\n", msg)
	}

	auth.Log("Go SDK example executed")

	valid, _ := auth.Check()
	if valid {
		fmt.Println("\n[+] Session is valid")
	}

	// ============ CLEANUP ============
	fmt.Println("\n[+] Done. Logging out...")
	auth.Logout()
}

func ifEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
