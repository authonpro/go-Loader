# Authon Go SDK

<p align="center">
  <img src="https://authon.pro/logo.png" alt="Authon" width="80" />
  <br/>
  <strong>Official Go SDK for Authon — Software Licensing & Authentication Platform</strong>
</p>

<p align="center">
  <a href="https://authon.pro">Website</a> •
  <a href="https://authon.pro/docs">Docs</a> •
  <a href="https://discord.gg/jMZCTKPsmE">Discord</a> •
  <a href="https://authon.pro/status">Status</a>
</p>

---

## Installation

```bash
go get github.com/authonpro/sdk-go
```

Or copy `authon.go` into your project.

## Requirements

- Go 1.21+
- No external dependencies (stdlib only)

## Quick Start

```go
package main

import (
    "fmt"
    authon "github.com/authonpro/sdk-go"
)

func main() {
    auth := authon.New("your-app-id", "your-api-key")

    ok, _ := auth.Init()
    if !ok {
        fmt.Println("Connection failed")
        return
    }

    result, _ := auth.Login("username", "password")
    if result.Success {
        fmt.Printf("Level: %d\n", auth.Level)
        fmt.Printf("Expires: %s\n", auth.ExpiresAt)
    } else {
        fmt.Printf("Error: %s\n", result.Message)
    }

    auth.Logout()
}
```

## Authentication

```go
// Login
result, _ := auth.Login("user", "pass")

// License key
result, _ := auth.License("XXXXX-XXXXX-XXXXX-XXXXX")

// Register
result, _ := auth.Register("newuser", "pass", "LICENSE-KEY")

// Custom HWID
result, _ := auth.Login("user", "pass", "custom-hwid")
```

## Features

```go
// Variables
val, _ := auth.GetVar("key")
auth.SetVar("key", "value")
uvar, _ := auth.GetUserVar("key")

// File download
data, _ := auth.DownloadFile("file-id")
os.WriteFile("output.exe", data, 0644)

// Stats
auth.FetchOnline()
auth.FetchStats()

// Logging
auth.Log("User action")

// Session
valid, _ := auth.Check()
auth.Logout()
```

## Run Example

```bash
cd example
go run main.go
```

## Links

- 🌐 Website: https://authon.pro
- 📖 Docs: https://authon.pro/docs
- 💬 Discord: https://discord.gg/jMZCTKPsmE
- 📊 Status: https://authon.pro/status
- 🔗 API Health: https://api.authon.pro/health

## License

MIT
