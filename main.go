package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/gofiber/fiber/v2"
)

//--------------------------------------------------------------------------------
// ตั้งค่าต่าง ๆ ที่ต้องใช้ในการเชื่อมต่อ Keycloak
//--------------------------------------------------------------------------------

const (
	// URL base ของแอปเราที่จะให้ Keycloak redirect กลับ
	baseURL = "http://localhost:8081"

	// Authorization Endpoint ของ Keycloak
	keycloakAuthEndpoint = "http://localhost:8080/realms/poc-app/protocol/openid-connect/auth"

	// Token Endpoint ของ Keycloak
	keycloakTokenEndpoint = "http://localhost:8080/realms/poc-app/protocol/openid-connect/token"

	// ค่าตัวอย่าง Client ID/Secret (อย่าลืมตั้งเป็นของจริงใน Keycloak)
	clientID     = "code-flow-client"
	clientSecret = "ZTjZB6xjstp4uNJWLZihjXjpyr1msjIK"

	// เมื่อ Keycloak login เสร็จ จะ redirect กลับมาที่ /callback
	redirectURI = baseURL + "/callback"
)

// TokenResponse ใช้ map ผลลัพธ์จากการแลก Token
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

func main() {
	app := fiber.New()

	// เส้นทางสำหรับ /login -> redirect ไปหน้า Keycloak เพื่อขอ code
	app.Get("/login", handleLogin)

	// เส้นทางสำหรับ /callback -> Keycloak จะส่ง code กลับมาที่นี่
	app.Get("/callback", handleCallback)

	fmt.Println("Server started at :8081")
	log.Fatal(app.Listen(":8081"))
}

//--------------------------------------------------------------------------------
// handleLogin: เริ่มต้นขอ Authorization Code โดย redirect ไปที่ Keycloak
//--------------------------------------------------------------------------------

func handleLogin(c *fiber.Ctx) error {
	/*
		เมื่อมีการเรียก /login:
		1. เราจะ redirect ผู้ใช้ไปยัง Authorization Endpoint ของ Keycloak
		2. โดยส่ง query parameters: client_id, response_type, redirect_uri, scope, state ฯลฯ
	*/

	authURL, err := url.Parse(keycloakAuthEndpoint)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("parse auth endpoint error")
	}

	fmt.Println("strat login")

	// เตรียม query string
	query := authURL.Query()
	query.Set("client_id", clientID)
	query.Set("response_type", "code")
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", "openid") // อาจเพิ่ม scope อื่น ๆ ได้ เช่น "profile email"
	query.Set("state", "xyz123") // ในระบบจริงควร random + เก็บไว้ใน session เพื่อตรวจสอบกัน CSRF

	authURL.RawQuery = query.Encode()

	// redirect ไปยัง Keycloak
	return c.Redirect(authURL.String())
}

//--------------------------------------------------------------------------------
// handleCallback: รับ code จาก Keycloak แล้วส่งไปแลก Token
//--------------------------------------------------------------------------------

func handleCallback(c *fiber.Ctx) error {
	/*
		เมื่อ Keycloak ทำ redirect กลับมาที่ /callback:
		1. เราจะได้รับ code ใน query parameter
		2. นำ code ไปเรียก Token Endpoint (POST) พร้อม client_secret เพื่อแลก Access Token
	*/

	code := c.Query("code", "")
	if code == "" {
		return c.Status(fiber.StatusBadRequest).SendString("missing code")
	}

	// เตรียมข้อมูลสำหรับ POST ไป Token Endpoint
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret) // ถ้าเป็น public client + PKCE อาจไม่ต้องใช้ secret
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)

	// ส่งคำขอไป Token Endpoint ด้วย http.PostForm
	resp, err := http.PostForm(keycloakTokenEndpoint, data)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("error requesting token: " + err.Error())
	}
	defer resp.Body.Close()

	// แปลงผลลัพธ์ (JSON) เป็น struct TokenResponse
	var tokenRes TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenRes); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("decode token response error: " + err.Error())
	}

	// ส่งผลลัพธ์ token ให้ client ดู (ในระบบจริง ควรเก็บไว้ใน session/database)
	return c.JSON(tokenRes)
}
