package services

import (
	"bytes"
	"crypto/tls"
	"github.com/k3a/html2text"
	"github.com/ottolauncher/gtodo/config"
	"gopkg.in/gomail.v2"
	"html/template"
	"io/fs"
	"log"
	"path/filepath"
)

type EmailData struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Subject  string `json:"subject"`
}

// ParseTemplateDir search for templates on a given directory
func ParseTemplateDir(dir string) (*template.Template, error) {
	var paths []string
	err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return template.ParseFiles(paths...)
}

func SendEmail(cfg *config.Config, email *string, data *EmailData, tpl string) {
	from := cfg.EmailFrom
	smtpPassword := cfg.SandBoxEmailPassword
	smtpUser := cfg.SandBoxEmailUser
	//to := user.Email
	to := cfg.SandBoxEmailAPI
	smtpHost := cfg.EmailHost
	smtpPort := cfg.EmailPort

	var body bytes.Buffer
	tmpl, err := ParseTemplateDir("templates")
	if err != nil {
		log.Fatalln("could not parse template: ", err)
	}
	err = tmpl.ExecuteTemplate(&body, tpl, &data)
	if err != nil {
		log.Fatalln("could not execute template: ", err)
	}

	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", data.Subject)
	m.SetBody("text/html", body.String())
	m.AddAlternative("text/plain", html2text.HTML2Text(body.String()))

	d := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPassword)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(m); err != nil {
		log.Fatalln("could not send email: ", err)
	}

}
