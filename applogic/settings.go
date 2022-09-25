package applogic

import (
	"os"
)

// Settigns is a struct that holds the settings for the micro bruh Api
type Settings struct {
	Title    string
	Hostname string
	// Port is the port that the server will listen on
	Port string
	// Version is the version of the micro bruh Api
	Version string
}

func CheckTitle(api *Api, template string) {
	// Check the variables from env and set them to the settings
	// if they are not set, set them to the default values
	// get title from env
	api.Settings.Title = os.Getenv("TITLE")
	if api.Settings.Title == "" {
		api.Settings.Title = template
	}
}

func CheckHostname(api *Api, template string) {
	// Check the variables from env and set them to the settings
	// if they are not set, set them to the default values
	// get hostname from env
	api.Settings.Hostname = os.Getenv("HOSTNAME")
	if api.Settings.Hostname == "" {
		api.Settings.Hostname = template
	}
}

func CheckPort(api *Api, template string) {
	api.Settings.Port = os.Getenv("PORT")
	if api.Settings.Port == "" {
		api.Settings.Port = template
	}
}
func CheckVersion(api *Api, template string) {
	api.Settings.Version = os.Getenv("VERSION")
	if api.Settings.Version == "" {
		api.Settings.Version = template
	}
}

type Template struct {
	Title    string
	Hostname string
	Port     string
	Version  string
}

func DefaultTemplate() Template {
	return Template{
		Title:    "Micro bruh Api",
		Hostname: "localhost",
		Port:     "8080",
		Version:  "1.0.0",
	}
}
func CheckSettings(api *Api) {
	CheckTitle(api, DefaultTemplate().Title)
	CheckHostname(api, DefaultTemplate().Hostname)
	CheckPort(api, DefaultTemplate().Port)
	CheckVersion(api, DefaultTemplate().Version)
}
func SetPort(api *Api, port string) {
	api.Settings.Port = port
}
func GetPort(api *Api) string {
	return api.Settings.Port
}
func ShowApiPort(api *Api) {
	println(api.Settings.Port)
}
func SetTitle(api *Api, title string) {
	api.Settings.Title = title
}
func GetTitle(api *Api) string {
	return api.Settings.Title
}
func ShowApiTitle(api *Api) {
	println(api.Settings.Title)
}
func SetHostname(api *Api, hostname string) {
	api.Settings.Hostname = hostname
}
func GetHostname(api *Api) string {
	return api.Settings.Hostname
}
func ShowHostname(api *Api) {
	println(api.Settings.Hostname)
}
func SetVersion(api *Api, version string) {
	api.Settings.Version = version
}
func GetVersion(api *Api) string {
	return api.Settings.Version
}
func ShowVersion(api *Api) {
	println(api.Settings.Version)
}
func GetSettings(api *Api) Settings {
	return api.Settings
}
