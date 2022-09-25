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

func CheckTitle(api *Api) {
	// Check the variables from env and set them to the settings
	// if they are not set, set them to the default values
	// get title from env
	api.Settings.Title = os.Getenv("TITLE")
	if api.Settings.Title == "" {
		api.Settings.Title = "Micro bruh Api"
	}
}

func CheckHostname(api *Api) {
	// Check the variables from env and set them to the settings
	// if they are not set, set them to the default values
	// get hostname from env
	api.Settings.Hostname = os.Getenv("HOSTNAME")
	if api.Settings.Hostname == "" {
		api.Settings.Hostname = "localhost"
	}
}

func CheckPort(api *Api) {
	api.Settings.Port = os.Getenv("PORT")
	if api.Settings.Port == "" {
		api.Settings.Port = "8080"
	}
}
func CheckVersion(api *Api) {
	api.Settings.Version = os.Getenv("VERSION")
	if api.Settings.Version == "" {
		api.Settings.Version = "0.3.0"
	}
}

func CheckSettings(api *Api) {
	CheckTitle(api)
	CheckHostname(api)
	CheckPort(api)
	CheckVersion(api)
}
