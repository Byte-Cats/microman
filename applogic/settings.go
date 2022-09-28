package applogic

import (
	"fmt"
	"os"

	"github.com/gorilla/mux"
)

// Settings struct holds settings for Api
type Settings struct {
	// Title of the api instance
	Title string
	// Hostname of the api server (default: localhost)
	Hostname string
	// Port that the server will listen on
	Port string
	// Version of the Api
	Version string
	// Value of Prefix
	Prefix string
}

// Template is a struct that holds the default settings of the Api
type Template struct {
	// Default title of the api instance
	Title string
	// Default hostname of the api server (default: localhost)
	Hostname string
	// Default port that the server will listen on
	Port string
	// Default version of the Api
	Version string
	// Default value of prefix
	Prefix string
}

// DefaultTemplate is the default template of the Api settings
func DefaultTemplate() Template {
	return Template{
		Title:    "Micro Dude Api",
		Hostname: "localhost",
		Port:     "6969",
		Version:  "0.420.69",
		Prefix:   "default",
	}
}

// CheckTitle is a function that checks if the title is set from .env
func CheckTitle(api *Api, template string) {
	// Check the variables from env and set them to the settings
	// if they are not set, set them to the default values
	// get title from env
	api.Settings.Title = os.Getenv("TITLE")
	if api.Settings.Title == "" {
		api.Settings.Title = template
	}
}

// CheckHostname is a function that checks if the hostname is set from .env
func CheckHostname(api *Api, template string) {
	// Check the variables from env and set them to the settings
	// if they are not set, set them to the default values
	// get hostname from env
	api.Settings.Hostname = os.Getenv("HOSTNAME")
	if api.Settings.Hostname == "" {
		api.Settings.Hostname = template
	}
}

// CheckPort is a function that checks if the port is set from .env
func CheckPort(api *Api, template string) {
	api.Settings.Port = os.Getenv("PORT")
	if api.Settings.Port == "" {
		api.Settings.Port = template
	}
}

// CheckVersion is a function that checks if the version is set from .env
func CheckVersion(api *Api, template string) {
	api.Settings.Version = os.Getenv("VERSION")
	if api.Settings.Version == "" {
		api.Settings.Version = template
	}
}

// CheckPrefix is a function that checks if the prefix is set from .env
func CheckPrefix(api *Api, template string) {
	api.Settings.Prefix = os.Getenv("PREFIX")
	if api.Settings.Prefix == "" {
		api.Settings.Prefix = template
	}
}

// CheckSettings is a function that checks if the settings are set from .env
func CheckSettings(api *Api) {
	CheckTitle(api, DefaultTemplate().Title)
	CheckHostname(api, DefaultTemplate().Hostname)
	CheckPort(api, DefaultTemplate().Port)
	CheckVersion(api, DefaultTemplate().Version)
	CheckPrefix(api, DefaultTemplate().Prefix)
}

// SetPort is a pointer receiver function that sets the port of the Api
func (api *Api) SetPort(port string) {
	api.Settings.Port = port
}

// GetPort is a function that returns the port of the Api
func GetPort(api *Api) string {
	return api.Settings.Port
}

// ShowPort is a function that returns the router of the Api
func ShowPort(api *Api) {
	fmt.Println(api.Settings.Port)
}

// SetTitle is a pointer receiver function that sets the title of the Api
func (api *Api) SetTitle(title string) {
	api.Settings.Title = title
}

// GetTitle is a function that returns the title of the Api
func GetTitle(api *Api) string {
	return api.Settings.Title
}

// ShowTitle is a function that prints the title of the Api
func ShowTitle(api *Api) {
	fmt.Println(api.Settings.Title)
}

// SetHostname is a pointer receiver function that sets the hostname of the Api
func (api *Api) SetHostname(hostname string) {
	api.Settings.Hostname = hostname
}

// GetHostname is a function that returns the hostname of the Api
func GetHostname(api *Api) string {
	return api.Settings.Hostname
}

// ShowHostname is a function that prints the hostname of the Api
func ShowHostname(api *Api) {
	fmt.Println(api.Settings.Hostname)
}

// SetVersion is a pointer receiver function that sets the version of the Api
func (api *Api) SetVersion(version string) {
	api.Settings.Version = version
}

// GetVersion is a function that returns the version of the Api
func GetVersion(api *Api) string {
	return api.Settings.Version
}

// ShowVersion is a function that prints the version of the Api
func ShowVersion(api *Api) {
	fmt.Println(api.Settings.Version)
}

// SetPrefix is a pointer receiver function that sets the url prefix of the Api
func (api *Api) SetPrefix(prefix string) {
	api.Settings.Prefix = prefix
}

// GetPrefix is a function that returns the url prefix of the Api
func GetPrefix(api *Api) string {
	return api.Settings.Prefix
}

// ShowPrefix is a function that prints the url prefix of the Api
func ShowPrefix(api *Api) {
	fmt.Println(api.Settings.Prefix)
}

// GetSettings is a function that returns the settings of the Api
func GetSettings(api *Api) Settings {
	return api.Settings
}

// GetFullPath is a function that returns the full path of the Api
func GetFullPath(api *Api) string {
	var pathToReturn string
	switch GetPort(api) {
	case "":
		// is it possible? even if we aren't setting it manually,
		// CheckPort(api) func is setting it to env default
		fmt.Println("The port value is empty. Something gone really wrong =/")
		break
	case "80":
		// HTTP protocol port
		fmt.Println("HTTP protocol port is set.")
		pathToReturn = GetHostname(api) + ":" + GetPort(api)
		break
	case "443":
		// HTTPS protocol port
		pathToReturn = GetHostname(api)
		break
	default:
		pathToReturn = GetHostname(api) + ":" + GetPort(api)
	}
	return pathToReturn
}

// GetRnP is a function that returns port and router of the Api for http serving
func GetRnP(api *Api) (string, *mux.Router) {
	return ":" + GetPort(api), GetRouter(api)
}
