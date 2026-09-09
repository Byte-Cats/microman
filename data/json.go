package data

import (
	jsoniter "github.com/json-iterator/go"

	"github.com/byte-cats/microman/log"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func JsonConvert(value interface{}) (string, error) {
	content, err := json.Marshal(value)
	if err != nil {
		log.Log("%v", err)
	}
	return string(content), nil
}
