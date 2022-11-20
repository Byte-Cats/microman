package data

import (
	"encoding/json"

	"github.com/byte-cats/microman/log"
)

func JsonConvert(value interface{}) (string, error) {
	content, err := json.Marshal(value)
	if err != nil {
		log.Log("%v", err)
	}
	return string(content), nil
}
