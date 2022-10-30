package applogic

import (
	"encoding/json"
)

func JsonConvert(value interface{}) (string, error) {
	content, err := json.Marshal(value)
	if err != nil {
		Log("%v", err)
	}
	return string(content), nil
}
