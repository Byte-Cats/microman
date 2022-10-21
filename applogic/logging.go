package applogic

import (
	"encoding/json"
	"fmt"
	"os"
)

func Log(format string, v ...any) {
	byteArray, err := json.Marshal(format)
	if err != nil {
		fmt.Println(err)
	}
	f, err := os.OpenFile("github.com/byte-cats/microman/log/logging.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	n, err := f.Write(byteArray)
	if err != nil {
		fmt.Println(n, err)
	}

	if n, err = f.WriteString("\n"); err != nil {
		fmt.Println(n, err)
	}
}
