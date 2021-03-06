package main

import (
	"fmt"
	"testing"
)

func TestConfig(t *testing.T) {
	var c config
	err := loadConfig(&c, "config_example.yaml")
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%+v\n", c)
}
