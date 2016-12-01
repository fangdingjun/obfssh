package main

import (
	//"github.com/go-yaml/yaml"
	//"io/ioutil"
	"log"
	"testing"
)

func TestConfig(t *testing.T) {
	c, err := loadConfig("config_example.yaml")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%+v", c)
}
