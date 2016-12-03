package main

import (
	"github.com/go-yaml/yaml"
	"io/ioutil"
)

type config struct {
	Host                      string   `yaml:"host"`
	Port                      int      `yaml:"port"`
	PrivateKey                string   `yaml:"private_key"`
	ObfsMethod                string   `yaml:"obfs_method"`
	ObfsKey                   string   `yaml:"obfs_key"`
	Username                  string   `yaml:"username"`
	Password                  string   `yaml:"password"`
	KeepaliveInterval         int      `yaml:"keepalive_interval"`
	KeepaliveMax              int      `yaml:"keepalive_max"`
	Debug                     bool     `yaml:"debug"`
	DisableObfsAfterHandshake bool     `yaml:"disable_obfs_after_handshake"`
	NotRunCmd                 bool     `yaml:"not_run_cmd"`
	LocalForward              []string `yaml:"local_forward"`
	RemoteForward             []string `yaml:"remote_forward"`
	DynamicForward            []string `yaml:"dynamic_forward"`
}

func loadConfig(f string) (*config, error) {
	buf, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	var c config
	err = yaml.Unmarshal(buf, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
