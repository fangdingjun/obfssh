package main

import (
	"bytes"
	"github.com/go-yaml/yaml"
	"github.com/golang/crypto/ssh"
	"io/ioutil"
	"log"
)

type serverConfig struct {
	Port    int          `yaml:"port"`
	Key     string       `yaml:"obfs_key"`
	Debug   bool         `yaml:"debug"`
	HostKey string       `yaml:"host_key_file"`
	Method  string       `yaml:"obfs_method"`
	Users   []serverUser `yaml:"users"`
}

type serverUser struct {
	Username          string `yaml:"username"`
	Password          string `yaml:"password"`
	AuthorizedKeyFile string `yaml:"authorized_key_file"`
	publicKeys        []ssh.PublicKey
}

func (c *serverConfig) getUser(user string) (serverUser, error) {
	for _, u := range c.Users {
		if u.Username == user {
			return u, nil
		}
	}
	return serverUser{}, nil
}

func loadConfig(f string) (*serverConfig, error) {
	buf, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}

	var c serverConfig
	if err := yaml.Unmarshal(buf, &c); err != nil {
		return nil, err
	}

	for i := range c.Users {
		buf1, err := ioutil.ReadFile(c.Users[i].AuthorizedKeyFile)
		if err != nil {
			log.Printf("read publickey for %s failed, ignore", c.Users[i].Username)
			continue
		}

		// parse authorized_key
		//var err error
		var p1 ssh.PublicKey
		r := bytes.Trim(buf1, " \r\n")
		for {
			p1, _, _, r, err = ssh.ParseAuthorizedKey(r)
			if err != nil {
				//log.Println(err)
				//log.Printf("%+v %+v", r, p1)
				return nil, err
			}
			c.Users[i].publicKeys = append(c.Users[i].publicKeys, p1)
			if len(r) == 0 {
				break
			}
		}
	}
	return &c, nil
}
