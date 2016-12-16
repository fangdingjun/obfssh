package main

import (
	"flag"
	"github.com/go-yaml/yaml"
	"io/ioutil"
	"strings"
)

// stringSlice implemnts the flag.Value interface
// used to hold multiple command line arguments
type stringSlice []string

func (lf *stringSlice) Set(val string) error {
	ss := strings.Split(val, ",")

	if len(*lf) == 0 {
		*lf = append(*lf, ss...)
		return nil
	}

	tmp := []string{}
	for _, s1 := range ss {
		exists := false
		for _, s2 := range *lf {
			if s1 == s2 {
				exists = true
				break
			}
		}
		if !exists {
			tmp = append(tmp, s1)
		}
	}

	if len(tmp) > 0 {
		*lf = append(*lf, tmp...)
	}
	return nil
}

func (lf *stringSlice) String() string {
	return strings.Join(*lf, ",")
}

type config struct {
	Host                      string      `yaml:"host"`
	Port                      int         `yaml:"port"`
	PrivateKey                string      `yaml:"private_key"`
	ObfsMethod                string      `yaml:"obfs_method"`
	ObfsKey                   string      `yaml:"obfs_key"`
	Username                  string      `yaml:"username"`
	Password                  string      `yaml:"password"`
	KeepaliveInterval         int         `yaml:"keepalive_interval"`
	KeepaliveMax              int         `yaml:"keepalive_max"`
	Debug                     bool        `yaml:"debug"`
	DisableObfsAfterHandshake bool        `yaml:"disable_obfs_after_handshake"`
	NotRunCmd                 bool        `yaml:"not_run_cmd"`
	LocalForwards             stringSlice `yaml:"local_forward"`
	RemoteForwards            stringSlice `yaml:"remote_forward"`
	DynamicForwards           stringSlice `yaml:"dynamic_forward"`
}

// loadConfig load config from config file
// it will save the commandline argument and
// restore it after load the config file
func loadConfig(cfg *config, f string) error {
	// save commandline arguments
	savedCommandline := map[string]string{}
	flag.Visit(func(f *flag.Flag) {
		savedCommandline[f.Name] = f.Value.String()
	})

	// load config file
	buf, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(buf, cfg)
	if err != nil {
		return err
	}

	// restore commandline arguments
	for k, v := range savedCommandline {
		flag.Set(k, v)
	}

	return nil
}
