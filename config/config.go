package config

import (
	"io/ioutil"

	yaml "gopkg.in/yaml.v1"
)

type IPRange struct {
	Domain struct {
		Name     string
		Ranges   []string `yaml:",flow"`
		Url      string
		Response struct {
			Headers  map[string]string
			Status   string
			SanValue string
		}
	}
}

type YamlDef struct {
	Ipranges []IPRange
}

func GetRanges() (error, []IPRange) {
	fdata, err := ioutil.ReadFile("./config.yaml")
	if err != nil {
		return err, nil
	}

	ipranges := YamlDef{}
	err = yaml.Unmarshal([]byte(fdata), &ipranges)
	if err != nil {
		return err, nil
	}

	return nil, ipranges.Ipranges
}
