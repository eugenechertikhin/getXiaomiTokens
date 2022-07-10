package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/MajaSuite/getXiaomiTokens/cloud"
	"log"
	"sort"
	"strings"
)

var (
	servers = []string{"cn", "de", "ru", "us", "tw", "sg", "in", "i2"}
	uid     = flag.String("uid", "0", "mi account id")
	pass    = flag.String("pass", "", "mi account password")
	server  = flag.String("server", "cn", "server to fetch data ("+strings.Join(servers, ",")+")")
)

type DeviceSpec struct {
	DeviceId    string `json:"did"`
	Token       string `json:"token"`
	Ip          string `json:"localip"`
	Parent      string `json:"parent_id"'`
	ParentModel string `json:"parent_model"'`
	Model       string `json:"model"`
	Online      bool   `json:"isOnline"`
}

type VirtualModels struct {
	Model string `json:"model"`
}

type Result struct {
	List    []DeviceSpec    `json:"list""`
	Virtual []VirtualModels `json:"virtualModels"`
}

func main() {
	flag.Parse()

	if *uid == "0" || *pass == "" {
		flag.Usage()
		return
	}

	if i := sort.SearchStrings(servers, *server); servers[i] != *server {
		log.Println("wrong server specified")
		return
	}

	log.Println("loging")
	c := cloud.NewConnection(*uid, *pass, *server)
	if err := c.Login(); err != nil {
		panic(err)
	}
	log.Println("login ok")

	m, err := c.GetDevices()
	if err != nil {
		panic(err)
	}

	//log.Println("decoded", m)

	var objmap map[string]json.RawMessage
	err = json.Unmarshal([]byte(m), &objmap)

	var result Result
	err = json.Unmarshal(objmap["result"], &result)

	for _, d := range result.List {
		fmt.Printf(" deviceid = %x\n Token = %s\n Ip = %s\n Parent = %s (%s)\n Model = %s\n Online = %v\n\n", d.DeviceId, d.Token, d.Ip, d.Parent, d.ParentModel, d.Model, d.Online)
	}
}
