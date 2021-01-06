package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	elastic "github.com/olivere/elastic/v7"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	WATCHDIR = "/storage0/mdw/"
	DESTDIR  = "/storage0/suricata/"

)

func GetESClient() (*elastic.Client, error) {
	//hostname, err := os.Hostname()
	//if err != nil {
	//	fmt.Println(err)
	//}

	jsonFile, err := os.Open("/usr/local/ui/elastic.ini")
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var result map[string]interface{}
	json.Unmarshal([]byte(byteValue), &result)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	

	client1 := &http.Client{Transport: tr}
	client, err := elastic.NewClient(
		elastic.SetHttpClient(client1),
		elastic.SetURL("https://"+fmt.Sprintf("%v",result["nodename"])+":9200"),
		elastic.SetScheme("https"),
		elastic.SetBasicAuth("elastic", fmt.Sprintf("%v", result["password"])),
		elastic.SetMaxRetries(40),
		elastic.SetHealthcheckTimeoutStartup(130*time.Second),
		elastic.SetSniff(false), elastic.SetHealthcheck(false))
	return client, err

}

func main() {
	nc_nodename := os.Getenv("NC_NODENAME");
	client, err := GetESClient()
	if err != nil {
		fmt.Println("%v", err)
	}

	for true {
		args := os.Args[1:]

		items, err := ioutil.ReadDir(WATCHDIR + args[0])
		if err != nil || len(items) == 0 {
			
			fmt.Println("Sleeping...");
			time.Sleep(8 * time.Second)


		}
		fmt.Println(len(items));
		processed := false
		for _, item := range items {
			fmt.Println(item)
			if item.IsDir() {
				subitems, _ := ioutil.ReadDir(WATCHDIR + args[0] + "/" + item.Name())
				for _, subitem := range subitems {
					if !subitem.IsDir() && !strings.HasPrefix(subitem.Name(), ".") {
						file, err := os.Open(WATCHDIR + args[0] + "/" + item.Name() + "/" + subitem.Name())
						if err != nil {
							log.Fatal(err)
						}else {
							defer file.Close()
							scanner := bufio.NewScanner(file)
							//calling these two inside
							ctx := context.Background()
							bulkRequest := client.Bulk()
							for scanner.Scan() {
								req := elastic.NewBulkIndexRequest().Index("investigate_"+ 
									nc_nodename + "_" + item.Name()).Type("_doc").Doc(scanner.Text())
								bulkRequest = bulkRequest.Add(req)
							}
							if !processed {
								processed = true;
							}
							bulkRequest.Do(ctx)
							//free memory
							bulkRequest = nil
							ctx = nil
							scanner = nil

							os.Mkdir(DESTDIR + item.Name(), 0755)
							err1 := os.Rename(WATCHDIR + args[0] + "/" + item.Name() + "/" +
								subitem.Name(), DESTDIR + item.Name() + "/" + args[0] + "_" + subitem.Name())
							if err1 != nil {
								fmt.Println(err1)
							}
						}
					}

				}
			}

		}
		if !processed {
			time.Sleep(8*time.Second);
		}
	}

}
