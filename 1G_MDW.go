package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
	"bufio"
	"crypto/tls"
	elastic "github.com/olivere/elastic/v7"
	"net/http"
	"encoding/json"
)

const (
	WATCHDIR = "/storage0/mdw/"
	DESTDIR  = "/storage0/suricata/"
)

func GetESClient() (*elastic.Client, error) {
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println(err)
	}

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
		elastic.SetURL("https://"+hostname+":9200"),
		elastic.SetScheme("https"),
		elastic.SetBasicAuth("elastic", fmt.Sprintf("%v", result["password"])),
		elastic.SetMaxRetries(40),
		elastic.SetHealthcheckTimeoutStartup(130*time.Second),
		elastic.SetSniff(false), elastic.SetHealthcheck(false))
	fmt.Println("ES initialized...")

	return client, err

}

func main() {
	client, err := GetESClient()
	if err != nil {
		fmt.Println("%v", err)
	}

	ctx := context.Background()
	bulkRequest := client.Bulk()
	numrecords := 0
	for true {
		items, err := ioutil.ReadDir(WATCHDIR)
		if err != nil || len(items) > 0{
			fmt.Println(numrecords);
			numrecords = 0;
			fmt.Println("if length is zero");
			time.Sleep(8 * time.Second)

		}

		for _, item := range items {
			if item.IsDir() {

				subitems, _ := ioutil.ReadDir(WATCHDIR + item.Name())
				for _, subitem := range subitems {
					if !subitem.IsDir() && !strings.HasPrefix(subitem.Name(), ".") {
						fmt.Println(subitem.Name());
						file, err := os.Open(WATCHDIR+item.Name()+"/"+subitem.Name())
						if err != nil {
							log.Fatal(err)
						}
						defer file.Close()
						scanner := bufio.NewScanner(file)
						//e:=0
						filesize, err := os.Stat(file.Name())
						if err != nil {
							fmt.Println(err)

						}

						fsize := int(filesize.Size())
						i := 1
						for scanner.Scan() {
							if i == fsize {
								break
							}
							req := elastic.NewBulkIndexRequest().Index("investigate_nc191_"+item.Name()).Type("_doc").Doc(scanner.Text())
							bulkRequest = bulkRequest.Add(req)
							i++
							numrecords++
						}
						bulkResponse, err := bulkRequest.Do(ctx)
						if err != nil {
							fmt.Println("Ramababu")
							fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())

						}else{
							for _, info := range bulkResponse.Indexed() {
								fmt.Println("nBulk response Index:", info)
								fmt.Println(info.Result)

							}
						}
						err1 := os.Rename(WATCHDIR+item.Name()+"/"+subitem.Name(), DESTDIR+item.Name()+"/"+subitem.Name())
						if err1 != nil {
							fmt.Println(err1)
						}
						

					}
				}

			}

		}
	}

}

