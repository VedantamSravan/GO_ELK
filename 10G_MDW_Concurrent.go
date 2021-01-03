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
	"strconv"
	"strings"
	"sync"
	"time"
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
	args := os.Args[1:]
	var wg sync.WaitGroup
	threads, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Println(err)
	}
	wg.Add(threads)
	go func() {
		for true {

			items, err := ioutil.ReadDir(WATCHDIR + args[0])
			if err != nil || len(items) == 0 {
				fmt.Println(numrecords)
				numrecords = 0
				fmt.Println("if length is zero")
				time.Sleep(8 * time.Second)

			}

			for _, item := range items {
				defer wg.Done()
				if item.IsDir() {

					subitems, _ := ioutil.ReadDir(WATCHDIR + args[0] + "/" + item.Name())
					for _, subitem := range subitems {
						if !subitem.IsDir() && !strings.HasPrefix(subitem.Name(), ".") {
							fmt.Println(subitem.Name())
							fmt.Println(WATCHDIR + args[0] + "/" + item.Name() + "/" + subitem.Name())
							file, err := os.Open(WATCHDIR + args[0] + "/" + item.Name() + "/" + subitem.Name())
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
								req := elastic.NewBulkIndexRequest().Index("investigate_nc191_" + item.Name()).Type("_doc").Doc(scanner.Text())
								bulkRequest = bulkRequest.Add(req)
								i++
								numrecords++
							}
							bulkResponse, err := bulkRequest.Do(ctx)
							if err != nil {
								fmt.Println("Ramababu")
								fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())

							} else {
								for _, info := range bulkResponse.Indexed() {
									fmt.Println("nBulk response Index:", info)
									fmt.Println(info.Result)

								}
							}
							os.Mkdir(DESTDIR+item.Name(), 0755)
							err1 := os.Rename(WATCHDIR+args[0]+"/"+item.Name()+"/"+subitem.Name(), DESTDIR+item.Name()+"/"+args[0]+"_"+subitem.Name())
							if err1 != nil {
								fmt.Println(err1)
							}

						}
					}

				}

			}
		}
	}()
	wg.Wait()
}
