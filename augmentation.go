package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
	elastic "gopkg.in/olivere/elastic.v7"
	"bufio"
	"os"
)

type options struct {
	option []string
}

func GetESClient() (*elastic.Client, error) {
	jsonFile,err := os.Open("/usr/local/ui/elastic.ini")
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
		elastic.SetURL("https://"+fmt.Sprintf("%v", result["nodename"])+":9200"),
		elastic.SetScheme("https"),
		elastic.SetBasicAuth("elastic", fmt.Sprintf("%v", result["password"])),
		elastic.SetMaxRetries(40),
		elastic.SetHealthcheckTimeoutStartup(130*time.Second),
		elastic.SetSniff(false), elastic.SetHealthcheck(false))
	fmt.Println("ES initialized...")
	return client, err

}
func createAugumentation(indexname string, filename string,size int){
	client, err := GetESClient()
	if err != nil {
		fmt.Println("%v", err)
	}
	q := elastic.RawStringQuery("{\"match_all\":{}}")
	res, err := client.Search().Index(indexname).Query(q).From(1).Size(size).Do(context.TODO())
	if err != nil {
		fmt.Println(err)
	}
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("failed creating file: %s", err)
	}
	datawriter := bufio.NewWriter("/dev/shm/"+file)
	for _, hit := range res.Hits.Hits {
		j, err := json.Marshal(hit.Source)
		if err != nil {
			fmt.Println(err)
		}
		for n, line := range bytes.Split(j, []byte{'\n'}) {
			n++
			if n < len(j) {
				_, _ = datawriter.WriteString(string(line) + "\n")
			}
		}
	}
	datawriter.Flush()
	file.Close()

}
func main() {
	size := 100000;
	if(os.Args[1] == nil){
		fmt.Println("Enter Index Type")
	}
	if(os.Args[1] == "md5sums" || os.Args[1] == "augmentation" ){
		createAugumentation("md5sum_*", "suspmd5.csv",size)
	}
	if(os.Args[1] == "signatures" || os.Args[1] == "augmentation"){
		createAugumentation("ja3_*", "suspsignatures.csv",size)
        }
	if(os.Args[1] == "domains" || os.Args[1] == "augmentation"){
		createAugumentation("suspicious-domain_*", "suspdomains.csv",size)
        }
	if(os.Args[1] == "ipaddresses" || os.Args[1] == "augmentation"){
		createAugumentation("suspicious-ip*", "suspips.csv",size)
        }

}
