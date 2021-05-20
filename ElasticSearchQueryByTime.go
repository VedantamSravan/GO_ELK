package main

import (
	"os"
	"fmt"
	"io/ioutil"
	"encoding/json"
	"net/http"
	"crypto/tls"
	"time"
	"context"
	elastic "github.com/olivere/elastic/v7"

)

func GetESClient() (*elastic.Client, error) {

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

func main(){
	client, err := GetESClient()
	if err != nil {
		fmt.Println("%v", err)
	}
	
	timeQ := elastic.NewRangeQuery("timestamp").Lte("now-1h")
	componentQ := elastic.NewMatchQuery("event_type","flow")
	generalQ := elastic.NewBoolQuery().Should().Filter(timeQ).Filter(componentQ)

	result, err := client.Search().Index("investigate_*").Query(generalQ).From(1).Size(2000).Do(context.TODO())
	if err != nil {
		fmt.Println(err)
	}

	var mapresult map[string]interface{}

	for _, hit := range result.Hits.Hits {
		fmt.Println(hit.Source)
		err := json.Unmarshal(hit.Source, &mapresult)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(mapresult)

	}
}
