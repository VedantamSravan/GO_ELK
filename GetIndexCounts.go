package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	elastic "gopkg.in/olivere/elastic.v7"
)

func GetESClient() (*elastic.Client, error) {
	//jsonFile,err := os.Open("/usr/local/ui/elastic.ini")
	jsonFile, err := os.Open("elastic.ini")
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

func getCounts(indexname string) (int64, error) {
	client, err := GetESClient()
	if err != nil {
		fmt.Println("%v", err)
	}
	clientservice := client.Count(indexname)
	countvalue, err1 := clientservice.Do(context.TODO())
	if err != nil {
		fmt.Println("%v", err)
	}
	return countvalue, err1
}

func main() {

	result := make(map[string]interface{})
	studentscount, _ := getCounts("students*")

	result["students"] = "students"
	result["studentscount"] = studentscount

	investigatorcount, _ := getCounts("investigator_*")

	result["investigator"] = "investigator"
	result["investigatorcount"] = investigatorcount

	jsonString, _:= json.Marshal(result)
	fmt.Println(string(jsonString))



}
