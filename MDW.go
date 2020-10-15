package main

import (
	"bytes"
	"context"
	//"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	///"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	elastic "gopkg.in/olivere/elastic.v7"
)

const (
	WATCHDIR = "./storage0/investigator/"
)

type options struct {
	option []string
}
type FileData struct {
	BeginTime    time.Time
	EndTime      time.Time
	TotalRecords int
}

/*func GetESClient() (*elastic.Client, error) {
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

}*/
func main() {
	//begintime
	//totoal records

	var totalrecords = 0;
	begintime := time.Now()
	files, err := ioutil.ReadDir(WATCHDIR)
	if err != nil {
		log.Fatal(err)
	}
	client, err := elastic.NewClient()
	if err != nil {
		fmt.Println("%v", err)
	}
	bulkRequest := client.Bulk()



	permissionarr := []string{}
	for _, file := range files {

		if strings.HasSuffix(file.Name(), ".json") {
			filesize, err := os.Stat(WATCHDIR + file.Name())
			if err != nil {
				fmt.Println(err)
				continue
			}
			// get file size
			fsize := int(filesize.Size())
			if fsize != 0 {
				filedata, err := ioutil.ReadFile(WATCHDIR + file.Name())
				if err != nil {
					fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
				}
				var result = options{}

				for n, line := range bytes.Split(filedata, []byte{'\n'}) {
					n++
					if n < fsize {
						json.Unmarshal([]byte(line), &result)
						permissionarr = append(permissionarr, string(line))

					}
					if true {

						totalrecords = totalrecords+1
					}
				}

			}
			if fsize == fsize {
				os.Remove(WATCHDIR + file.Name())
			}

		}

	}
	for e, element := range permissionarr {

		req := elastic.NewBulkIndexRequest().Index("students").Type("students").Id(strconv.Itoa(e)).Doc(element)
		bulkRequest = bulkRequest.Add(req)

		bulkResponse, err := bulkRequest.Do(context.TODO())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())

		}
		indexed := bulkResponse.Indexed()
		if len(indexed) != 1 {
			fmt.Printf("\n Indexed documents: %v \n", len(indexed))
		}
		for _, info := range indexed {
			fmt.Println("nBulk response Index:", info)
			fmt.Println(info.Result)

		}

	}
	endtime := time.Now()
	//end time
	//totalrecods endtime start write into file
	/*filedata := make(map[string]interface{})
	filedata["begintime"] = begintime
	filedata["endtime"] = endtime
	filedata["totalrecords"] = totalrecodrds
	jsonData, err := json.Marshal(filedata)
	*/
	fdata := &FileData{
		BeginTime:    begintime,
		EndTime:      endtime,
		TotalRecords: totalrecords,
	}

	out, err := json.Marshal(fdata)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(out))

}
