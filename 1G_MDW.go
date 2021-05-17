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

	"strconv"
)

const (
	WATCHDIR = "/storage0/dbpipe/"
	DESTDIR  = "/storage0/suricata/"


)

var suspsigmap = make(map[string]string)
var suspsipmap = make(map[string]string)
var suspdomainmap = make(map[string]string)
var suspmd5map = make(map[string]string)
var defendedassetmap = make(map[string]string)
var defendedservicemap = make(map[string]string)

func initaugmentation(suspsignatures bool,suspips bool,suspdomains bool,suspmd5 bool,defendedassets bool,defendedservices bool,client *elastic.Client ) {
	if suspsignatures {
		result, err := client.Search().Index("augmentation").Query(elastic.NewMatchQuery("augtype.keyword", "suspicioussignatures")).From(1).Size(2000).Do(context.TODO())
		if err != nil {
			fmt.Println(err)
		}

		var mapresult map[string]interface{}

		for _, hit := range result.Hits.Hits {

			err := json.Unmarshal(hit.Source, &mapresult)
			if err != nil {
				fmt.Println(err)
			}
			suspsigmap[fmt.Sprintf("%v",mapresult["ja3"])] = fmt.Sprintf("%v",mapresult["description"])

		}
	}
	if suspips {
		result, err := client.Search().Index("augmentation").Query(elastic.NewMatchQuery("augtype.keyword", "suspiciousips")).From(1).Size(2000).Do(context.TODO())
		if err != nil {
			fmt.Println(err)
		}

		var mapresult map[string]interface{}

		for _, hit := range result.Hits.Hits {

			err := json.Unmarshal(hit.Source, &mapresult)
			if err != nil {
				fmt.Println(err)
			}
			suspsipmap[fmt.Sprintf("%v",mapresult["suspip"])] = fmt.Sprintf("%v",mapresult["description"])

		}

	}

	if suspdomains {
		result, err := client.Search().Index("augmentation").Query(elastic.NewMatchQuery("augtype.keyword", "suspiciousdomains")).From(1).Size(2000).Do(context.TODO())
		if err != nil {
			fmt.Println(err)
		}

		var mapresult map[string]interface{}

		for _, hit := range result.Hits.Hits {

			err := json.Unmarshal(hit.Source, &mapresult)
			if err != nil {
				fmt.Println(err)
			}
			suspdomainmap[fmt.Sprintf("%v",mapresult["suspdomain"])] = fmt.Sprintf("%v",mapresult["description"])

		}
	}

	if suspmd5 {
		result, err := client.Search().Index("augmentation").Query(elastic.NewMatchQuery("augtype.keyword", "suspmd5sums")).From(1).Size(2000).Do(context.TODO())
		if err != nil {
			fmt.Println(err)
		}

		var mapresult map[string]interface{}

		for _, hit := range result.Hits.Hits {

			err := json.Unmarshal(hit.Source, &mapresult)
			if err != nil {
				fmt.Println(err)
			}
			suspmd5map[fmt.Sprintf("%v",mapresult["suspmd5"])] = fmt.Sprintf("%v",mapresult["description"])

		}
	}

	if defendedassets {
		result, err := client.Search().Index("augmentation").Query(elastic.NewMatchQuery("augtype.keyword", "defendedassets")).From(1).Size(2000).Do(context.TODO())
		if err != nil {
			fmt.Println(err)
		}

		var mapresult map[string]interface{}

		for _, hit := range result.Hits.Hits {

			err := json.Unmarshal(hit.Source, &mapresult)
			if err != nil {
				fmt.Println(err)
			}
			defendedassetmap[fmt.Sprintf("%v",mapresult["defendedasset"])] = fmt.Sprintf("%v",mapresult["description"])

		}
	}

	if defendedservices {
		result, err := client.Search().Index("augmentation").Query(elastic.NewMatchQuery("augtype.keyword", "defendedservices")).From(1).Size(2000).Do(context.TODO())
		if err != nil {
			fmt.Println(err)
		}

		var mapresult map[string]interface{}

		for _, hit := range result.Hits.Hits {

			err := json.Unmarshal(hit.Source, &mapresult)
			if err != nil {
				fmt.Println(err)
			}
			defendedservicemap[fmt.Sprintf("%v",mapresult["defendedservice"])] = fmt.Sprintf("%v",mapresult["description"])

		}
	}
}

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
	//suspiciousips
	suspips,err := ioutil.ReadFile("/storage0/configuration/suspips.json")
	if err != nil{
		fmt.Println("File Doesnot exist")
	}
	var suspipsmap map[string]interface{}
	if err := json.Unmarshal([]byte(suspips), &suspipsmap); err != nil {
		fmt.Println(err)
	}
	nc_nodename,err := ioutil.ReadFile("/usr/local/ui/public/data/cs_hostname.ini")
	if err != nil{
		fmt.Println("Host File Doesnot exist")
	}
	client, err := GetESClient()
	if err != nil {
		fmt.Println("%v", err)
	}
	initaugmentation(true,true,true,true,true,true,client) //comment this out on version before.44

	//start := time.Now()
	for true {

		items, err := ioutil.ReadDir(WATCHDIR )
		if err != nil || len(items) == 0 {

			fmt.Println("Sleeping...");
			time.Sleep(8 * time.Second)


		}
		//fmt.Println(len(items));
		processed := false
		for _, item := range items {
			//fmt.Println(item)
			if item.IsDir() {
				subitems, _ := ioutil.ReadDir(WATCHDIR  + "/" + item.Name())
				for _, subitem := range subitems {
					if !subitem.IsDir() && !strings.HasPrefix(subitem.Name(), ".") {
						file, err := os.Open(WATCHDIR + "/" + item.Name() + "/" + subitem.Name())
						if err != nil {
							log.Fatal(err)
						}else {
							//defer file.Close() dont use defer close
							scanner := bufio.NewScanner(file)
							scanner.Split(bufio.ScanLines)
							//calling these two inside
							ctx := context.Background()
							bulkRequest := client.Bulk()
							var objmap map[string]interface{}
							for scanner.Scan() {


								if err := json.Unmarshal([]byte(scanner.Text()), &objmap); err != nil {
									fmt.Println(err)
								}

								objmap["nodename"] = "nc192"
								objmap["defended"] = false
								objmap["suspected"] = false
								//delete unwanted value
								delete(objmap, "nc_id")
								if objmap["event_type"] == "tls" {

									ja3hash := fmt.Sprintf("%v",objmap["tls"].(map[string]interface{})["ja3"].(map[string]interface{})["hash"])
									value, exists := suspsigmap[ja3hash];

									if exists{
										objmap["suspected"] = true
										objmap["ioc"]= fmt.Sprintf("%v",value)+","+ja3hash

									}

								}else if objmap["event_type"] == "flow" ||  objmap["event_type"] == "netflows"{
									bytestoserver,_ := strconv.Atoi(fmt.Sprintf("%v",objmap["flow"].(map[string]interface{})["bytes_toserver"]))
									bytestoclient,_ := strconv.Atoi(fmt.Sprintf("%v",objmap["flow"].(map[string]interface{})["bytes_toclient"]))


									//flowbytes := fmt.Sprintf("%v",objmap["flow"].(map[string]interface{})["bytes_toserver"]) + fmt.Sprintf("%v",objmap["flow"].(map[string]interface{})["bytes_toclient"])
									flowbytes := bytestoserver + bytestoclient
									objmap["flowbytes"] = flowbytes


								}else if objmap["event_type"] == "dns" {
									dnsrrname := fmt.Sprintf("%v",objmap["dns"].(map[string]interface{})["rrname"])
									value, exists := suspdomainmap[dnsrrname];
									if exists{
										objmap["suspected"] = true
										objmap["ioc"]= fmt.Sprintf("%v",value)+","+dnsrrname
									}
								}else if objmap["event_type"] == "fileinfo"  {

									md5key := fmt.Sprintf("%v",objmap["md5"]) //TBD
									value, exists := suspmd5map[md5key];
									if exists{
										objmap["suspected"] = true
										objmap["ioc"]= fmt.Sprintf("%v",value)+","+md5key
									}

								}else if objmap["event_type"] == "alert"  {

									srcip := fmt.Sprintf("%v",objmap["src_ip"])
									value, exists := defendedassetmap[srcip];
									if exists{
										objmap["defended"] = true
										objmap["ioc"]= fmt.Sprintf("%v",value)+","+srcip
									}else{
										dstip := fmt.Sprintf("%v",objmap["dest_ip"])
										value, exists := defendedassetmap[dstip];
										if exists{
											objmap["defended"] = true
											objmap["ioc"]= fmt.Sprintf("%v",value)+","+dstip
										}
									}
									if objmap["defended"] == false {
										srcport := fmt.Sprintf("%v",objmap["src_port"])

										value, exists = defendedservicemap[srcport];
										if exists{
											objmap["defended"] = true
											objmap["ioc"]= fmt.Sprintf("%v",value)+","+srcport
										}else{
											dstport := fmt.Sprintf("%v",objmap["dest_port"])
											value, exists := defendedservicemap[dstport];
											if exists{
												objmap["defended"] = true
												objmap["ioc"]= fmt.Sprintf("%v",value)+","+dstport
											}
										}
									}

								}


								if objmap["suspected"] == false{

									srcipvalue := fmt.Sprintf("%v", objmap["src_ip"])

									if srcipvalue != "" {
										value, exists := suspsipmap[srcipvalue];
										if exists {
											objmap["suspected"] = true
											objmap["ioc"] = fmt.Sprintf("%v", value) + "," + srcipvalue
										}
									}

								}
								if objmap["suspected"] == false{
									dstipvalue := fmt.Sprintf("%v", objmap["dest_ip"])
									if dstipvalue != "" {
										value, exists := suspsipmap[dstipvalue];
										if exists {
											objmap["suspected"] = true
											objmap["ioc"] = fmt.Sprintf("%v", value) + "," + dstipvalue
										}
									}
								}

								j, err := json.Marshal(objmap)
								if err != nil {
									fmt.Printf("Error: %s", err.Error())
								} else {
									//fmt.Println(string(j))
									//w.Write([]byte(j))
									//w.WriteByte('\n')
									//req := elastic.NewBulkIndexRequest().Index("investigate_" + fmt.Sprintf("%s", nc_nodename) + "_" + item.Name()).Type("_doc").Doc(string(j))
									req := elastic.NewBulkIndexRequest().Index("investigate_" + fmt.Sprintf("%s", nc_nodename) + "_" + item.Name()).Type("_doc").Doc(string(j))

									bulkRequest = bulkRequest.Add(req)
								}


							}
							if !processed {
								processed = true;
							}
							bulkRequest.Do(ctx)
							//
							//bulkResp, err := bulkRequest.Do(ctx)
							//
							//if err != nil {
							//	fmt.Println(err)
							//} else {
							//
							//	// If there is no error then get the Elasticsearch API response
							//	indexed := bulkResp.Indexed()
							//	fmt.Println("nbulkResp.Indexed():", indexed)
							//	//fmt.Println("bulkResp.Indexed() TYPE:", reflect.TypeOf(indexed))
							//	//fmt.Println("nBulk response Index:", indexed)
							//	////numrecords := 0
							//	//for _, info := range indexed {
							//	//	numrecords++
							//	//	//fmt.Println("nBulk response Index:", info)
							//	//	//fmt.Println("nBulk response Index:", info.Index)
							//	//}
							//	//fmt.Println("***********************************************************")
							//	//fmt.Println("FileName : NUMRECORDS !s",file.Name() , numrecords)
							//	//fmt.Println("***********************************************************")
							//
							//}
							//free memory
							bulkRequest = nil
							ctx = nil
							scanner = nil

							os.Mkdir(DESTDIR + item.Name(), 0755)
							err1 := os.Rename(WATCHDIR  + item.Name() + "/" + subitem.Name(), DESTDIR + item.Name() + "/"  + "_" + subitem.Name())
							if err1 != nil {
								fmt.Println(err1)
							}
							file.Close()
						}

					}

				}
			}

		}
		if !processed {
			initaugmentation(true,true,true,true,true,true,client) //tmp //comment this out on version before.44
			time.Sleep(8*time.Second);
			//elapsed := time.Since(start)
			//log.Printf("Time took %s", elapsed)
			//os.Exit(0)
		}
	}

}
