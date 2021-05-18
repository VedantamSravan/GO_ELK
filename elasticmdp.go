package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	elastic "github.com/olivere/elastic/v7"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
	"strconv"
)

const (
	WATCHDIR = "/storage0/dbpipe/"
	DESTDIR  = "/storage0/tmp/logforwarder/"


)

var suspsigmap = make(map[string]string)
var suspsipmap = make(map[string]string)
var suspdomainmap = make(map[string]string)
var suspmd5map = make(map[string]string)
var defendedassetmap = make(map[string]string)
var defendedservicemap = make(map[string]string)

func initaugmentation(instanceindex string,client *elastic.Client ) {
	fileprefix:="/dev/shm/"+instanceindex+"_"
	if fileExists(fileprefix+"suspicioussignatures.refresh") {
		result, err := client.Search().Index("augmentation").Query(elastic.NewMatchQuery("augtype", "suspicioussignatures")).From(1).Size(2000).Do(context.TODO())
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
		os.Remove(fileprefix+"suspicioussignatures.refresh")
	}
	if fileExists(fileprefix+"suspiciousips.refresh") {
		result, err := client.Search().Index("augmentation").Query(elastic.NewMatchQuery("augtype", "suspiciousips")).From(1).Size(2000).Do(context.TODO())
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
		os.Remove(fileprefix+"suspiciousips.refresh")
	}

	if fileExists(fileprefix+"suspiciousdomains.refresh") {
		result, err := client.Search().Index("augmentation").Query(elastic.NewMatchQuery("augtype", "suspiciousdomains")).From(1).Size(2000).Do(context.TODO())
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

			fmt.Println(mapresult)
		}
		os.Remove(fileprefix+"suspiciousdomains.refresh")
	}

	if fileExists(fileprefix+"suspmd5sums.refresh") {
		result, err := client.Search().Index("augmentation").Query(elastic.NewMatchQuery("augtype", "suspmd5sums")).From(1).Size(2000).Do(context.TODO())
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
		os.Remove(fileprefix+"suspmd5sums.refresh")

	}

	if fileExists(fileprefix+"defendedassets.refresh") {
		result, err := client.Search().Index("augmentation").Query(elastic.NewMatchQuery("augtype", "defendedassets")).From(1).Size(2000).Do(context.TODO())
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
		os.Remove(fileprefix+"defendedassets.refresh")

	}

	if fileExists(fileprefix+"defendedservices.refresh") {
		result, err := client.Search().Index("augmentation").Query(elastic.NewMatchQuery("augtype", "defendedservices")).From(1).Size(2000).Do(context.TODO())
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
		os.Remove(fileprefix+"defendedservices.refresh")

	}
}

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

func main() {

	instanceindex := os.Getenv("INSTANCEINDEX")
	var tempindex int
	tempindex1, err := fmt.Sscanf(instanceindex,"%d",&tempindex)
	if err != nil || tempindex1 > 10{
		fmt.Println(err)
		os.Exit(1) //0 means success grater than > 0 is bad
	}


	layout := "2006-01-02T15:04:05"
	//suspiciousips
	suspips,err := ioutil.ReadFile("/storage0/configuration/suspips.json")
	if err != nil{
		fmt.Println("File Doesnot exist")
	}
	var suspipsmap map[string]interface{}
	if err := json.Unmarshal([]byte(suspips), &suspipsmap); err != nil {
		fmt.Println(err)
	}
	nc_nodename:="localhost"
	nc_nodenamebytes,err := ioutil.ReadFile("/usr/local/ui/public/data/cs_hostname.ini")
	if err == nil{
		nc_nodename = strings.TrimSuffix(fmt.Sprintf("%s",nc_nodenamebytes), "\n")
	}
	client, err := GetESClient()
	if err != nil {
		fmt.Println("%v", err)
	}
	initaugmentation(instanceindex,client) //comment this out on version before.44

	//start := time.Now()
	var minfilemap = make(map[int64]*os.File)
	var bufminfilemap = make(map[int64]*bufio.Writer)

	for true {

		items, err := ioutil.ReadDir(WATCHDIR + instanceindex)
		if err != nil || len(items) == 0 {

			fmt.Println("Sleeping...");
			time.Sleep(8 * time.Second)


		}
		processed := false
		for _, item := range items {
			//fmt.Println(item)
			if item.IsDir() {
				subitems, _ := ioutil.ReadDir(WATCHDIR + instanceindex + "/" + item.Name())
				for _, subitem := range subitems {
					if !subitem.IsDir() && !strings.HasPrefix(subitem.Name(), ".") {
						file, err := os.Open(WATCHDIR + instanceindex + "/" + item.Name() + "/" + subitem.Name())
						if err != nil {
							fmt.Println(err)
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
								if objmap == nil {
									fmt.Println(file.Name())
									continue

								}

								//fmt.Println(objmap["rts"])
								//fmt.Println(reflect.TypeOf(objmap["rts"]))
								//var epochseconds uint64 = 0
								//if objmap["rts"] != nil{
								//	epochseconds = objmap["rts"].(uint64)
								//	time.Parse(layout, "2021-05-18T01:34:02")
								//}
								timestamparr:= strings.Split(fmt.Sprintf("%v",objmap["timestamp"]),".")
								tepochseconds,_ := time.Parse(layout, timestamparr[0])


								epochseconds:=tepochseconds.Unix()
								epochmin := epochseconds/60
								fpvalue, rtsexists := minfilemap[epochmin]
								wfpvalue,_ := bufminfilemap[epochmin]
								if !rtsexists{
									currHour := epochseconds/3600
									currMin := (epochseconds/60)%60
									currDayMin := (epochseconds/60)%1440
									filepath := fmt.Sprintf("/storage0/int%d/%d_%02d/%s.log",currDayMin,currHour,currMin,objmap["event_type"])

									fpvalue,err = os.OpenFile(filepath,os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
									if err != nil {
										fmt.Println(err)
									}else{
										wfpvalue = bufio.NewWriter(fpvalue)
										minfilemap[epochmin] = fpvalue
										bufminfilemap[epochmin] = wfpvalue
									}

								}
								objmap["nodename"] = fmt.Sprintf("%s",nc_nodename)
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
									req := elastic.NewBulkIndexRequest().Index("investigate_" + fmt.Sprintf("%s", nc_nodename) + "_" + item.Name()).Type("_doc").Doc(string(j))
									bulkRequest = bulkRequest.Add(req)
									if fpvalue != nil {
										wfpvalue.Write([]byte(j))
										wfpvalue.WriteByte('\n')
									}
								}

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
							err1 := os.Rename(WATCHDIR  + instanceindex + "/"+ item.Name() + "/" + subitem.Name(), DESTDIR +  subitem.Name() + ".json")
							if err1 != nil {
								fmt.Println(err1)
							}
							file.Close()
							for key, element := range bufminfilemap {
								if element != nil {
									element.Flush()
									delete(bufminfilemap, key)
								}

							}
							for key, element := range minfilemap {
								if element != nil {
									element.Close()
									delete(minfilemap, key)
								}
							}
							minfilemap = make(map[int64]*os.File)
							bufminfilemap = make(map[int64]*bufio.Writer)

						}

					}

				}
				os.Remove(WATCHDIR + instanceindex + "/" + item.Name())
			}



		}
		if !processed {
			initaugmentation(instanceindex,client) //tmp //comment this out on version before.44
			time.Sleep(8*time.Second);
			//elapsed := time.Since(start)
			//log.Printf("Time took %s", elapsed)
			//os.Exit(0)
		}
	}

}
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
