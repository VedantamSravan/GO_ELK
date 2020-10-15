package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	elastic "gopkg.in/olivere/elastic.v7"
)

//./NCECBackup nc_saverepository -repositoryname hellobabu1 -locationname hellobabu1 -snapshotname hellobabu1

// ./NCECBackup nc_restorerepository -resotrerepositoryname hellobabu1 -resotresnapshotname hellobabu1

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
func createRepo(repositoryname *string, locationname *string) {
	repositorynamevalue := *repositoryname
	locationnamevalue := *locationname

	client, err := GetESClient()
	if err != nil {
		fmt.Println("Error initializing : ", err)
		panic("Client fail ")
	}

	service := client.SnapshotCreateRepository(repositorynamevalue)
	service.Type("fs")
	service.Repository(repositorynamevalue)
	service.Settings(map[string]interface{}{
		"location": locationnamevalue,
	})
	service.Do(context.TODO())

}
func creatSnapshot(repositoryname *string, snapshotname *string) {
	repositorynamevalue := *repositoryname
	snapshotnamevalue := *snapshotname

	client, err := GetESClient()
	if err != nil {
		fmt.Println("Error initializing : ", err)
		panic("Client fail ")
	}

	service := client.SnapshotCreate(repositorynamevalue, snapshotnamevalue)
	service.WaitForCompletion(true)
	service.Repository(repositorynamevalue)
	service.BodyJson(map[string]interface{}{
		"indices": "_all",
	})
	service.Do(context.TODO())

}
func restorerepo(repositoryname *string, snapshotname *string) {
	repositorynamevalue := *repositoryname
	snapshotnamevalue := *snapshotname
	client, err := GetESClient()
	if err != nil {
		fmt.Println("Error initializing : ", err)
		panic("Client fail ")
	}
	service := client.SnapshotRestore(repositorynamevalue, snapshotnamevalue)
	service.Repository(repositorynamevalue)
	service.WaitForCompletion(true)
	service.IndexSettings(map[string]interface{}{
		"indices": "_all",
	})
	service.Do(context.TODO())

}
func main() {

	adddrepoCMD := flag.NewFlagSet("nc_saverepository", flag.ExitOnError)
	repositoryname := adddrepoCMD.String("repositoryname", "", "repositoryname")
	locationname := adddrepoCMD.String("locationname", "", "locationname")
	snapshotname := adddrepoCMD.String("snapshotname", "", "snapshotname")

	restorerepoCmd := flag.NewFlagSet("nc_restorerepository", flag.ExitOnError)
	resotrerepositoryname := restorerepoCmd.String("resotrerepositoryname", "", "resotrerepositoryname")
	resotresnapshotname := restorerepoCmd.String("resotresnapshotname", "", "resotresnapshotname")

	if len(os.Args) < 2 {
		fmt.Println("'nc_saverepository' or 'nc_resotrerepository' ")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "nc_saverepository":
		adddrepoCMD.Parse(os.Args[2:])
		fmt.Println(" repositoryname:", *repositoryname)
		fmt.Println("  locationname:", *locationname)
		fmt.Println("  snapshotname:", *snapshotname)
		createRepo(repositoryname, locationname)
		time.Sleep(2 * time.Second)
		creatSnapshot(repositoryname, snapshotname)

	case "nc_restorerepository":
		restorerepoCmd.Parse(os.Args[2:])
		fmt.Println("resotrerepositoryname:", *resotrerepositoryname)
		fmt.Println("resotresnapshotname:", *resotresnapshotname)
		restorerepo(resotrerepositoryname, resotresnapshotname)
	default:
		fmt.Println("'nc_saverepository' or 'nc_resotrerepository' ")
		os.Exit(1)
	}
}
