package main

import (
	//"context"
	//"encoding/json"
	//"fmt"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/net/context"
)

const (
	CONNECTIONSTRING = "mongodb://localhost:27017"
	DBNAME           = "testing1234"
)

var db *mongo.Database
var client *mongo.Client

type Element struct {
	Stime   uint64 `json:"stime"`
	Srcip   uint64 `json:"srcip"`
	Dstip   uint64 `json:"dstip"`
	Srcport uint32 `json:"srcport"`
	Dstport uint32 `json:"dstport"`
	Proto   uint16 `json:"proto"`
	Qid     string `json:"qid"`
	Flowid  uint64 `json:"flowid"`
}

//func init() {
//	ctx := context.Background()
//	ctx, err := context.WithTimeout(context.Background(), 120*time.Second)
//	if err != nil {
//		log.Println("connection timeout error", err)
//	}
//	clientOptions := options.Client().ApplyURI(CONNECTIONSTRING)
//	client, _ = mongo.Connect(ctx, clientOptions)
//	db = client.Database(DBNAME)
//}
func main() {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// create a mongo client
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017/"))
	if err != nil {
		log.Fatal(err)
	}

	// disconnect from mongo
	defer client.Disconnect(ctx)

	args := os.Args[1:]
	if len(args) > 0 {
		btime, _ := strconv.ParseUint(args[0], 10, 64)
		etime, _ := strconv.ParseUint(args[1], 10, 64)

		//searchstring:=args[2]
		//searchname := args[3]
		//limit, _ := strconv.ParseInt(args[4], 10, 64)
		for d := btime / 86400; d <= etime/86400; d++ {

			findOptions := options.Find()
			findOptions.SetLimit(1000)

			//col := strconv.FormatUint(d, 10)
			col := client.Database("testing1234").Collection("metadata" + strconv.FormatUint(d, 10))
			//col := db.Collection(strconv.FormatUint(d, 10))

			fmt.Println(col.Name())
			//proto arg
			proto := strings.Split(args[3], " ")
			protoSlice := []int{}
			for _, num := range proto {
				val, _ := strconv.Atoi(num)
				protoSlice = append(protoSlice, val)
			}

			//port arg
			port := strings.Split(args[3], " ")
			portSlice := []int{}
			for _, num := range port {
				val, _ := strconv.Atoi(num)
				portSlice = append(portSlice, val)
			}

			cursor, err := col.Find(ctx, bson.M{
				"$and": []bson.M{
					bson.M{"stime": bson.M{
						"$gt": 1610657874,
						"$lt": 1610746182},
					},
					bson.M{"proto": bson.M{
						"$in": protoSlice,
						},
					},
					bson.M{"port": bson.M{
						"$in": portSlice,
					},
					},
				},
			})

			if err != nil {
				log.Fatal(err)
			}

			// iterate through all documents
			for cursor.Next(ctx) {
				var p Element
				// decode the document
				if err := cursor.Decode(&p); err != nil {
					log.Fatal(err)
				}
				fmt.Printf("post: %+v\n", p)
			}

			if err := cursor.Err(); err != nil {
				log.Fatal(err)
			}

		}
	}
}

//func sliceAtoi(sa []string) ([]int, error) {
//	si := make([]int, 0, len(sa))
//	for _, a := range sa {
//		i, err := strconv.Atoi(a)
//		if err != nil {
//			return si, err
//		}
//		si = append(si, i)
//	}
//	return si, nil
//}
