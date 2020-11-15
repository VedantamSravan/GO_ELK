package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"io/ioutil"
	elastic "gopkg.in/olivere/elastic.v7"
	"bufio"
	"strings"
)


const (
	WATCHDIR = "./storage2/investigator2/"
)

const (
indexName    = "continuum"
mappings = `{
	"settings": {
		"index": {
			"default_pipeline": "invpipeline",
			"number_of_shards": "1",
			"number_of_replicas": "0"
		}
	},
	"mappings": {
		"properties": {
			"@timestamp": {
				"type": "date_nanos"
			},
			"@version": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"Message": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"SessionInfo": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"Timestamp": {
				"type": "date"
			},
			"alert": {
				"properties": {
					"action": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"category": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"gid": {
						"type": "long"
					},
					"metadata": {
						"properties": {
							"affected_product": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"attack_target": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"created_at": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"deployment": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"former_category": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"impact_flag": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"malware_family": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"performance_impact": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"policy": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"ruleset": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"service": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"signature_severity": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"tag": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"updated_at": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							}
						}
					},
					"rev": {
						"type": "long"
					},
					"severity": {
						"type": "long"
					},
					"signature": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"signature_id": {
						"type": "long"
					}
				}
			},
			"app_proto": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"app_proto_expected": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"app_proto_orig": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"app_proto_tc": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"app_proto_ts": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"community_id": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"defended": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"dest_ip": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"dest_port": {
				"type": "long"
			},
			"dns": {
				"properties": {
					"aa": {
						"type": "boolean"
					},
					"answers": {
						"properties": {
							"rdata": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"rrname": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"rrtype": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"ttl": {
								"type": "long"
							}
						}
					},
					"authorities": {
						"properties": {
							"rrname": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"rrtype": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"ttl": {
								"type": "long"
							}
						}
					},
					"flags": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"grouped": {
						"properties": {
							"A": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"AAAA": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"CNAME": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"MX": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"PTR": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							}
						}
					},
					"id": {
						"type": "long"
					},
					"qr": {
						"type": "boolean"
					},
					"query": {
						"properties": {
							"id": {
								"type": "long"
							},
							"rrname": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"rrtype": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"tx_id": {
								"type": "long"
							},
							"type": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							}
						}
					},
					"ra": {
						"type": "boolean"
					},
					"rcode": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"rd": {
						"type": "boolean"
					},
					"rrname": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"rrtype": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"tc": {
						"type": "boolean"
					},
					"tx_id": {
						"type": "long"
					},
					"type": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"version": {
						"type": "long"
					}
				}
			},
			"email": {
				"properties": {
					"attachment": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"from": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"reply_to": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"status": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"subject": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"to": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					}
				}
			},
			"ether": {
				"properties": {
					"dst": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"src": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"type": {
						"type": "long"
					}
				}
			},
			"event_type": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"fileinfo": {
				"properties": {
					"filename": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"gaps": {
						"type": "boolean"
					},
					"magic": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"sid": {
						"type": "long"
					},
					"size": {
						"type": "long"
					},
					"state": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"stored": {
						"type": "boolean"
					},
					"tx_id": {
						"type": "long"
					}
				}
			},
			"flow": {
				"properties": {
					"age": {
						"type": "long"
					},
					"alerted": {
						"type": "boolean"
					},
					"bytes_toclient": {
						"type": "long"
					},
					"bytes_toserver": {
						"type": "long"
					},
					"emergency": {
						"type": "boolean"
					},
					"end": {
						"type": "date_nanos"
					},
					"pkts_toclient": {
						"type": "long"
					},
					"pkts_toserver": {
						"type": "long"
					},
					"reason": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"start": {
						"type": "date_nanos"
					},
					"state": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					}
				}
			},
			"flow_id": {
				"type": "long"
			},
			"geo_dest_ip": {
				"properties": {
					"city_name": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"continent_name": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword"
							}
						}
					},
					"country_iso_code": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword"
							}
						}
					},
					"location": {
						"type": "geo_point"
					},
					"region_iso_code": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"region_name": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					}
				}
			},
			"geo_src_ip": {
				"properties": {
					"city_name": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"continent_name": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword"
							}
						}
					},
					"country_iso_code": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword"
							}
						}
					},
					"location": {
						"type": "geo_point"
					},
					"region_iso_code": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"region_name": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					}
				}
			},
			"host": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"http": {
				"properties": {
					"hostname": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"http_content_type": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"http_method": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"http_port": {
						"type": "long"
					},
					"http_refer": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"http_user_agent": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"length": {
						"type": "long"
					},
					"protocol": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"redirect": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"status": {
						"type": "long"
					},
					"url": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					}
				}
			},
			"icmp_code": {
				"type": "long"
			},
			"icmp_type": {
				"type": "long"
			},
			"ioc": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"ip_map_id": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"md5": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"metadata": {
				"properties": {
					"flowbits": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					}
				}
			},
			"nc_id": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"nfs": {
				"properties": {
					"file_tx": {
						"type": "boolean"
					},
					"filename": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"hhash": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"id": {
						"type": "long"
					},
					"procedure": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"status": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"type": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"version": {
						"type": "long"
					},
					"write": {
						"properties": {
							"chunks": {
								"type": "long"
							},
							"first": {
								"type": "boolean"
							},
							"last": {
								"type": "boolean"
							},
							"last_xid": {
								"type": "long"
							}
						}
					}
				}
			},
			"nodename": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"path": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"pcap_cnt": {
				"type": "long"
			},
			"proto": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"response_icmp_code": {
				"type": "long"
			},
			"response_icmp_type": {
				"type": "long"
			},
			"rpc": {
				"properties": {
					"auth_type": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"creds": {
						"properties": {
							"gid": {
								"type": "long"
							},
							"machine_name": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"uid": {
								"type": "long"
							}
						}
					},
					"status": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"xid": {
						"type": "long"
					}
				}
			},
			"rtp_meta": {
				"properties": {
					"invitee": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"invitee_ip": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"inviter": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"inviter_ip": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					}
				}
			},
			"sip_meta": {
				"properties": {
					"c_seq": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"call_id": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"client_tag": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"from": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"length": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"request_method": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"response_method": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"server_tag": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"to": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					}
				}
			},
			"smb": {
				"properties": {
					"access": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"accessed": {
						"type": "long"
					},
					"changed": {
						"type": "long"
					},
					"client_dialects": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"command": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"created": {
						"type": "long"
					},
					"dialect": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"disposition": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"filename": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"fuid": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"id": {
						"type": "long"
					},
					"modified": {
						"type": "long"
					},
					"named_pipe": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"ntlmssp": {
						"properties": {
							"domain": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"host": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"user": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							}
						}
					},
					"request": {
						"properties": {
							"native_lm": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"native_os": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							}
						}
					},
					"response": {
						"properties": {
							"native_lm": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"native_os": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							}
						}
					},
					"server_guid": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"service": {
						"properties": {
							"request": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							},
							"response": {
								"type": "text",
								"fields": {
									"keyword": {
										"type": "keyword",
										"ignore_above": 256
									}
								}
							}
						}
					},
					"session_id": {
						"type": "long"
					},
					"share": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"size": {
						"type": "long"
					},
					"status": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"status_code": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"tree_id": {
						"type": "long"
					}
				}
			},
			"smtp": {
				"properties": {
					"helo": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"mail_from": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"rcpt_to": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					}
				}
			},
			"src_ip": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"src_port": {
				"type": "long"
			},
			"tags": {
				"type": "text",
				"fields": {
					"keyword": {
						"type": "keyword",
						"ignore_above": 256
					}
				}
			},
			"tcp": {
				"properties": {
					"ack": {
						"type": "boolean"
					},
					"cwr": {
						"type": "boolean"
					},
					"ecn": {
						"type": "boolean"
					},
					"fin": {
						"type": "boolean"
					},
					"psh": {
						"type": "boolean"
					},
					"rst": {
						"type": "boolean"
					},
					"state": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"syn": {
						"type": "boolean"
					},
					"tcp_flags": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"tcp_flags_tc": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"tcp_flags_ts": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					}
				}
			},
			"timestamp": {
				"type": "date_nanos"
			},
			"tls": {
				"properties": {
					"fingerprint": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"from_proto": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"issuerdn": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"ja3": {
						"type": "object"
					},
					"notafter": {
						"type": "date_nanos"
					},
					"notbefore": {
						"type": "date_nanos"
					},
					"serial": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"session_resumed": {
						"type": "boolean"
					},
					"sni": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"subject": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					},
					"version": {
						"type": "text",
						"fields": {
							"keyword": {
								"type": "keyword",
								"ignore_above": 256
							}
						}
					}
				}
			},
			"tx_id": {
				"type": "long"
			},
			"vlan": {
				"type": "long"
			}
		}
	}
}`
)
/*

curl --header "Content-Type: application/json" -X PUT "http://localhost:9200/continuum"  -d '{"settings":{"index":{"default_pipeline":"invpipeline","number_of_shards":"1","number_of_replicas":"0"}},"mappings":{"properties":{"@timestamp":{"type":"date_nanos"},"@version":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"Message":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"SessionInfo":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"Timestamp":{"type":"date"},"alert":{"properties":{"action":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"category":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"gid":{"type":"long"},"metadata":{"properties":{"affected_product":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"attack_target":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"created_at":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"deployment":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"former_category":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"impact_flag":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"malware_family":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"performance_impact":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"policy":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"ruleset":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"service":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"signature_severity":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"tag":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"updated_at":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"rev":{"type":"long"},"severity":{"type":"long"},"signature":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"signature_id":{"type":"long"}}},"app_proto":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"app_proto_expected":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"app_proto_orig":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"app_proto_tc":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"app_proto_ts":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"community_id":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"defended":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"dest_ip":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"dest_port":{"type":"long"},"dns":{"properties":{"aa":{"type":"boolean"},"answers":{"properties":{"rdata":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"rrname":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"rrtype":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"ttl":{"type":"long"}}},"authorities":{"properties":{"rrname":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"rrtype":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"ttl":{"type":"long"}}},"flags":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"grouped":{"properties":{"A":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"AAAA":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"CNAME":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"MX":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"PTR":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"id":{"type":"long"},"qr":{"type":"boolean"},"query":{"properties":{"id":{"type":"long"},"rrname":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"rrtype":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"tx_id":{"type":"long"},"type":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"ra":{"type":"boolean"},"rcode":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"rd":{"type":"boolean"},"rrname":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"rrtype":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"tc":{"type":"boolean"},"tx_id":{"type":"long"},"type":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"version":{"type":"long"}}},"email":{"properties":{"attachment":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"from":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"reply_to":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"status":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"subject":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"to":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"ether":{"properties":{"dst":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"src":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"type":{"type":"long"}}},"event_type":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"fileinfo":{"properties":{"filename":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"gaps":{"type":"boolean"},"magic":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"sid":{"type":"long"},"size":{"type":"long"},"state":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"stored":{"type":"boolean"},"tx_id":{"type":"long"}}},"flow":{"properties":{"age":{"type":"long"},"alerted":{"type":"boolean"},"bytes_toclient":{"type":"long"},"bytes_toserver":{"type":"long"},"emergency":{"type":"boolean"},"end":{"type":"date_nanos"},"pkts_toclient":{"type":"long"},"pkts_toserver":{"type":"long"},"reason":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"start":{"type":"date_nanos"},"state":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"flow_id":{"type":"long"},"geo_dest_ip":{"properties":{"city_name":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"continent_name":{"type":"text","fields":{"keyword":{"type":"keyword"}}},"country_iso_code":{"type":"text","fields":{"keyword":{"type":"keyword"}}},"location":{"type":"geo_point"},"region_iso_code":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"region_name":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"geo_src_ip":{"properties":{"city_name":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"continent_name":{"type":"text","fields":{"keyword":{"type":"keyword"}}},"country_iso_code":{"type":"text","fields":{"keyword":{"type":"keyword"}}},"location":{"type":"geo_point"},"region_iso_code":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"region_name":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"host":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"http":{"properties":{"hostname":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"http_content_type":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"http_method":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"http_port":{"type":"long"},"http_refer":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"http_user_agent":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"length":{"type":"long"},"protocol":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"redirect":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"status":{"type":"long"},"url":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"icmp_code":{"type":"long"},"icmp_type":{"type":"long"},"ioc":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"ip_map_id":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"md5":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"metadata":{"properties":{"flowbits":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"nc_id":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"nfs":{"properties":{"file_tx":{"type":"boolean"},"filename":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"hhash":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"id":{"type":"long"},"procedure":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"status":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"type":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"version":{"type":"long"},"write":{"properties":{"chunks":{"type":"long"},"first":{"type":"boolean"},"last":{"type":"boolean"},"last_xid":{"type":"long"}}}}},"nodename":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"path":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"pcap_cnt":{"type":"long"},"proto":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"response_icmp_code":{"type":"long"},"response_icmp_type":{"type":"long"},"rpc":{"properties":{"auth_type":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"creds":{"properties":{"gid":{"type":"long"},"machine_name":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"uid":{"type":"long"}}},"status":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"xid":{"type":"long"}}},"rtp_meta":{"properties":{"invitee":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"invitee_ip":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"inviter":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"inviter_ip":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"sip_meta":{"properties":{"c_seq":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"call_id":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"client_tag":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"from":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"length":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"request_method":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"response_method":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"server_tag":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"to":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"smb":{"properties":{"access":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"accessed":{"type":"long"},"changed":{"type":"long"},"client_dialects":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"command":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"created":{"type":"long"},"dialect":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"disposition":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"filename":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"fuid":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"id":{"type":"long"},"modified":{"type":"long"},"named_pipe":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"ntlmssp":{"properties":{"domain":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"host":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"user":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"request":{"properties":{"native_lm":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"native_os":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"response":{"properties":{"native_lm":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"native_os":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"server_guid":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"service":{"properties":{"request":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"response":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"session_id":{"type":"long"},"share":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"size":{"type":"long"},"status":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"status_code":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"tree_id":{"type":"long"}}},"smtp":{"properties":{"helo":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"mail_from":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"rcpt_to":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"src_ip":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"src_port":{"type":"long"},"tags":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"tcp":{"properties":{"ack":{"type":"boolean"},"cwr":{"type":"boolean"},"ecn":{"type":"boolean"},"fin":{"type":"boolean"},"psh":{"type":"boolean"},"rst":{"type":"boolean"},"state":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"syn":{"type":"boolean"},"tcp_flags":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"tcp_flags_tc":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"tcp_flags_ts":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"timestamp":{"type":"date_nanos"},"tls":{"properties":{"fingerprint":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"from_proto":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"issuerdn":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"ja3":{"type":"object"},"notafter":{"type":"date_nanos"},"notbefore":{"type":"date_nanos"},"serial":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"session_resumed":{"type":"boolean"},"sni":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"subject":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"version":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}}}},"tx_id":{"type":"long"},"vlan":{"type":"long"}}}}'
 */

func main() {


	files, err := ioutil.ReadDir(WATCHDIR)
	if err != nil {
		log.Fatal(err)
	}
	var client *elastic.Client
	hostAddr := "" // Elasticsearch host IP address
	client, _ = elastic.NewClient(elastic.SetSniff(false), elastic.SetURL(fmt.Sprintf("http://%s:9200/", hostAddr)))
	ctx := context.Background()

	if exists, _ := client.IndexExists(indexName).Do(ctx); !exists {
		fmt.Println("CreateIndex", indexName)
		if _, err := client.CreateIndex(indexName).Body(mappings).Do(ctx); err != nil {
			log.Printf("elasticsearch CreateIndex err: %s", err.Error())
		}
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".") {
			continue
		} else {
			file, err := os.Open(WATCHDIR+file.Name())
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			//e:=0
			filesize, err := os.Stat(file.Name())
			if err != nil {
				fmt.Println(err)
				continue
			}
			bulkRequest := client.Bulk()
			// get file size
			fsize := int(filesize.Size())
			i := 1
			for scanner.Scan() {
				if i == fsize {
					break
				}
				req := elastic.NewBulkIndexRequest().Index(indexName).Pipeline("invpipeline").Doc(scanner.Text())

				bulkRequest = bulkRequest.Add(req)
				i++

			}
			bulkRequest.Do(ctx)
			log.Println("Bulk request is done")
		}
	}
}
