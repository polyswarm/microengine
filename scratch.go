package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"

	//"github.com/dutchcoders/go-clamd"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/gorilla/websocket"
	"github.com/mr-tron/base58/base58"
	uuid "github.com/satori/go.uuid"
)

// General response format from polyswarmd
type Success struct {
	Status string      `json:"status"`
	Result interface{} `json:"result"`
}

// Stats of artifacts from IPFS
type ArtifactStats struct {
	Hash           string
	BlockSize      int
	CumulativeSize int
	DataSize       int
	NumLinks       int
}

// Event notifcations delivered over websocket
type Event struct {
	Type string      `json:"event"`
	Data interface{} `json:"data"`
}

// Transactions to be signed delivered over websocket
type TxData struct {
	Value    *big.Int `json:"value"`
	To       string   `json:"to"`
	Gas      uint64   `json:"gas"`
	GasPrice *big.Int `json:"gasPrice"`
	ChainId  int64    `json:"chainId"`
	Nonce    uint64   `json:"nonce"`
	Data     string   `json:"data"`
}

type SignTxRequest struct {
	Id   uint64  `json:"id"`
	Data *TxData `json:"data"`
}

type SignTxResponse struct {
	Id      uint64 `json:"id"`
	ChainId uint64 `json:"chainId"`
	Data    string `json:"data"`
}

// Assertions that haven't yet been revealed
type SecretAssertion struct {
	Guid     string
	Verdicts []bool
	Metadata string
	Nonce    string
}

const TIMEOUT = 3000 * time.Second
const MAX_DATA_SIZE = 50 * 1024 * 1024
const BID_AMOUNT = 62500000000000000
const KEYFILE = "keyfile"
const PASSWORD = "password"

func readKeyFile(keyfile, auth string) (*keystore.Key, error) {
	keyjson, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	key, err := keystore.DecryptKey(keyjson, auth)
	if err != nil {
		return nil, err
	}

	return key, nil
}
// TODO: FIX TRANSACTION SIGNING LUL
func listenForTx(conn *websocket.Conn, key *keystore.Key) {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("error reading from websocket:", err)
			return
		}

		log.Println(string(message[:]))

		var req SignTxRequest
		json.Unmarshal(message, &req)

		data, err := hexutil.Decode(req.Data.Data)
		if err != nil {
			log.Println("invalid transaction data:", err)
			continue
		}

		signer := types.NewEIP155Signer(big.NewInt(req.Data.ChainId))
		tx := types.NewTransaction(req.Data.Nonce, common.HexToAddress(req.Data.To), req.Data.Value, req.Data.Gas, req.Data.GasPrice, data)
		signedTx, err := types.SignTx(tx, signer, key.PrivateKey)
		if err != nil {
			log.Println("error signing transaction:", err)
			continue
		}

		e, err := rlp.EncodeToBytes(signedTx)
		if err != nil {
			log.Println("error encoding transaction:", err)
			continue
		}

		response := &SignTxResponse{req.Id, uint64(req.Data.ChainId), hexutil.Encode(e)[2:]}

		j, err := json.Marshal(response)
		if err != nil {
			log.Println("error marshaling signed transaction:", err)
			continue
		}

		log.Println(string(j[:]))
		conn.WriteMessage(websocket.TextMessage, j)
	}
}


func connectToPolyswarm(host string) (*websocket.Conn, *websocket.Conn, error) {
	eventUrl := url.URL{Scheme: "ws", Host: host, Path: "/events/home"}
	txUrl := url.URL{Scheme: "ws", Host: host, Path: "/transactions"}

	timeout := time.After(TIMEOUT)
	tick := time.Tick(time.Second)

	for {
		select {
		case <-timeout:
			return nil, nil, errors.New("timeout waiting for polyswarm")
		case <-tick:
			eventConn, _, err := websocket.DefaultDialer.Dial(eventUrl.String(), nil)
			if err != nil {
				return nil, nil, err
			}

			txConn, _, err := websocket.DefaultDialer.Dial(txUrl.String(), nil)
			if err != nil {
				return nil, nil, err
			}

			return eventConn, txConn, nil
		}
	}
}

func retrieveFileFromIpfs(host, resource string, id int) (io.ReadCloser, error) {
	if len(resource) >= 100 {
		return nil, errors.New("ipfs resource too long")
	}

	if _, err := base58.Decode(resource); err != nil {
		return nil, err
	}

	client := http.Client{
		Timeout: time.Duration(10 * time.Second),
	}
	artifactURL := url.URL{Scheme: "http", Host: host, Path: path.Join("artifacts", resource, strconv.Itoa(id))}
	statResp, err := client.Get(artifactURL.String() + "/stat")
	if err != nil {
		return nil, err
	}
	defer statResp.Body.Close()

	var success Success
	json.NewDecoder(statResp.Body).Decode(&success)

	stats, ok := success.Result.(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid ipfs artifact stats")
	}

	dataSize, ok := stats["data_size"].(float64)
	if !ok {
		return nil, errors.New("invalid ipfs artifact stats")
	}

	if uint(dataSize) == 0 || uint(dataSize) > MAX_DATA_SIZE {
		return nil, errors.New("invalid ipfs artifact")
	}

	response, err := client.Get(artifactURL.String())
	if err != nil {
		return nil, err
	}

	return response.Body, nil
}
//TODO: gut this, document how to add clamd back
func scanBounty(polyswarmHost string,uri string){
	verdicts := make([]bool, 0, 256)//create verdicts array for future assertion
	var metadata bytes.Buffer

	log.Println("retrieving artifacts:", uri)
	for i:= 0; i < 256; i++ {
		r, err := retrieveFileFromIpfs(polyswarmHost, uri, i)
		if err!=nil {
                        log.Println("error retrieving artifact", i, ":", err)
                        break
                }
		defer r.Close()

                log.Println("got artifact, scanning:", uri)
//THIS NEEDS TO HAVE A WORKING ANALYSIS BACKEND AND IS NOT A VALID SCAN METHOD UNTIL YOU HAVE DONE SO
		response, err := YOURBACKEND.SCAN(r, make(chan bool))
                if err != nil {
                        log.Println("error scanning artifact:", err)
                        continue
                }
		log.Println("scanned artifact:", uri, i)

                verdict := false
                for s := range response {
                        verdict = verdict || s.Status == "FOUND"

                        verdicts = append(verdicts, s.Status == "FOUND")
                        metadata.WriteString(s.Description)
                        metadata.WriteString(";")
                }


	}//end 256-for loop
        return verdicts, metadata.String() //return verdicts(verdict array) at the end of the scanning
}

func makeBoolMask(len int) []bool {
	ret := make([]bool, len)
	for i := 0; i < len; i++ {
		ret[i] = true
	}
	return ret
}

func main() {
	time.Sleep(30 * time.Second)
	log.Println("Starting microengine")

	key, err := readKeyFile(KEYFILE, PASSWORD)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Using account", key.Address.Hex())

	//clamd, err := connectToClamd(os.Getenv("CLAMD_HOST"))
	//if err != nil {
	//	log.Fatalln(err)
	//} 

	polyswarmHost := os.Getenv("POLYSWARMD_HOST")
	eventConn, txConn, err := connectToPolyswarm(polyswarmHost)
	if err != nil {
		log.Fatalln(err)
	}
	defer eventConn.Close()
	defer txConn.Close()

	go listenForTx(txConn, key)

	revealDeadlines := make(map[uint64]SecretAssertion)

	for {
		_, message, err := eventConn.ReadMessage()
		if err != nil {
			log.Println("error reading from websocket:", err)
		}

		var event Event
		json.Unmarshal(message, &event)

		if event.Type == "bounty" {
			data, ok := event.Data.(map[string]interface{})
			if !ok {
				log.Println("invalid bounty object")
				continue
			}

			log.Println("got bounty:", data)

			guid, ok := data["guid"].(string)
			if !ok {
				log.Println("invalid guid")
				continue
			}

			uuid, err := uuid.FromString(guid)
			if err != nil {
				log.Println("invalid uuid:", err)
				continue
			}

			uri, ok := data["uri"].(string)
			if !ok {
				log.Println("invalid uri")
				continue
			}

			expirationStr, ok := data["expiration"].(string)
			if ok {
				log.Println("invalid expiration")
				continue
			}

			expiration, err := strconv.ParseUint(expirationStr, 0, 64)
			if err != nil {
				log.Println("invalid expiration")
				continue
			}
			//Put that backend here lad
			verdicts, metadata := scanBounty(polyswarmHost, YOUR_BACKEND_d, uri)

			var a struct {
				Verdicts []bool `json:"verdicts"`
				Mask     []bool `json:"mask"`
				Bid      string `json:"bid"`
			}

			a.Verdicts = verdicts
			a.Mask = makeBoolMask(len(verdicts))
			a.Bid = strconv.Itoa(BID_AMOUNT)

			j, err := json.Marshal(a)
			if err != nil {
				log.Println("error marshaling assertion:", err)
				continue
			}

			assertionURL := url.URL{Scheme: "http", Host: polyswarmHost, Path: path.Join("bounties", uuid.String(), "assertions"), RawQuery: "account=" + key.Address.Hex()}
			client := http.Client{
				Timeout: time.Duration(10 * time.Second),
			}

			response, err := client.Post(assertionURL.String(), "application/json", bytes.NewBuffer(j))
			if err != nil {
				log.Println("error posting assertion:", err)
				continue
			}
			defer response.Body.Close()

			var success Success
			json.NewDecoder(response.Body).Decode(&success)

			data, ok = success.Result.(map[string]interface{})
			if !ok {
				log.Println("error posting assertion:", err)
				continue
			}

			nonce, ok := data["nonce"].(string)
			if !ok {
				log.Println("error parsing nonce:", err)
				continue
			}

			// Wait a block to be safe
			revealDeadlines[expiration+1] = SecretAssertion{uuid.String(), verdicts, metadata, nonce}
		} else if event.Type == "block" {
			data, ok := event.Data.(map[string]interface{})
			if !ok {
				log.Println("invalid block event")
				continue
			}

			number, ok := data["number"].(float64)
			if !ok {
				log.Println("invalid block event")
				continue
			}

			assertion, ok := revealDeadlines[uint64(number)]
			if !ok {
				continue
			}

			var r struct {
				Nonce    string `json:"nonce"`
				Verdicts []bool `json:"verdicts"`
				Metadata []bool `json:"verdicts"`
			}

			j, err := json.Marshal(r)
			if err != nil {
				log.Println("error marshaling reveal:", err)
				continue
			}

			assertionURL := url.URL{Scheme: "http", Host: polyswarmHost, Path: path.Join("bounties", assertion.Guid, "assertions", "reveal"),
				RawQuery: "account=" + key.Address.Hex()}
			client := http.Client{
				Timeout: time.Duration(10 * time.Second),
			}

			client.Post(assertionURL.String(), "application/json", bytes.NewBuffer(j))
		}

		log.Println("recv:", event)
	}
}
