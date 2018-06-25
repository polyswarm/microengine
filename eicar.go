package main

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "io/ioutil"
    "log"
    "math/big"
    "net/http"
    "net/url"
    "path"
    "strconv"
    "time"
    "github.com/ethereum/go-ethereum/accounts/keystore"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/common/hexutil"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/rlp"
    "github.com/gorilla/websocket"
    "github.com/mr-tron/base58/base58/base58"
    uuid "github.com/satori/go.uuid"
)

// General response format from polyswarmd
type Success struct {
    Status string      `json:"status"`
    Result interface{} `json:"result"`
}

type Bounty struct {
    Verdicts []bool `json:"verdicts"`
    Mask     []bool `json:"mask"`
    Bid      string `json:"bid"`
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

const ARTIFACT_MAXIMUM = 256
const BID_AMOUNT       = 62500000000000000
const KEYFILE          = "keyfile"
const MAX_DATA_SIZE    = 50 * 1024 * 1024
const PASSWORD         = "password"
const POLYSWARM_HOST   = "localhost:31337"
const TIMEOUT          = 3000 * time.Second

const FOUND            = "FOUND"
const NOT_FOUND        = "NOT_FOUND"

//THIS NEEDS TO HAVE A WORKING ANALYSIS BACKEND AND IS NOT A VALID SCAN METHOD UNTIL YOU HAVE DONE SO
/*
 *
 * All you need to do for scanning is to write here:
 * [Return values]
 *
 * status:     FOUND / NOT_FOUND
 * decription: description on the infection if infected
 * error:      runtime error, if raised
 *
 */
func scan(artifact string)(string, string, error){
    status      := NOT_FOUND
    description := ""

    if artifact.Contains('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'){
        status      = FOUND      
        description = "EICAR Detected." 
    }

    return status, description, nil
}

func main() {
    say("Starting microengine")
    if !exists(KEYFILE) { say("keyfile is missing: " + KEYFILE); return }

    key, err := readKeyFile(KEYFILE, PASSWORD)
    alertFatal(err)

    say(fmt.Sprintf("Using account %s", key.Address.Hex()))
 
    /*
     *
     * Websocket connection
     *
     */
    eventConn, txConn, err := connectToPolyswarm(polyswarmHost())
    if err != nil { log.Fatalln(err) }
    defer eventConn.Close()
    defer txConn.Close()

    go listenForTransaction(txConn, key)
    revealDeadlines := makeDeadLine()

    for {
        _, message, err := eventConn.ReadMessage()
        if err != nil { log.Println("error reading from websocket:", err) }

        var event Event
        json.Unmarshal(message, &event)

        if event.Type == "bounty" {
            data, ok           := getBounty(event);        if !ok { continue }
            guid, ok           := pop(data, "guid");       if !ok { continue }

            uuid, err          := uuid.FromString(guid)
            if err             != nil { log.Println("invalid uuid:", err); continue }

            uri, ok            := pop(data, "uri");        if !ok { continue }
            expirationStr, ok  := pop(data, "expiration"); if !ok { continue }

            expiration, err    := strconv.ParseUint(expirationStr, 0, 64)
            if err             != nil { log.Println("invalid expiration"); continue }

            verdicts, metadata := scanBounty(polyswarmHost(), uri)
            j, err             := getBountyJson(verdicts); if err != nil { continue }

            assertionURL       := assertionUrl(key.Address.Hex(), uuid.String())
            client             := http.Client{ Timeout: time.Duration(10 * time.Second), }
            response, err      := client.Post(assertionURL, "application/json", bytes.NewBuffer(j))

            if err             != nil { log.Println("error posting assertion:", err); continue }
            defer response.Body.Close()

            var success Success
            json.NewDecoder(response.Body).Decode(&success)

            nonce, ok          := pop(data, "nonce");        if !ok { continue }
            revealDeadlines     = waitBlockToBeSafe(metadata, verdicts, nonce, uuid.String(), revealDeadlines, expiration)
        }
        log.Println("recv:", event)
    }
}

func waitBlockToBeSafe(
         metadata        string,
         verdicts        []bool,
         nonce           string,
         uuid            string,
         revealDeadlines map[uint64]SecretAssertion,
         expiration      uint64,
     )(map[uint64]SecretAssertion){

    revealDeadlines[expiration+1] = SecretAssertion{uuid, verdicts, metadata, nonce}
    return revealDeadlines

}

func assertionUrl(key string, uuid string)(string){
    _path := path.Join("bounties", uuid, "assertions")
    _url  := url.URL{Scheme: "http", Host: polyswarmHost(), Path: _path, RawQuery: "account=" + key}
    return _url.String()
}

func pop(data map[string]interface{}, tag string)(string, bool){
    value, ok := data[tag].(string)
    if !ok { log.Println("invalid", tag) }
    return value, ok
}

func getBounty(event Event)(map[string]interface{}, bool){
    data, ok := event.Data.(map[string]interface{})
    if !ok { say("invalid bounty object") }
    log.Println("got bounty:", data)
    return data, ok
}

func alertFatal(err error){
   if err != nil {
       log.Fatalln(err)
   }
}

func exists(name string) bool {
    _, err := os.Stat(name)
    return !os.IsNotExist(err)
}

func readKeyFile(keyfile, auth string) (*keystore.Key, error) {
     keyjson, err := ioutil.ReadFile(keyfile);           if err != nil { return nil, err }
     key, err     := keystore.DecryptKey(keyjson, auth); if err != nil { return nil, err }
     return key, nil
}

func say(message string){
    log.Println(message)
}

func jsonify(req SignTxRequest, message []byte)(SignTxRequest){
    json.Unmarshal(message, &req)
    return req
}

func buildSigner(chainId int64)(types.EIP155Signer){
    return types.NewEIP155Signer(big.NewInt(chainId))
}

func buildTransaction(req SignTxRequest, data []byte)(*types.Transaction){
     return types.NewTransaction(
                req.Data.Nonce,
                common.HexToAddress(req.Data.To),
                req.Data.Value,
                req.Data.Gas,
                req.Data.GasPrice,
                data,
            )
}

func signTransactionResponse(req SignTxRequest, e []byte)(*SignTxResponse){
    return &SignTxResponse{req.Id, uint64(req.Data.ChainId), hexutil.Encode(e)[2:]}
}

// TODO: FIX TRANSACTION SIGNING LUL
func listenForTransaction(conn *websocket.Conn, key *keystore.Key) {
    for {
        _, message, err := conn.ReadMessage()
        if err != nil { log.Println("websocket read failed", err); return }

        say(string(message[:]))
        var req SignTxRequest
        req        = jsonify(req, message)
        data, err := hexutil.Decode(req.Data.Data)
        if err != nil { log.Println("invalid transaction data:", err) ; continue }

        signer        := buildSigner(req.Data.ChainId)
        tx            := buildTransaction(req, data)
        signedTx, err := types.SignTx(tx, signer, key.PrivateKey)
        if err != nil { log.Println("error signing transaction:", err); continue } 

        e, err        := rlp.EncodeToBytes(signedTx)
        if err != nil { log.Println("error encoding transaction:", err); continue }

        response := signTransactionResponse(req, e)

        j, err := json.Marshal(response)
        if err != nil { log.Println("error marshaling signed transaction:", err); continue }

        say(string(j[:]))
        conn.WriteMessage(websocket.TextMessage, j)
    }
}

func connectToPolyswarm(host string) (*websocket.Conn, *websocket.Conn, error) {
    timeout  := time.After(TIMEOUT)
    tick     := time.Tick(time.Second)
    eventUrl := url.URL{Scheme: "ws", Host: host, Path: "/events/home"}
    txUrl    := url.URL{Scheme: "ws", Host: host, Path: "/transactions"}

    for {
        select {
        case <-timeout:
            return nil, nil, errors.New("timeout waiting for polyswarm")
        case <-tick:
            eventConn, _, err := websocket.DefaultDialer.Dial(eventUrl.String(), nil)
            if err != nil { return nil, nil, err }

            txConn, _, err := websocket.DefaultDialer.Dial(txUrl.String(), nil)
            if err != nil { return nil, nil, err }
                
            return eventConn, txConn, nil
        }
    }
}

func makeDeadLine()(map[uint64]SecretAssertion){
    return make(map[uint64]SecretAssertion)
}

func errorRetrievingArtifact(i int, err error){
    log.Println("error retrieving artifact", i, ":", err)
}

func set_verdicts(status string, verdicts []bool)([]bool){
    // verdict := false
    // verdict  = status == FOUND
    verdicts = append(verdicts, status == FOUND)
    return verdicts
}

func set_metadata(description string, metadata bytes.Buffer)(bytes.Buffer){
    metadata.WriteString(description)
    metadata.WriteString(";")
    return metadata
}

func scanBounty(polyswarmHost string,uri string)([]bool, string){
    verdicts := make([]bool, 0, 256) //create verdicts array for future assertion
    var metadata bytes.Buffer

    log.Println("retrieving artifacts:", uri)
    for i:= 0; i < ARTIFACT_MAXIMUM; i++ {
        artifact, err := retrieveFileFromIpfs(polyswarmHost, uri, i)
        if err        != nil { errorRetrievingArtifact(i, err); break }
        defer artifact.Close()
        log.Println("got artifact, scanning:", uri)

        buf         := new(bytes.Buffer)
        buf.ReadFrom(artifact)
        artifactStr := buf.String()
        fmt.Printf(artifactStr)

        status, description, err := scan(artifactStr)

        if err != nil { log.Println("error scanning artifact:", err); continue }
        log.Println("scanned artifact:", uri, i)

        verdicts = set_verdicts(status, verdicts)
        metadata = set_metadata(description, metadata)
    }
    return verdicts, metadata.String() 
}

func getBountyJson(verdicts []bool)([]byte, error){
    var bounty Bounty 
    bounty.Verdicts = verdicts
    bounty.Mask     = makeBoolMask(len(verdicts))
    bounty.Bid      = strconv.Itoa(BID_AMOUNT)

    j, err := json.Marshal(bounty)
    if err != nil { log.Println("error marshaling assertion:", err) }
    return j, err
}

func retrieveFileFromIpfs(host, resource string, id int) (io.ReadCloser, error) {
    if len(resource) >= 100 { return nil, errors.New("ipfs resource too long") }

    if _, err     := base58.Decode(resource); err != nil { return nil, err }
    client        := http.Client{ Timeout: time.Duration(10 * time.Second), }
    artifactURL   := url.URL{Scheme: "http", Host: host, Path: path.Join("artifacts", resource, strconv.Itoa(id))}
    statResp, err := client.Get(artifactURL.String() + "/stat"); if err != nil { return nil, err }

    defer statResp.Body.Close()

    var success Success
    json.NewDecoder(statResp.Body).Decode(&success)

    stats, ok := success.Result.(map[string]interface{})
    if !ok { return nil, errors.New("invalid ipfs artifact stats") }

    dataSize, ok := stats["data_size"].(float64)
    if !ok { return nil, errors.New("invalid ipfs artifact stats") }

    if uint(dataSize) == 0 || uint(dataSize) > MAX_DATA_SIZE {
        return nil, errors.New("invalid ipfs artifact")
    }

    response, err := client.Get(artifactURL.String()); if err != nil { return nil, err }
    return response.Body, nil
}

func makeBoolMask(len int) []bool {
    ret := make([]bool, len)
    for i := 0; i < len; i++ {
        ret[i] = true
    }
    return ret
}

func polyswarmHost()(string){
    return POLYSWARM_HOST
}
