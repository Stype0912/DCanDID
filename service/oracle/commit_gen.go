package oracle

import (
	"database/sql"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"k8s.io/klog"
	"math/big"
	"time"
)

type Oracle struct {
	id string
}

func (o *Oracle) ClaimGen(id string) string {
	hash, err := o.GetHashById(id)
	if err != nil {
		klog.Errorf("db error: %v", err)
		return ""
	}
	if hash != "" {
		return hash
	} else {
		hash = mimcHash([]byte(id))
		err = o.InsertHashById(id, hash)
		if err != nil {
			klog.Errorf("db insert error: %v", err)
			return ""
		}
		return hash
	}
}

func (o *Oracle) GetHashById(id string) (string, error) {
	db, err := o.ConnectDB()
	if err != nil {
		klog.Errorf("db error: %v", err)
		return "", err
	}
	var hash string
	err = db.QueryRow("SELECT hash FROM oracle_platform WHERE user_id = ?", id).Scan(&hash)
	db.Close()
	if err != nil {
		klog.Errorf("query error: %v", err)
		//return "", err
	}
	return hash, nil
}

func (o *Oracle) InsertHashById(id, hash string) error {
	db, err := o.ConnectDB()
	if err != nil {
		klog.Errorf("db error: %v", err)
		return err
	}
	_, err = db.Exec("INSERT INTO oracle_platform (user_id, hash, submission_date) VALUES (?, ?, ?)", id, hash, time.Now().Format("2006-01-02 15:04:05"))
	db.Close()
	if err != nil {
		klog.Errorf("db insert error: %v", err)
		return err
	}
	return nil
}

func (o *Oracle) ConnectDB() (*sql.DB, error) {
	db, err := sql.Open("mysql", "root:tang2000912@tcp(127.0.0.1:3306)/user_information?charset=utf8")
	return db, err
}

func mimcHash(data []byte) string {
	f := bn254.NewMiMC("1")
	f.Write(data)
	hash := f.Sum(nil)
	hashInt := big.NewInt(0).SetBytes(hash)
	return hashInt.String()
}
