package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log"
	"strconv"
	"time"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/ssh"
)

type Core struct {
	YK            *piv.YubiKey
	ManagementKey [24]byte
	Pin           []byte
	Pub           *ecdsa.PublicKey
	Priv          *piv.ECDSAPrivateKey
	OriginPub     *crypto.PublicKey
	OriginPriv    *crypto.PrivateKey
}

func (core *Core) setPinToYubiKey() {
	if err := ensureYK(core.YK); err != nil {
		log.Fatal("Need Keep YubiKey inserted")
	}

	var managedKey [24]byte
	if _, err := rand.Read(managedKey[:]); err != nil {
		log.Fatal("Read random failed", err)
	}
	if err := core.YK.SetManagementKey(piv.DefaultManagementKey, managedKey); err != nil {
		log.Fatalln("The default Management Key did not work", err)
	}
	if err := core.YK.SetMetadata(managedKey, &piv.Metadata{
		ManagementKey: &managedKey,
	}); err != nil {
		log.Fatalln("Failed to store the Management Key on the device:", err)
	}
	if err := core.YK.SetPIN(piv.DefaultPIN, string(core.Pin)); err != nil {
		log.Fatalln("The default PIN did not work", err)
	}
	if err := core.YK.SetPUK(piv.DefaultPUK, string(core.Pin)); err != nil {
		log.Fatalln("The default PUK did not work", err)
	}
	core.ManagementKey = managedKey
}

func (core *Core) generateKeyPair() {

	if err := ensureYK(core.YK); err != nil {
		log.Fatal("Need Keep YubiKey inserted")
	}

	version := strconv.Itoa(core.YK.Version().Major) + "." + strconv.Itoa(core.YK.Version().Minor) + "." + strconv.Itoa(core.YK.Version().Patch)
	pub, err := core.YK.GenerateKey(core.ManagementKey, piv.SlotAuthentication, piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: piv.TouchPolicyAlways,
	})
	if err != nil {
		log.Fatalln("Failed to generate key:", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalln("Failed to generate parent key:", err)
	}

	parent := &x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"timedia"},
			OrganizationalUnit: []string{version},
		},
		PublicKey: priv.Public(),
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "SSH Standard Key Certificate",
		},
		NotAfter:     time.Now().AddDate(10, 0, 0),
		NotBefore:    time.Now(),
		SerialNumber: randomSerialNumber(),
		KeyUsage:     x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		log.Fatalln("Failed to generate certificate:", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatalln("Failed to parse certificate:", err)
	}

	if err := core.YK.SetCertificate(core.ManagementKey, piv.SlotAuthentication, cert); err != nil {
		log.Fatalln("Failed to store certificate:", err)
	}
}

func getCertificate(yk *piv.YubiKey) *x509.Certificate {
	cert, err := yk.Attest(piv.SlotAuthentication)
	if err != nil {
		log.Fatal("could not get certificate from yubikey", err)
	}
	return cert
}

func (core *Core) GetECDSAPublicKey() {
	if err := getECDSAPublicKey(core); err != nil {
		log.Fatal(err)
	}
}

func getECDSAPublicKey(core *Core) error {
	cert := getCertificate(core.YK)
	newPubKeyECDSA, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("generated ECDSA public key on yubikey is invalid")
	}
	core.Pub = newPubKeyECDSA
	return nil
}

func (core *Core) GetPrivateKey() {
	if err := core.getPrivateKey(); err != nil {
		log.Fatal(err)
	}
}

func (core *Core) getPrivateKey() error {
	cert := getCertificate(core.YK)
	pub, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return errors.New("failed to process public key:" + err.Error())
	}
	priv, err := core.YK.PrivateKey(
		piv.SlotAuthentication,
		pub.(ssh.CryptoPublicKey).CryptoPublicKey(),
		piv.KeyAuth{PIN: string(core.Pin)},
	)
	if err != nil {
		return errors.New("failed to prepare private key:" + err.Error())
	}
	ykPriv, ok := priv.(*piv.ECDSAPrivateKey)
	if !ok {
		return errors.New("cannnot Transfrom this key")
	}
	core.Priv = ykPriv
	originPub := ykPriv.Public()
	core.OriginPub = &originPub
	core.OriginPriv = &priv
	return nil
}

func (core *Core) AuthenticatePin() {
	if err := ensureYK(core.YK); err != nil {
		log.Fatal("Need Keep YubiKey inserted")
	}
	core.GetManagementKey()
}

func (core *Core) GetManagementKey() {
	meta, err := core.YK.Metadata(string(core.Pin))
	if err != nil {
		log.Fatal("cannot get metadata", err)
	}
	if meta.ManagementKey == nil {
		log.Fatal("invalid Pin")
	}

	key := *meta.ManagementKey
	core.ManagementKey = key
}
