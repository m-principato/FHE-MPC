package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/dbfv"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/utils"
)

type multTask struct {
	wg  *sync.WaitGroup
	op1 *rlwe.Ciphertext
	op2 *rlwe.Ciphertext
	res *rlwe.Ciphertext
}

type party struct {
	sk         *rlwe.SecretKey
	rlkEphemSk *rlwe.SecretKey

	ckgShare    *drlwe.CKGShare
	rkgShareOne *drlwe.RKGShare
	rkgShareTwo *drlwe.RKGShare
	pcksShare   *drlwe.PCKSShare

	input []uint64
}

func GenParties(params bfv.Parameters, N int) []*party {

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := make([]*party, N)
	for i := range P {
		pi := &party{}
		pi.sk = bfv.NewKeyGenerator(params).GenSecretKey()
		P[i] = pi
	}

	return P
}

// ---------------------   Main   --------------------------
func main() {
	l := log.New(os.Stderr, "", 0)
	bold := "\033[1m"
	reset := "\033[0m"
	underline := "\033[4m"
	start := time.Now()

	//--------> Setup start
	l.Printf("\n%v%vSetup%v", bold, underline, reset)
	params, crs := setup()         // Setup parameters
	P := GenParties(params, 2)     // Generating parties and their local secret key
	pk := ckgphase(params, crs, P) // Generating global public key
	l.Printf("\tPublic key: %v", *pk)
	rlk := rkgphase(params, crs, P) // Generating reliniarization keys
	l.Printf("\tEval key: %v", *rlk)
	// <-------- Setup end

	// --------> Encryption start
	l.Printf("\n%v%vEncryption%v", bold, underline, reset)
	genInputs(params, P)
	encoder := bfv.NewEncoder(params)
	encInputs := encPhase(params, P, pk, encoder) // Encrypting inputs locally
	for i := 0; i < len(encInputs); i++ {
		l.Printf("\tEncrypted value for party %v: %v", i, *encInputs[i])
	}
	// <-------- Decryption end

	//--------> MPC start
	l.Printf("\n%v%vMPC%v", bold, underline, reset)
	encRes := evalPhase(params, encInputs, rlk) // Circuit evaluation
	l.Printf("\tEncrypted Result (pk): %v", *encRes)

	tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair() //target key pair
	encOut := pcksPhase(params, tpk, encRes, P)          // encrypted result after key switching to tpk
	l.Printf("\tEncrypted Output (tpk): %v", *encOut)
	// <-------- MPC end

	// --------> Decryption start
	l.Printf("\n%v%vDecryption%v", bold, underline, reset)
	res := dec(params, tsk, encOut, encoder) // Decrypting result
	l.Printf("\tResult: %v", res[:1])
	// <-------- Decryption end
	l.Printf("%v\n>>> Done. Elapsed time: %s\n%v", bold, time.Since(start), reset)

}

//---------------------------------------------------------

func setup() (params bfv.Parameters, crs *utils.KeyedPRNG) {
	paramsDef := bfv.PN14QP438 // Creating encryption parameters with logN=14, logQP=438 with a plaintext modulus T=65537
	params, err := bfv.NewParametersFromLiteral(paramsDef)
	if err != nil {
		panic(err)
	}
	// Creating common random string with keyed seed
	crs, err = utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	if err != nil {
		panic(err)
	}

	return params, crs
}

func ckgphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.PublicKey {
	l := log.New(os.Stderr, "", 0)
	l.Println("> CKG Phase") // Public key generation

	ckg := dbfv.NewCKGProtocol(params)
	ckgCombined := ckg.AllocateShare()
	pk := rlwe.NewPublicKey(params.Parameters) // initializes an empty pk
	crp := ckg.SampleCRP(crs)                  // sample random polynomial (crp) from crs

	for _, pi := range P {
		// Generate global Pk share from local keypair
		pi.ckgShare = ckg.AllocateShare()
		/*l.Printf("sk: %v, crp: %v, ckgShare: %v", *pi.sk, crp, *pi.ckgShare)*/
		ckg.GenShare(pi.sk, crp, pi.ckgShare)
	}

	for _, pi := range P {
		// Calculate the global Pk via the sent shares:
		ckg.AggregateShares(pi.ckgShare, ckgCombined, ckgCombined)
		/*l.Printf("ckgCombined: %v, crp: %v, pk: %v", *ckgCombined, crp, *pk)*/
		ckg.GenPublicKey(ckgCombined, crp, pk)
	}
	return pk
}

func rkgphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.RelinearizationKey {
	l := log.New(os.Stderr, "", 0)
	l.Println("> RKG Phase") // reliniarization key generation

	rkg := dbfv.NewRKGProtocol(params) // Relineariation key generation
	_, rkgCombined1, rkgCombined2 := rkg.AllocateShare()
	crp := rkg.SampleCRP(crs)
	rlk := rlwe.NewRelinearizationKey(params.Parameters, 1)

	for _, pi := range P {
		pi.rlkEphemSk, pi.rkgShareOne, pi.rkgShareTwo = rkg.AllocateShare()
	}
	for _, pi := range P {
		rkg.GenShareRoundOne(pi.sk, crp, pi.rlkEphemSk, pi.rkgShareOne)
	}
	for _, pi := range P {
		rkg.AggregateShares(pi.rkgShareOne, rkgCombined1, rkgCombined1)
	}
	for _, pi := range P {
		rkg.GenShareRoundTwo(pi.rlkEphemSk, pi.sk, rkgCombined1, pi.rkgShareTwo)
	}
	for _, pi := range P {
		rkg.AggregateShares(pi.rkgShareTwo, rkgCombined2, rkgCombined2)
	}

	rkg.GenRelinearizationKey(rkgCombined1, rkgCombined2, rlk)

	return rlk
}

func genInputs(params bfv.Parameters, P []*party) {
	l := log.New(os.Stderr, "", 0)
	l.Println("> Enter Inputs")
	for i, pi := range P {
		var userInput uint64
		fmt.Printf("\tValue for party %v: ", i)
		_, err := fmt.Scanf("%d", &userInput)
		if err != nil {
			l.Println("Error:", err)
			return
		}
		pi.input = []uint64{userInput}
		//fmt.Printf("Input: %v\n", pi.input)
	}
}

func encPhase(params bfv.Parameters, P []*party, pk *rlwe.PublicKey, encoder bfv.Encoder) (encInputs []*rlwe.Ciphertext) {
	l := log.New(os.Stderr, "", 0)
	l.Println("> Encrypt Phase")

	encInputs = make([]*rlwe.Ciphertext, len(P))
	for i := range encInputs {
		encInputs[i] = bfv.NewCiphertext(params, 1, params.MaxLevel())
	}

	encryptor := bfv.NewEncryptor(params, pk)
	pt := bfv.NewPlaintext(params, params.MaxLevel())

	for i, pi := range P {
		encoder.Encode(pi.input, pt)
		encryptor.Encrypt(pt, encInputs[i])
	}

	return
}

func evalPhase(params bfv.Parameters, encInputs []*rlwe.Ciphertext, rlk *rlwe.RelinearizationKey) (encRes *rlwe.Ciphertext) {
	l := log.New(os.Stderr, "", 0)
	l.Println("> Eval Phase")

	encLvls := make([][]*rlwe.Ciphertext, 0)
	encLvls = append(encLvls, encInputs)
	for nLvl := len(encInputs) / 2; nLvl > 0; nLvl = nLvl >> 1 {
		encLvl := make([]*rlwe.Ciphertext, nLvl)
		for i := range encLvl {
			encLvl[i] = bfv.NewCiphertext(params, 2, params.MaxLevel())
		}
		encLvls = append(encLvls, encLvl)
	}
	encRes = encLvls[len(encLvls)-1][0]

	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: nil})

	// Start the tasks
	for i, lvl := range encLvls[:len(encLvls)-1] {
		nextLvl := encLvls[i+1]
		//l.Println("\tlevel", i, len(lvl), "->", len(nextLvl))
		for j, nextLvlCt := range nextLvl {
			task := multTask{nil, lvl[2*j], lvl[2*j+1], nextLvlCt}
			// 1) Multiplication of two inputs
			evaluator.Mul(task.op1, task.op2, task.res)
			// 2) Relinearization
			evaluator.Relinearize(task.res, task.res)
		}
	}

	return
}

func pcksPhase(params bfv.Parameters, tpk *rlwe.PublicKey, encRes *rlwe.Ciphertext, P []*party) (encOut *rlwe.Ciphertext) {
	l := log.New(os.Stderr, "", 0)
	l.Println("> PCKS Phase")

	pcks := dbfv.NewPCKSProtocol(params, 3.19)
	pcksCombined := pcks.AllocateShare(params.MaxLevel())
	encOut = bfv.NewCiphertext(params, 1, params.MaxLevel())

	for _, pi := range P {
		pi.pcksShare = pcks.AllocateShare(params.MaxLevel())
		pcks.GenShare(pi.sk, tpk, encRes, pi.pcksShare)
		pcks.AggregateShares(pi.pcksShare, pcksCombined, pcksCombined)
		pcks.KeySwitch(encRes, pcksCombined, encOut)
	}

	return
}

func dec(params bfv.Parameters, tsk *rlwe.SecretKey, encOut *rlwe.Ciphertext, encoder bfv.Encoder) (res []uint64) {
	l := log.New(os.Stderr, "", 0)
	l.Println("> Decrypt Phase:")

	decryptor := bfv.NewDecryptor(params, tsk)
	ptres := bfv.NewPlaintext(params, params.MaxLevel())
	decryptor.Decrypt(encOut, ptres)

	res = encoder.DecodeUintNew(ptres)

	return res
}
