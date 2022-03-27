package threshold_signature

import (
	"math/big"
	"math/rand"
	"time"
)

var p, q, p_hat, q_hat, n, m, e, d *big.Int
var Delta, v *big.Int

// 节点数
var l int = 15

// 门限值
var k = 7
var a map[int]*big.Int
var lambda map[int]map[int]*big.Int
var S, SOut []int
var s, VK map[int]*big.Int

//var M = "320282200009128411"
//var x *big.Int

func init() {
	//file, err := os.Open("big_prime1.txt")
	//if err != nil {
	//	fmt.Printf("%v", err)
	//	return
	//}
	//defer file.Close()
	//content, err := ioutil.ReadAll(file)
	//big_primes := strings.Split(string(content), ",")
	//
	//for _, prime := range big_primes {
	//	p_hat, _ = new(big.Int).SetString(prime, 10)
	//	p = new(big.Int).Add(new(big.Int).Mul(big.NewInt(2), p_hat), big.NewInt(1))
	//	if !p.ProbablyPrime(10) {
	//		continue
	//	} else {
	//		break
	//	}
	//}
	//fmt.Printf("p:%v,q:%v,p':%v,q':%v,m:%v,n:%v", p, q, p_hat, q_hat, m, n)
	//x, _ = new(big.Int).SetString(fmt.Sprintf("%x", sha256.Sum256([]byte(M))), 16)
	p, _ = new(big.Int).SetString("195035409467", 10)
	p_hat, _ = new(big.Int).SetString("97517704733", 10)
	q, _ = new(big.Int).SetString("195288414899", 10)
	q_hat, _ = new(big.Int).SetString("97644207449", 10)
	n, _ = new(big.Int).SetString("38088155963987848448833", 10)
	m, _ = new(big.Int).SetString("9522038990899381156117", 10)
	e = big.NewInt(17)
	d = new(big.Int).ModInverse(e, m)
	//fmt.Println(p.ProbablyPrime(10), q.ProbablyPrime(10), p_hat.ProbablyPrime(10), q_hat.ProbablyPrime(10))
	//n = new(big.Int).Mul(p, q)
	//m = new(big.Int).Mul(p_hat, q_hat)

	a = make(map[int]*big.Int)
	a[0] = d
	for i := 1; i <= k-1; i++ {
		rand.Seed(time.Now().Unix())
		a[i] = new(big.Int).Rand(rand.New(rand.NewSource(time.Now().Unix())), new(big.Int).Sub(m, big.NewInt(1)))
	}

	s = make(map[int]*big.Int)
	for i := 0; i <= l; i++ {
		s[i] = new(big.Int).Mod(f(i), m)
		//fmt.Printf("s[%v]: %v", i, s[i])
	}

	sqrtN := new(big.Int).Sub(new(big.Int).Sqrt(n), big.NewInt(5))
	v = new(big.Int).Mul(sqrtN, sqrtN)
	VK = make(map[int]*big.Int)
	for i := 1; i <= l; i++ {
		VK[i] = new(big.Int).Exp(v, s[i], n)
	}

	Delta = factorial(big.NewInt(int64(l)))

	counter := 0

	var lTemp []int
	for i := 0; i <= l; i++ {
		lTemp = append(lTemp, i)
	}

	rand.Shuffle(len(lTemp), func(i, j int) {
		lTemp[i], lTemp[j] = lTemp[j], lTemp[i]
	})
	for i := 0; i <= l; i++ {
		if counter < k {
			counter++
			S = append(S, lTemp[i])
		} else {
			SOut = append(SOut, lTemp[i])
		}
	}
	//t.Log(S, "\n", SOut)

	lambda = make(map[int]map[int]*big.Int)
	for _, i := range lTemp {
		subLambda := make(map[int]*big.Int)
		for _, j := range S {
			fenzi := func() *big.Int {
				res := big.NewInt(1)
				for _, j_hat := range S {
					if j_hat == j {
						continue
					}
					res = new(big.Int).Mul(res, big.NewInt(int64(i-j_hat)))
				}
				return res
			}()
			fenmu := func() *big.Int {
				res := big.NewInt(1)
				for _, j_hat := range S {
					if j_hat == j {
						continue
					}
					res = new(big.Int).Mul(res, big.NewInt(int64(j-j_hat)))
				}
				return res
			}()
			subLambda[j] = new(big.Int).Div(new(big.Int).Mul(Delta, fenzi), fenmu)
			lambda[i] = subLambda
			//t.Logf("lambda[%v][%v]: %v", i, j, lambda[i][j])
		}
	}
}

func f(x int) *big.Int {
	res := big.NewInt(0)
	for i := 0; i <= k-1; i++ {
		res = new(big.Int).Add(res, new(big.Int).Mul(a[i], new(big.Int).Exp(big.NewInt(int64(x)), big.NewInt(int64(i)), nil)))
	}
	return res
}

func factorial(n *big.Int) *big.Int {
	if n.Cmp(big.NewInt(0)) == 1 {
		return new(big.Int).Mul(n, factorial(new(big.Int).Sub(n, big.NewInt(1))))
	}
	return big.NewInt(1)
}
