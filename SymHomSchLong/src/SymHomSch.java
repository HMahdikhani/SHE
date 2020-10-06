import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
 
//SHS = Symmetric Homomorphic Scheme
public final class SymHomSch {

	private SecureRandom rnd = new SecureRandom();
	private int k0, k1, k2; 
    private  SHSParamters secretParam; //sp
    private  SHSParamters publicParam; //pp
	public  void KeyGen(int param_k0, int param_k1, int param_k2)
	{

		k0 = param_k0; //1024; Length of large prime numbers p and q
		k1 = param_k1; //30; Length of message and message space
		k2 = param_k2; //80; Length of parameter L and generated random values in encryption method 
	
		//k0=2048, k1=300, k2=400
		//k1=300 can support 10^90 (log(10)/log2()= 3.322 and 300/3.322 = 90)
		//Single multiplication needs 2k2+2k2=4*k2 and 4K2<<k0 4*400 => 1600 << 2048 (it is okey!)
		//Two multiplication needs 2k2+2k2+2k2=6*k2 and 6k2<<k0 ==> 6*400<< 20148 (it os not acceptable)
		
		
		BigInteger p = new BigInteger(k0, 40, rnd); // Certainty = 40		
		//p = BigInteger.probablePrime(k0, rnd);
		BigInteger q = new BigInteger(k0, 40, rnd); // Certainty = 40
		//q = BigInteger.probablePrime(k0, rnd);
		
		BigInteger N = p.multiply(q);
		
		//L = BigInteger.probablePrime(k2, rnd);
		BigInteger L = new BigInteger(k2, rnd).add(BigInteger.ONE) ; //L in {1,2,3,..., 2^k2}; e.g., k2=80;
		
		secretParam = new SHSParamters(new ArrayList<>(Arrays.asList(p, L, N, q)));
		publicParam = new SHSParamters(new ArrayList<>(Arrays.asList(N)));
	

	}

	
	
	
	
	
    public BigInteger Enc(BigInteger message, SHSParamters Param) {
    	//Param is a secret paramater. (p,L,N)
    	BigInteger p = Param.getParams().get(0);
    	BigInteger L = Param.getParams().get(1);
    	BigInteger N = Param.getParams().get(2);
    	
    	
    	BigInteger r = (new BigInteger(k2, rnd)).add(BigInteger.ONE); //r in {1,2,3,..., 2^k2}; e.g., k2=80;
    	System.out.println("|r|=k2: " + r.bitLength());//+ " " +r);
    	BigInteger rp = ((new BigInteger(k0*2, rnd)).add(BigInteger.ONE)).mod(N); //r' in ZN; |N|=|p|*|q|=k0*K0;
    	System.out.println("|r'∈ ZN|: " + rp.bitLength());//+ " " +rp);
   	return (((r.multiply(L)).add(message)).multiply((BigInteger.ONE).add(rp.multiply(p)))).mod(N);
    }
    
    /*
    public BigInteger Dec(BigInteger cipher, SHSParamters Param) {
    	
    	BigInteger p = Param.getParams().get(0);
    	BigInteger L = Param.getParams().get(1);
    	BigInteger N = Param.getParams().get(2);

    	BigInteger res = cipher.mod(p);
    	res = res.mod(L);    	
    	return res;

    }

    
    public BigInteger Dec2(BigInteger cipher, SHSParamters Param) {
    	
    	BigInteger p = Param.getParams().get(0);
    	BigInteger L = Param.getParams().get(1);
    	BigInteger N = Param.getParams().get(2);

    	System.out.println("cipher.BitLength()" + cipher.bitLength());
    	BigInteger x = cipher.mod(p);
    	System.out.println("x.BitLength()" + x.bitLength());
    	BigInteger y = x.mod(L);
    	System.out.println("y.BitLength()" + y.bitLength());
   
    	if (x.bitLength()<k0+5 && x.bitLength()>k0-5)
    	{
    		System.out.println("case");
    		x = x.subtract(p.mod(L));
    		return x.mod(L);
    	}
    	if (y.bitLength()<k1+1) 
    		return y;

    	if ((y.bitLength()<k2+10)&&(y.bitLength()>k2-10))  
    		return y.subtract(L);

    	
    	
    	return BigInteger.valueOf((long)-1);

    }
    */
    
 public BigInteger Dec(BigInteger cipher, SHSParamters Param) {
    	
    	BigInteger p = Param.getParams().get(0);
    	BigInteger L = Param.getParams().get(1);
    	BigInteger N = Param.getParams().get(2);

    	System.out.println("cipher.BitLength: " + cipher.bitLength());
    	BigInteger x = cipher.mod(p);
    	BigInteger y;
    	System.out.println("x.BitLength: " + x.bitLength());
    	if (x.bitLength() < k1+15) // x = c mod p; x in Message space.
    	{// if it had been set to k1+15 it can recover m values grater than message space.
    		y = x.mod(L);
    		System.out.println("y.BitLength: " + y.bitLength());
    		System.out.println("Case -1");
    		return x.mod(L); // or return x;
    	}else if ((x.bitLength() > k2+5) &&  (x.bitLength() < k0-50))// x = c mod p; |L| < |x| << |p|    	
    	{
    		y = x.mod(L);
    		System.out.println("y.BitLength: " + y.bitLength());
    		if (y.bitLength()<k1+15) // if it had been set to k1+15 it can recover m values grater than message space. 
    		{    			
    			System.out.println("Case 1");
    			return y;
    		}
    		else if ((y.bitLength()<k2+10)&&(y.bitLength()>k2-10)) // y close to L
    		{
    			System.out.println("Case 2.1");
    			return y.subtract(L);
    		}
    		else
    		{
    			System.out.println("Case unknown01 - due to bad boundary setting.");
    			return BigInteger.valueOf((long)-1);
    		}
    	}else if((x.bitLength()<k0+5 && x.bitLength()>k0-5))// x = c mod p; x close to p
    	{
    		y = x.mod(L);
    		System.out.println("y.BitLength: " + y.bitLength());
    		if ( y.compareTo(p.mod(L))>=0) // y>= p mod L
    		{
    			System.out.println("Case 3");
    			return y.subtract(p.mod(L));
    		}
    		else if(y.compareTo(p.mod(L))==-1)// y < p mod L
    		{
    			System.out.println("Case 4 or 2.2");
    			return y.subtract(p.mod(L));
    		}
    		else
    		{
    			System.out.println("Case unknown02");
    			return BigInteger.valueOf((long)-1);
    		}    	
    	}
    	else
    	{
    		System.out.println("Case unknown03");
			return BigInteger.valueOf((long)-1);
    	}
    }
    /*
    public BigInteger Enc2(BigInteger message,BigInteger ran, SHSParamters Param) {
    	//Param is a secret paramater. (p,L,N)
    	BigInteger p = Param.getParams().get(0);
    	BigInteger L = Param.getParams().get(1);
    	BigInteger N = Param.getParams().get(2);
    	
    	
    	BigInteger r = ran;
    	   //r = BigInteger.valueOf((long)2);
    	System.out.println("r = " + r.bitLength()+ " " +r);
    	//r2 in ZN; r2=rand(k0*2 bit) mod N;
    	BigInteger rp = ((new BigInteger(k0*2, rnd)).add(BigInteger.ONE)).mod(N); //r' in ZN; |N|=|p|*|q|=k0*K0;
    	   //rp = BigInteger.valueOf((long)3); 
    	System.out.println("r' = " + rp.bitLength()+ " " +rp);

    	//System.out.println("(("+r+"*"+L+"+"+message+")*(1+"+rp+"*"+p+"))%"+N);
    	//retrun EncValue = (r.L+m)(1+rp.p) mod N
    	return (((r.multiply(L)).add(message)).multiply((BigInteger.ONE).add(rp.multiply(p)))).mod(N);
  	
        //return message.modPow(Param.get.get(0), publicKey.getKey().get(1));
    }
    */

    
    public SHSParamters getPublicParams() {
        return publicParam;
    }

    public SHSParamters getSecretParams() {
        return secretParam;
    }
    
    
    public static BigInteger Add(BigInteger cipher1, BigInteger cipher2, SHSParamters Param)
    {
    	//Param is a public parameter(N)    	
    	return cipher1.add(cipher2).mod(Param.getParams().get(0));
    }

    public static BigInteger Mul(BigInteger cipher1, BigInteger cipher2, SHSParamters Param)
    {
    	//Param is a public parameter(N)    	
    	return cipher1.multiply(cipher2).mod(Param.getParams().get(0));
    }

    public static BigInteger Sub(BigInteger cipher1, BigInteger cipher2, SHSParamters Param)
    {
    	//Param is a public parameter(N)    	
    	return cipher1.subtract(cipher2).mod(Param.getParams().get(0));
    }
    

    
}
