import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import javax.sound.midi.SysexMessage;

public class SymHOMSchTest {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

/*
		SymHomSch shs =  new SymHomSch();
		shs.KeyGen(3300, 300, 400);//4*k2<<k0 it support 2 multiplication of enc values, enc(a)*enc(b)
		//support multilipcation 2k2+2K2 = 4*k2 for one multiplication enc(a)*enc(b)
		// 2k2+2k2+2k2 = 6*k2 for two multiplication, enc(a)*enc(b)*enc(c) and 6*k2 = 6*400 << 3500 (k0)
		//2k2+2k2+2k2+2k2 = 8*k2 for three multiplication, enc(a)*enc(b)*enc(c)*enc(d) and 8*k2= 8*400 << 3500
		
		SHSParamters pp = shs.getPublicParams();
		SHSParamters sp = shs.getSecretParams();
*/		


		SymHomSch shs =  new SymHomSch();
		shs.KeyGen(2300, 35, 45);//4*k2<<k0 it support 2 multiplication of enc values, enc(a)*enc(b)
		//support multilipcation 2k2+2K2 = 4*k2 for one multiplication enc(a)*enc(b)
		// 2k2+2k2+2k2 = 6*k2 for two multiplication, enc(a)*enc(b)*enc(c) and 6*k2 = 6*400 << 3500 (k0)
		//2k2+2k2+2k2+2k2 = 8*k2 for three multiplication, enc(a)*enc(b)*enc(c)*enc(d) and 8*k2= 8*400 << 3500
		//To support w multiplication, (w+1)*2K2 << k0 should be staisfied.
		SHSParamters pp = shs.getPublicParams();
		SHSParamters sp = shs.getSecretParams();
		
		
		System.out.println("N = " + pp.getParams().get(0).bitLength() + " " + pp.getParams().get(0));
		System.out.println("P = " + sp.getParams().get(0).bitLength() + " " + sp.getParams().get(0));
		System.out.println("Q = " + sp.getParams().get(3).bitLength() + " " + sp.getParams().get(3));
		System.out.println("N = " + sp.getParams().get(2).bitLength() + " " + sp.getParams().get(2));
		System.out.println("L = " + sp.getParams().get(1).bitLength() + " " + sp.getParams().get(1));

		int[] plainText = new int[]{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1};
		BigInteger[] cipherText = new BigInteger[plainText.length];		
		
		for(int i=0; i<plainText.length; i++){
		   cipherText[i] = shs.Enc(BigInteger.valueOf(plainText[i]), sp);
		   System.out.println("Dec("+i+"): "+ shs.Dec(cipherText[i], sp));		  
		}
		
		BigInteger cipherMulResult = BigInteger.ONE;
		BigInteger cipherAddResult = BigInteger.ZERO;
		//BigInteger cipherResult = cipherText[0];	
		for(int i=0; i<plainText.length; i++){
		   cipherMulResult = shs.Mul(cipherMulResult, cipherText[i], pp);
                   cipherAddResult = shs.Add(cipherAddResult, cipherText[i], pp);
		   System.out.println("Dec_Mul("+i+"): "+ shs.Dec(cipherMulResult, sp));
		   System.out.println("Dec_ADD("+i+"): "+ shs.Dec(cipherAddResult, sp));
		   System.out.println("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%");	
		}



               
		System.exit(0);


		BigInteger s = shs.Enc(new BigInteger("1000"), sp);
		BigInteger t = shs.Enc(new BigInteger("2000"), sp);
		BigInteger res = new BigInteger("1");
		
		System.out.println(shs.Dec(s, sp));
		res = s.subtract(new BigInteger("3"));
		System.out.println(shs.Dec(res, sp));
		res = shs.Sub(s, t, shs.getPublicParams());
		System.out.println(shs.Dec(res ,sp));
		
		System.exit(0);
		
		
		
											
		BigInteger x = shs.Enc(new BigInteger("30"), sp);
		System.out.println(shs.Dec(x, sp));
		System.out.println("========================== Enc(a) op plaintext ==========================");
		System.out.println(shs.Dec(x.add(new BigInteger("20")), sp));
		System.out.println(shs.Dec(x.add(new BigInteger("-20")), sp));
		System.out.println(shs.Dec(x.subtract(new BigInteger("20")), sp));
		System.out.println(shs.Dec(x.subtract(new BigInteger("-20")), sp));
		System.out.println(shs.Dec(x.multiply(new BigInteger("20")), sp));
		System.out.println(shs.Dec(x.multiply(new BigInteger("-20")), sp));
		System.out.println("========================== Enc(a) op Enc(b) ==========================");
		BigInteger y = shs.Enc(new BigInteger("10"), sp);
		System.out.println(shs.Dec(y, sp));
		System.out.println(shs.Dec(x.add(y), sp));		
		System.out.println(shs.Dec(x.subtract(y), sp));		
		System.out.println(shs.Dec(x.multiply(y), sp));//cipher.BitLength=8188	
		System.out.println(shs.Dec(shs.Mul(x,y,pp), sp));//cipher.BitLength=4095
		System.out.println("========================== Enc(a) op Enc(-b) ==========================");
		BigInteger z = shs.Enc(new BigInteger("-10"), sp);
		System.out.println(shs.Dec(z, sp));
		System.out.println(shs.Dec(x.add(z), sp));		
		System.out.println(shs.Dec(x.subtract(z), sp));		
		System.out.println(shs.Dec(x.multiply(z), sp));//cipher.BitLength=8190	
		System.out.println(shs.Dec(shs.Mul(x,z,pp), sp));//cipher.BitLength=4096
		
		BigInteger a = shs.Enc(new BigInteger("-23"), sp);
		System.out.println(shs.Dec(a, sp));
		System.out.println("========================== Enc(-a) op plaintext ==========================");
		System.out.println(shs.Dec(a.add(new BigInteger("20")), sp));
		System.out.println(shs.Dec(a.add(new BigInteger("-20")), sp));
		System.out.println(shs.Dec(a.subtract(new BigInteger("20")), sp));
		System.out.println(shs.Dec(a.subtract(new BigInteger("-20")), sp));
		System.out.println(shs.Dec(a.multiply(new BigInteger("20")), sp));
		System.out.println(shs.Dec(a.multiply(new BigInteger("-20")), sp));
		System.out.println("========================== Enc(-a) op Enc(b) ==========================");
		BigInteger b = shs.Enc(new BigInteger("1000"), sp);
		System.out.println(shs.Dec(b, sp));
		System.out.println(shs.Dec(a.add(b), sp));		
		System.out.println(shs.Dec(a.subtract(b), sp));		
		System.out.println(shs.Dec(a.multiply(b), sp));//cipher.BitLength=8188	
		System.out.println(shs.Dec(shs.Mul(a,b,pp), sp));//cipher.BitLength=4095
		System.out.println("========================== Enc(-a) op Enc(-b) ==========================");
		BigInteger c = shs.Enc(new BigInteger("-1000"), sp);
		System.out.println(shs.Dec(c, sp));
		System.out.println(shs.Dec(a.add(c), sp));		
		System.out.println(shs.Dec(a.subtract(c), sp));		
		System.out.println(shs.Dec(a.multiply(c), sp));//cipher.BitLength=8192	
		System.out.println(shs.Dec(shs.Mul(a,c,pp), sp));//cipher.BitLength=4095
		
		System.out.println("========================== Enc(b) * Enc(b) =====4k2 {<<} k0==============");
		System.out.println(shs.Dec(shs.Mul(b,b,pp), sp));//with k0=2048 and k2=400 (4*400<<2048) It can be processed.
		System.out.println("========================== Enc(b) * Enc(b) * Enc(b) =====6k2 {<<} k0=====SET K0=2500 or 2600 for  k2=400 =========");
		System.out.println(shs.Dec(shs.Mul(b,shs.Mul(b,b,pp),pp), sp));//with k0=2048 and k2=400 (6*400 IS NOT <<2048) It can NOT be processed.
		System.out.println("========================== Enc(b) * Enc(b) * Enc(b) * Enc(b)=====8k2 {<<} k0=====SET k0=3300 or 3400 for k2=400 =========");
		System.out.println(shs.Dec(shs.Mul(b,shs.Mul(b,shs.Mul(b,b,pp),pp),pp), sp));//with k0=2048 and k2=400 (8*400 IS NOT <<2048) It can NOT be processed.
		System.out.println("========================== Enc(b) * Enc(b) * Enc(b) * Enc(b) * 5 =====8k2 {<<} k0=====SET k0=3300 or 3400 for k2=400 =========");
		System.out.println(shs.Dec(shs.Mul(b,shs.Mul(b,shs.Mul(b,b,pp),pp),pp).multiply(BigInteger.valueOf(5)), sp));//with k0=2048 and k2=400 (8*400 IS NOT <<2048) It can NOT be processed.

			
		
				
	}

}
