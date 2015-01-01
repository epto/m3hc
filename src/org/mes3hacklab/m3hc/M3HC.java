
/*
 * The M3HC block cipher (mes3hacklab block cipher).
 * Version 1.00
 * Copyright (C) 2014  by epto@mes3hacklab.org
 * 
 * M3HC is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this source code; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package org.mes3hacklab.m3hc;

public class M3HC {

	public static final int MODE_ENCRYPT=1;
	public static final int MODE_DECRYPT=2;
	public static final int MODE_ADVANCED=4;		//  Attiva la modalita con cambio automatico delle chiavi.
	public static final int MODE_NORMAL=0;		
	private static final int MODE_INVALID= MODE_ENCRYPT | MODE_DECRYPT;
	
	public static final int BLOCK_SIZE = 16;			//  Puramente informative.
	public static final int IV_SIZE=16;
		
	private int maxRound=10;					// Parti della chiave.
	private int[] byteSwapper = null;
	private byte[][][] sBox6 = null;
	private boolean[][] dirDir= null;
	private boolean swapDir=false;
	private byte[][] midXor=null;
	private byte[][][] sBox4A = null;
	private byte[][] sBox4AMode = null;
	private long[][] sBox64 = null;
	private long[] sBox64Mask = null;
	private int byteShift[] = null;
	private int[] bitSwap = null;
	private byte[] localIV=null;
	
	private boolean fAdvance=false; 	// Modalità.
	private boolean Mode=false;
	
	///////////////////// Costruttori e getter.
	
	public M3HC(byte[] key,int flags) throws Exception {		// Crea un'istanza nella modalità normale (con possibilità di cambio automatico delle chiavi). 
		if ((flags & MODE_INVALID)==MODE_INVALID) throw new Exception("Invalid configuration.");
		if ((flags & MODE_INVALID)==0) throw new Exception("Invalid configuration.");
		Mode=0!=(flags & M3HC.MODE_ENCRYPT);
		setKey(key,0!=(flags & M3HC.MODE_ADVANCED));
		localIV=new byte[16];
		}

	public M3HC(byte[] key,byte[] iv,int flags) throws Exception {		// Crea un'istanza nella modalità avanzata (con avanzamento IV).
		if ((flags & MODE_INVALID)==MODE_INVALID) throw new Exception("Invalid configuration.");
		if ((flags & MODE_INVALID)==0) throw new Exception("Invalid configuration.");
		Mode=0!=(flags & M3HC.MODE_ENCRYPT);
		setKey(key,0!=(flags & M3HC.MODE_ADVANCED));
		if (iv.length!=16) throw new Exception("Invalid IV size. Must be 16 bytes.");
		localIV = new byte[16];
		System.arraycopy(iv, 0, localIV, 0, 16);
		}

	public boolean isAvancedMode() { return fAdvance; }
	
	///////////////////// Operazioni su Word64bit
	
	private long word64E(byte[] a,int i,boolean r) {	// Gira e/o accorpa 64 bit.
		long w = 0;
		for (int j=0;j<8;j++) {
			byte b = r ?  a[i+7-j] : a[j+i];
			w<<=8;
			w |=(b&255);
			}
		return w;
		}
	
	private void word64D(long w,byte[] a,int i,boolean r) {	//  Gira e/o disaccorpa 64 bit.
		for (int j =0 ;j<8;j++) {
			if (r)
				a[i+7-j] =(byte)  (255&(w>>(j*8)));
				else 
				a[j+i] =(byte)  (255&(w>>(j*8)));
			}		
		}
	
	///////////////////// Operazioni su stringhe di byte.
	
	private byte[] byteSwapper(byte[] in,int swp) {		//  Scambia i bytes.
		byte[] out = new byte[16];
		for (int i=0;i<16;i++) {
			int j = (i ^ swp)&15;
			out[j]=in[i];
			}
		return out;
		}
	
	private static byte[] byteShifter(byte[] in,boolean dir,int pow) {	// Shifta i byte in una direzione di pow passi.
		byte[] o = new byte[16];
		for (int i = 0;i<16;i++) {
			int j= dir ? i+pow : i-pow;
			j&=15;
			o[i]=in[j];
			}
		return o;	
		}	
	
	private void xorSB(byte[] io,byte[] key) {	// Xor di un array.
		int j=io.length;
		for (int i=0;i<j;i++) io[i]^=key[i];
		}
	
	private byte[] bitsSwap(byte[] in,int swap) {
		byte[] out  = new byte[16];
		swap&=127;
		for (int bit = 0;bit<128;bit++) {
			int bot = bit^swap;
			int ch = bot>>3;
			int cl = bot&7;
			if (0!=(in[ch]&1<<cl)) {
				int eh = bit>>3;
				int el = bit&7;
				out[eh]|=1<<el;
				}
			}
		return out;
		} 
	
	///////////////////// sBox
	
	private byte[] doSBox64(byte[] m,boolean enc) {	//  Critta/Decritta con sBox64 una stringa di 16 byte.
		long[] M = new long[2];
		M[0] = word64E(m,0,true);
		M[1] = word64E(m,8,true);
		
		if (enc) {
			M[0] = doSBox64Enc(M[0],sBox64Mask,sBox64);
			M[1] = doSBox64Enc(M[1],sBox64Mask,sBox64);
			} else {
			M[0] = doSBox64Dec(M[0],sBox64Mask,sBox64);
			M[1] = doSBox64Dec(M[1],sBox64Mask,sBox64);
			}
		
		byte[] out = new byte[16];
		word64D(M[0],out,0,false);
		word64D(M[1],out,8,false);
		return out;
	}

	private long doSBox64Enc(long M,long[] Mask,long[][] Box) {	//  Critta con sBox64
		for (int a=0;a<64;a++) {
					int ms = (Mask[a] & M)!=0 ? 1:0;
					M^= Box[ms][a];
					}
		return M;
	}

	private long doSBox64Dec(long M,long[] Mask,long[][] Box) {	//  Decritta con sBox64
		for (int a=63;a>-1;a--) {
					int ms = (Mask[a] & M)!=0 ? 1:0;
					M^= Box[ms][a];
					}
		return M;
	}

	private byte doSBox4(byte in,byte[] sBox,boolean inB,boolean ouB) {  // Sbox a 4 bit.
		int box = inB ? in>>4 : in &15;
		int pay = inB ? in&15 : in >>4;
		box&=15;
		pay=(pay^sBox[box])&15;
		byte out =(byte)( ouB ? pay : pay<<4 ) ;
		out |=  ouB ? box<<4 : box;
		return out;
		}
				
	private byte doSBox6(byte in,byte[] sBox) {	// SBOX a 6 Bit.
		int box = 3&(in >> 6);
		int pay = in &63;
		pay =63 & (pay ^ sBox[box]);
		pay|=box<<6;
		return (byte) (255&pay);
		}
		
	///////////////////// Funzioni per l'espansione delle chiavi.
	
	private int getW(int[] b,int sz,byte[] i) {		// Prende un po di bit.
		int r=0;
		for (int a=0;a<sz;a++) {
			boolean bit =0!=(i	[b[0]>>3] & 1<<(b[0]&7));
			if (bit) r|=1<<a;
			b[0]++;
			}
		
		return r;
		}

	private byte[] getSW(int[] b,int sz,int n,byte[] i) {	// Prende una string adi bit.
		byte[] q = new byte[n];
		for (int a=0;a<n;a++) q[a] = (byte) getW(b,sz,i);
		return q;
		}

	private void initSBox64(byte[] data,long[] Mask,long[][] Box) {
		long a =word64E(data,24,true) |1;
		long b = a^-1;
		a^=a>>1;
		b^=b<<1;
		
		long nz = 0x35679BCDEF35679BL;
		for (int p=0;p<64;p++) {
					a =Long.rotateRight(a, 1) ^a<<1;
					b=Long.rotateRight(b,1)^b<<1;
					Box[0][p]^=a^nz;
					Box[1][p]^=b^nz^-1;
					nz=nz^nz>>1;
					}
						
		int bp=0;
		int mb=data.length-8;
		
		for (int i=0;i<128;i++) {
					int p=i&63;
					Box[0][p]^=word64E(data,bp %mb ,i>63);
					bp++;
					Box[1][p]^=word64E(data,bp %mb ,i>63)^-1;
					bp++;
					a^=Box[0][p] ^ Box[1][p];
					b^=Box[0][p] ^ Box[1][p];
					b^=b>>1;
					}
			
		a^=a>>1;
		int ai=(int)(a&63);
		for (int i=0;i<64;i++) {
			int bi = i^ai;
			long t0 = i;
		
			t0=t0^t0<<1;
			Box[0][i]^=b^t0;
			Box[1][i]^=b^t0^b>>1;
		
			Mask[i] = (1L<<bi);
			Box[0][i] &= (-1L^Mask[i]);
			Box[1][i] &= (-1L^Mask[i]);
			b++;
			}
		
		}

	private void setKey(byte[] keyi,boolean canAdvance) throws Exception { 		//  Espande la chiave simmetrica ( 256 bit o 512 bit ).
		int ks = keyi.length;
		int kb =ks/8;
		
		if (ks==32)
				maxRound=8;
			else if (ks==64) 
				maxRound=16;
			else throw new Exception("Invalid Key Size. Must be 32 bytes or 64 bytes.");
		
		byte[] key=new byte[ks];
		System.arraycopy(keyi,0, key, 0, ks);
		fAdvance=canAdvance;
		byteSwapper = new int[maxRound];
		sBox4A = new byte[maxRound][4][16];
		sBox4AMode=new byte[maxRound][4];
		sBox6 = new byte[maxRound][2][4];
		dirDir = new boolean[maxRound][2];
		midXor = new byte[maxRound][16];
		byteShift = new int[maxRound];
		bitSwap = new int[maxRound];
		sBox64=new long[2][64];
		sBox64Mask=new long[64];
		localIV = null;
		initSBox64(keyi, sBox64Mask, sBox64);
		
		long last = word64E(key,24,true);
				
		for (int r=0;r<maxRound;r++) {
			byteShift[r] = 0x5a ^ r;
			
			long[] ke = new long[kb];
			for (int a=0;a<kb;a++) {
					ke[a] = word64E(key,8*a,0!=(a&1));
					ke[a]^=0x1248842112488421L;
					ke[a]^=ke[a]<<1;
					}
			
			for (int a=0;a<kb;a++) {
					ke[(a+1)&3] ^=ke[a]>>1;
					ke[a]+=last;
					last^=last>>1;
					}
			
			for (int a=0;a<kb;a++) word64D(ke[a],key,8*a,true);
			
			int[] bp = new int[1];
			if (ks==32) 	for (int b=0;b<4;b++) sBox4A[r][b] = getSW(bp,4,16,key);
			
			if (0!=(r&1)) for (int a=0;a<ks;a++) {
					key[a]^=keyi[a];
					byteShift[r]+=key[a]&255;
					}
			
			byteShift[r]=1+(byteShift[r]&7);
			
			bp[0] = r;
			byteSwapper[r] = getW(bp,4,key);
			sBox4AMode[r] = getSW(bp,2,4,key);
			for (int b=0;b<2;b++) sBox6[r][b] = getSW(bp,6,4,key);
			dirDir[r][0] = getW(bp,1,key)!=0;
			dirDir[r][1] = getW(bp,1,key)!=0;
			midXor[r] = getSW(bp,8,16,key);
			midXor[r] = doSBox64(midXor[r],false);
			for (int b=0;b<16;b++) midXor[r][b]^=keyi[key[b]&31];
			
			if (r==0) swapDir = getW(bp,1,key)!=0;
			if (ks==64) 	for (int b=0;b<4;b++) sBox4A[r][b] = getSW(bp,4,16,key);
			for (int j =0;j<ks;j++) bitSwap[r]+=key[j]&255;
			bitSwap[r] ^=bitSwap[r]>>1;
			bitSwap[r] = (bitSwap[r]^127)&127;
			}
		}

	///////////////////// Funzioni per di crittatura/decrittatura.
	
	private byte[] roundEnc(byte[] inb,int round) { 		//  Un round che critta.
		byte[] in = new byte[16];
		boolean swr = 0!=(round&1);
		System.arraycopy(inb, 0, in, 0,16);
		
		in = byteSwapper(in,byteSwapper[round]);
		
		for (int i =0 ;i<8;i++) in[i] = doSBox6(in[i],sBox6[round][0]);			
		for (int i =8 ;i<16;i++) in[i] = doSBox6(in[i],sBox6[round][1]);
		
		long[] dir =new long[2];
		dir[0] = word64E(in,swr^ swapDir ? 8:0,dirDir[round][0]);
		dir[1] = word64E(in,swr^ swapDir ? 0:8,dirDir[round][1]);
		
		dir[swr ? 1: 0]^=dir[swr ? 0:1];
				
		in = new byte[16];
		word64D(dir[0],in,0,false);
		word64D(dir[1],in,8,false);
		
		for (int i=0;i<16;i++) {
			int j = i>>2;
			in[i] = doSBox4(in[i],sBox4A[round][j],0!=(sBox4AMode[round][j] &1),0!=(sBox4AMode[round][j] &2));
			}
		
		in = doSBox64(in,true);
		in = bitsSwap(in,bitSwap[round]);
		xorSB(in,midXor[round]);
		in = byteShifter(in,true,byteShift[round]);
		return in;		
		}

	private byte[] roundDec(byte[] inb,int round) {		//	Un round che decritta
		boolean swr=0!=(round&1);
		byte[] in = new byte[16];
		System.arraycopy(inb, 0, in, 0,16);
		
		in = byteShifter(in,false,byteShift[round]);
			
		xorSB(in,midXor[round]);
		in = bitsSwap(in,bitSwap[round]);
		in = doSBox64(in,false);
		
		for (int i=0;i<16;i++) {
			int j = i>>2;
			in[i] = doSBox4(in[i],sBox4A[round][j],0!=(sBox4AMode[round][j] &2),0!=(sBox4AMode[round][j] &1));
			}
		
		long[] dir =new long[2];
		dir[0] = word64E(in,0,false);
		dir[1] = word64E(in,8,false);
		
		dir[swr ? 1:0]^=dir[swr ? 0:1];
		
		in=new byte[16];
		
		word64D(dir[0],in,swr^ swapDir ? 8:0,dirDir[round][0]);
		word64D(dir[1],in,swr^ swapDir ? 0:8,dirDir[round][1]);
		
		for (int i =0 ;i<8;i++) in[i] = doSBox6(in[i],sBox6[round][0]);			
		for (int i =8 ;i<16;i++) in[i] = doSBox6(in[i],sBox6[round][1]);
		
		in = byteSwapper(in,byteSwapper[round]);
		
		return in;	
	}

	public byte[] encrypt(byte[] in,byte[] iv) throws Exception { // Cripta un blocco di 16 byte.
		if (fAdvance & !Mode) throw new Exception("This instance is to decrypt.");
		if (in.length!=16) throw new Exception("Invalid data block bust be 16 bytes");
		if (iv.length!=16) throw new Exception("Invalid IV block bust be 16 bytes");
		byte[] o = new byte[16];
		System.arraycopy(in, 0, o, 0, 16);
		xorSB(o,iv);
		for (int r =0;r<maxRound;r++) o = roundEnc(o,r);
		if (fAdvance) advance();
		return o;
		}

	public byte[] decrypt(byte[] in,byte[] iv) throws Exception { // Decripta un blocco di 16 byte.
		if (fAdvance & Mode) throw new Exception("This instance is to encrypt.");
		if (in.length!=16) throw new Exception("Invalid data block bust be 16 bytes");
		byte[] o = new byte[16];
		System.arraycopy(in, 0, o, 0, 16);
		for (int r =maxRound-1;r>-1;r--) o = roundDec(o,r);
		xorSB(o,iv);
		if (fAdvance) advance();
		return o;
		}

	////////////////////////////////////// FUNZIONI AVANZATE /////////////////////////////////////////////////////
	
	private void advance(){	// Cambia la chiave ad ogni blocco (Modalità avanzata).
		for (int r=0;r<maxRound;r++) {
			long[] h = new long[2];
			h[0] = word64E(midXor[r],0,true);
			h[1] = word64E(midXor[r],8,true);
			h[0]^=h[0]<<1;
			h[1]^=h[1]>>1;
			word64D(h[1],midXor[r],0,false);
			word64D(h[0],midXor[r],8,false);
			byteSwapper[r]^=midXor[r][15&(midXor[r][15&byteSwapper[r]])];
			byteSwapper[r]&=15;
			}
	}

	private void nextIV() {		// Calcola da solo un nuovo IV
		long[] iv = new long[3];
		iv[0] = word64E(localIV,0,true);
		iv[1] = word64E(localIV,8,false);
		iv[2] = word64E(localIV,3,true);
		iv[0]^=iv[2];
		iv[1]^=iv[2];
		localIV=new byte[16];
		iv[0]^=iv[0]<<1L;
		iv[1]^=iv[1]>>1L;
		word64D(iv[1],localIV,0,false);
		word64D(iv[0],localIV,8,false);
		}

	public byte[] encrypt(byte[] in) throws Exception {		// Critta un blocco di dati grande.
		if (!Mode) throw new Exception("This instance is to decrypt.");
		int cx = in.length;
		if (0!=(cx&15)) throw new Exception("Invalid data block size.");
		byte[] out = new byte[cx];
		cx>>=4;
		byte[] blo = new byte[16];
		
		for (int bl=0;bl<cx;bl++) {
				System.arraycopy(in, bl*16, blo, 0, 16);
				blo = encrypt(blo,localIV);
				if (fAdvance) nextIV();
				System.arraycopy(blo, 0, out, bl*16, 16);
				}
		return out;
		}

		public byte[] decrypt(byte[] in) throws Exception { 	//  Decritta un blocco di dati grande.
			if (Mode) throw new Exception("This instance is to encrypt.");
			int cx = in.length;
			if (0!=(cx&15)) throw new Exception("Invalid data block size.");
			byte[] out = new byte[cx];
			cx>>=4;
			byte[] blo = new byte[16];
			
			for (int bl=0;bl<cx;bl++) {
					System.arraycopy(in, bl*16, blo, 0, 16);
					blo = decrypt(blo,localIV);
					if (fAdvance) nextIV();
					System.arraycopy(blo, 0, out, bl*16, 16);
					}
			return out;
		}
	
}
