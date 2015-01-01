
/*
 * The M3HC block cipher (mes3hacklab block cipher) test file.
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

public class Main {
	
	public static void main(String[] args) {
		
		String path="./m3hc/";
			try {
				//GENERA UNA CHIAVE:
				SecureRandom RND = SecureRandom.getInstance("SHA1PRNG");
							
				byte[] key = new byte[64];
				byte[] iv = new byte[16];
				
				RND.nextBytes(key);
				RND.nextBytes(iv);
		
				//SALVALA:
				file_put_bytes(path+"msg.key",key);
				file_put_bytes(path+"msg.iv",iv);

				//CARICA IL FILE:
				byte[] msg = file_get_bytes(path+"msg.txt");
				
				//PADDING MULTIPLO DI 16 BYTE:
				int cx = msg.length;
				int dx=cx>>4;
				if (0!=(cx&15)) {		
					dx++;
					dx<<=4;
					byte[] pad = new byte[dx];
					System.arraycopy(msg, 0, pad, 0, cx);
					for (int ax=cx;ax<dx;ax++) pad[ax]=32;
					msg=pad;
					}
				
				System.out.print("Test normale:  \t");
				//CRITTA:
				M3HC Enc = new M3HC(key,iv,M3HC.MODE_ENCRYPT );
				byte[] encmsg = Enc.encrypt(msg);
				Enc=null;
				
				//SALVA:
				file_put_bytes(path+"msg-enc.bin",encmsg);
								
				//DECRITTA:
				M3HC Dec = new M3HC(key,iv,M3HC.MODE_DECRYPT );
				encmsg = Dec.decrypt(encmsg);
				Dec=null;
				
				//SALVA:
				file_put_bytes(path+"msg-dec.txt",encmsg);
				
				//VERIFICA:
				if (Arrays.equals(encmsg, msg)) {
					System.out.print("OK!\n\tTest superato.\n");
					} else {
					System.out.print("Errore!\nQualcosa è andato storto!?!??\nLe chiavi erano giuste???\n");	
					}
			
				/// MODALITÁ AVANZATA:
				System.out.print("Test avanzato:\t");
				//CRITTA:
				Enc = new M3HC(key,iv,M3HC.MODE_ENCRYPT  | M3HC.MODE_ADVANCED);
				encmsg = Enc.encrypt(msg);
				Enc=null;
				
				//SALVA:
				file_put_bytes(path+"msg-enc-adv.bin",encmsg);
								
				//DECRITTA:
				Dec = new M3HC(key,iv,M3HC.MODE_DECRYPT  | M3HC.MODE_ADVANCED);
				encmsg = Dec.decrypt(encmsg);
				Dec=null;
				
				//SALVA:
				file_put_bytes(path+"msg-dec-adv.txt",encmsg);
				
				if (Arrays.equals(encmsg, msg)) {
					System.out.print("OK!\n\tTest superato.\n");
					} else {
					System.out.print("Errore!\nQualcosa è andato storto!?!??\nLe chiavi erano giuste???\n");	
					}
							
			} catch(Exception E) {
				E.printStackTrace();
			}
			
	}
		
	public static void file_put_bytes(String name,byte[]  data) throws Exception {	//  Salva un file.
			FileOutputStream fo = new FileOutputStream(name);
			fo.write(data);
			fo.close();
			}	
	
	public static byte[] file_get_bytes(String name) throws Exception {	// Carica un file.
		File file = new File(name);
		long length = file.length();
		if (length>512384) throw new Exception("File Too big");
		
		byte[] data=new byte[(int)length];
		FileInputStream f = new FileInputStream(name);
		
		f.read(data);
		f.close();
		return data;
	}
	
}
