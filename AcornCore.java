package applets;

import javacard.framework.*;
import host.AcornMain;

/**
 *
 * @author Rajesh Kumar Pal
 * 05 May 2017
 */
public class AcornCore {
  
  // Defines
  public final static short LEN = 16;
  public final static byte SUCCESS = 0;
  public final static byte KEY_ERROR = -1;
  
  //private byte[] plaintextbyte = null;     // 16 bytes plaintext 
  //private byte[] ciphertextbyte = null;    // 16 bytes ciphertext 
  private byte[] mac = null;        // authentication tag
  private byte[] state = null;      // state
  private byte[] ekey = null;       // expanded scheduled keys
  private byte[] userkey = null;    // user inputed encryption key
  private short klen = 0;
  private byte[] ad = null;         // authenticated data
  private short adlen = 0;
  private byte[] nonce = null;     // public message number
  private short nlen = 0;
  private byte[] pt = null;         // plaintext
  private short ptlen = 0;
  private byte[] ct = null;         // ciphertext
  private short ctlen = 0;
  private byte[] tempbuf = null;
  private byte[] m = null;
  private byte plaintextbyte, ciphertextbyte, plaintextbit, ciphertextbit;
  private byte ks, ksbyte;
  
  public AcornCore(){
      state = JCSystem.makeTransientByteArray((short)293, JCSystem.CLEAR_ON_DESELECT);
      mac = JCSystem.makeTransientByteArray(LEN, JCSystem.CLEAR_ON_DESELECT);
      ekey = JCSystem.makeTransientByteArray(LEN, JCSystem.CLEAR_ON_DESELECT);
      tempbuf = JCSystem.makeTransientByteArray(LEN, JCSystem.CLEAR_ON_DESELECT);
      m = JCSystem.makeTransientByteArray((short)1536, JCSystem.CLEAR_ON_DESELECT);
  }
  
  // The initialization state of AEGIS
  // The input to initialization is the 128-bit key; 128-bit IV;
  public byte AcornCoreInitialization(byte[] cipher, short cipherlen, byte[] message, short messagelen, byte[] authdata, short authdatalen,
      byte[] nsecret, byte[] npublic, byte[] key, short keylen){
      if(keylen != LEN){
          return KEY_ERROR;
      }
      userkey = key;
      klen = keylen;
      
      ct = cipher;
      ctlen = cipherlen;
      pt = message;
      ptlen = messagelen;
      ad = authdata;
      adlen = authdatalen;
      nonce = npublic;  // iv
      nlen = (short)nonce.length;  
      return SUCCESS;
  }
  
  /*public void changeEndianness(short startIndex, short endIndex, byte[] src) {
      byte temp;
      for(short k=startIndex; (short)(k+3)<endIndex; k=(short)(k+4)){
            temp = src[k];
            src[k] = src[(short)(k+3)];
            src[(short)(k+3)] = temp;
            temp = src[(short)(k+1)];
            src[(short)(k+1)] = src[(short)(k+2)];
            src[(short)(k+2)] = temp;
        }
  }*/
  
  public byte acorn128_initialization() {
      short i,j;
      byte tem=0;
      //initialize the state to 0
      Util.arrayFillNonAtomic(state, (short)0, (short)293, (byte)0x00);
      
      //set the value of m
      for(j = 0; j <= 127; j++) 
          m[j] = (byte)( (byte)( userkey[(byte)(j/8)] >> (byte)(j & 7) ) & (byte)0x1);
      
      for(j = 0; j <= 127; j++)
          m[(short)(j+128)] = (byte)( (byte)( nonce[(byte)(j/8)]  >> (byte)(j & 7) ) & (byte)0x1);
       
      m[(short)(256)] = 1;
     
      Util.arrayFillNonAtomic(m, (short)257, (short)1279, (byte)0x00);
      
      //System.out.println("m_init:");
      //System.out.println(AcornMain.bytesToHex(m));
      
      ks=0; 
      //run the cipher for 1536 steps
      for (i = 0; i < 1536; i++) {
          plaintextbit = m[i];
          Encrypt_StateUpdate128((byte)0x01, (byte)0x01);
          tem = ciphertextbit;  
          //System.out.println(i + ", pb: " + AcornMain.byteToHex(plaintextbit) + ", cb: " + AcornMain.byteToHex(ciphertextbit));
      }
  
      return SUCCESS;
  }
  
  //encrypt one bit (input: plaintextbit, output: ciphertextbit)
  public byte Encrypt_StateUpdate128(byte ca, byte cb) {
      byte f;
      state[(short)289] ^= (byte)(state[(short)235] ^ state[(short)230]);
      state[(short)230] ^= (byte)(state[(short)196] ^ state[(short)193]);
      state[(short)193] ^= (byte)(state[(short)160] ^ state[(short)154]);
      state[(short)154] ^= (byte)(state[(short)111] ^ state[(short)107]);
      state[(short)107] ^= (byte)(state[(short)66]  ^ state[(short)61]);
      state[(short)61]  ^= (byte)(state[(short)23]  ^ state[(short)0]);
      
      f = FBK128(ca, cb);
      
      for(short j = 0; j <= 291; j++) state[j] = state[(short)(j+1)];
      state[(short)292] = (byte)(f ^ plaintextbit);
      ciphertextbit = (byte)(ks ^ plaintextbit);
       
      return SUCCESS;
  }
  
  //decrypt one bit (input: plaintextbit, output: ciphertextbit)
  public byte Decrypt_StateUpdate128(byte ca, byte cb) {
      byte f;
      state[(short)289] ^= (byte)(state[(short)235] ^ state[(short)230]);
      state[(short)230] ^= (byte)(state[(short)196] ^ state[(short)193]);
      state[(short)193] ^= (byte)(state[(short)160] ^ state[(short)154]);
      state[(short)154] ^= (byte)(state[(short)111] ^ state[(short)107]);
      state[(short)107] ^= (byte)(state[(short)66]  ^ state[(short)61]);
      state[(short)61]  ^= (byte)(state[(short)23]  ^ state[(short)0]);
      
      f = FBK128(ca, cb);
      
      for(short j = 0; j <= 291; j++) state[j] = state[(short)(j+1)];
      plaintextbit = (byte)(ks ^ ciphertextbit);
      state[(short)292] = (byte)(f ^ plaintextbit);
       
      return SUCCESS;
  }
  
  public byte FBK128(byte ca, byte cb) {
      ks = KSG128();
      return (byte)(state[(short)0] ^ (byte)(state[(short)107] ^ (byte)1) ^ maj(state[(short)244], state[(short)23], state[(short)160]) ^ ch(state[(short)230], state[(short)111], state[(short)66]) ^ (byte)(ca & state[(short)196]) ^ (byte)(cb & ks) );
  }
  
  public byte KSG128() {
      return (byte)((byte)state[(short)12] ^ (byte)state[(short)154] ^ maj((byte)state[(short)235], (byte)state[(short)61], (byte)state[(short)193]) );
  }
  
  public byte maj(byte x, byte y, byte z) {
      return (byte)( (byte)(x & y) ^ (byte)(x & z) ^ (byte)(y & z) );
  }
  
  public byte ch(byte x, byte y, byte z) {
      return (byte)( (byte)(x & y) ^ (byte)( (byte)(x ^ 1) & z )  );
  }
  
  // encrypt one byte
  public byte acorn128_enc_onebyte(byte cabyte, byte cbbyte) {
      byte caBit, cbBit, i;
      ciphertextbyte = (byte)0x00;
      ksbyte = 0;
      ks = 0;
      for(i = 0; i < 8; i++) {
          caBit = (byte)( (byte)(cabyte >> i) & (byte)1);
          cbBit = (byte)( (byte)(cbbyte >> i) & (byte)1);
          plaintextbit = (byte)( (byte)(plaintextbyte >> i) & (byte)1);
          Encrypt_StateUpdate128(caBit, cbBit);
          ciphertextbyte |= (byte)(ciphertextbit << i);
          ksbyte |= (byte)(ks << i);
      }
      //System.out.println("p: " + AcornMain.byteToHex(plaintextbyte) + ", c: " + AcornMain.byteToHex(ciphertextbyte));
      return SUCCESS;
  }
  
  // decrypt one byte
  public byte acorn128_dec_onebyte(byte cabyte, byte cbbyte) {
      byte caBit, cbBit, i;
      plaintextbyte = (byte)0x00;
      ksbyte = 0;
      ks = 0;
      for(i = 0; i < 8; i++) {
          caBit = (byte)( (byte)(cabyte >> i) & (byte)1);
          cbBit = (byte)( (byte)(cbbyte >> i) & (byte)1);
          ciphertextbit = (byte)( (byte)(ciphertextbyte >> i) & (byte)1);
          Decrypt_StateUpdate128(caBit, cbBit);
          plaintextbyte |= (byte)(plaintextbit << i);
      }
      //System.out.println("p: " + AcornMain.byteToHex(plaintextbyte) + ", c: " + AcornMain.byteToHex(ciphertextbyte));
      return SUCCESS;
  }
  
  public byte acorn128_tag_generation() {
      plaintextbyte = 0;
      ciphertextbyte = 0;
      ksbyte = 0;
      byte i;
      
      for(i = 0; i < (byte)(512/8); i++) {
        acorn128_enc_onebyte((byte)0xff, (byte)0xff);
        if ( i >= (byte)((byte)(512/8) - 16) ) {mac[i-(byte)((byte)(512/8)-16)] = ksbyte; }
      }
      return SUCCESS;
   }
  
  
  public byte crypto_aead_encrypt() {
      byte i;
      byte ca, cb;
      short j;
      //initialization stage
      acorn128_initialization();
      
      //process the associated data
      for(i = 0; i < adlen; i++) {
          plaintextbyte = ad[i];
          acorn128_enc_onebyte((byte)0xff, (byte)0xff);   
      } 
      
      for(i = 0; i < (byte)(512/8); i++) {
        if ( i == 0 ) plaintextbyte = 1;
        else plaintextbyte = 0;

        if ( i < (byte)(256/8) )   ca = (byte)0xff;
        else ca = (byte)0x00;

        cb = (byte)0xff;

        acorn128_enc_onebyte(ca, cb);
      }
      
      //process the plaintext
      for(j = 0; j < ptlen; j++) {
          plaintextbyte = pt[j];
          acorn128_enc_onebyte((byte)0xff, (byte)0x00);
          ct[j] = ciphertextbyte;
      }

      for(i = 0; i < (byte)(512/8); i++) {
        if ( i == 0 ) plaintextbyte = 1;
        else plaintextbyte = 0;

        if ( i < (byte)(256/8) )   ca = (byte)0xff;
        else ca = (byte)0x00;

        cb = (byte)0x00;

        acorn128_enc_onebyte(ca, cb);
      }
      
      //System.out.println("state_final:");
      //System.out.println(AcornMain.bytesToHex(state)); 
      
      //finalization stage, we assume that the tag length is a multiple of bytes
      acorn128_tag_generation();
      ctlen = (short)(ptlen + 16);
      Util.arrayCopyNonAtomic(mac, (short)0, ct, ptlen, LEN);
      
      return SUCCESS;
  }
  
  public byte crypto_aead_decrypt() {
      byte i;
      byte ca, cb;
      short j;
      byte check = 0;
      
      if(ctlen < 16) return -1;
      
      //initialization stage
      acorn128_initialization();
      
      //process the associated data
      for(i = 0; i < adlen; i++) {
          plaintextbyte = ad[i];
          acorn128_enc_onebyte((byte)0xff, (byte)0xff);   
      } 
      
      for(i = 0; i < (byte)(512/8); i++) {
        if ( i == 0 ) plaintextbyte = 1;
        else plaintextbyte = 0;

        if ( i < (byte)(256/8) )   ca = (byte)0xff;
        else ca = (byte)0x00;

        cb = (byte)0xff;

        acorn128_enc_onebyte(ca, cb);
      }
      
      //process the plaintext
      ptlen = (short)(ctlen - 16);
      for(j = 0; j < ptlen; j++) {
          ciphertextbyte = ct[j];
          acorn128_dec_onebyte((byte)0xff, (byte)0x00);
          pt[j] = plaintextbyte;
      }

      for(i = 0; i < (byte)(512/8); i++) {
        if ( i == 0 ) plaintextbyte = 1;
        else plaintextbyte = 0;

        if ( i < (byte)(256/8) )   ca = (byte)0xff;
        else ca = (byte)0x00;

        cb = (byte)0x00;

        acorn128_enc_onebyte(ca, cb);
      }
      
      //System.out.println("state_final:");
      //System.out.println(AcornMain.bytesToHex(state)); 
      
      //finalization stage, we assume that the tag length is a multiple of bytes
      acorn128_tag_generation();
      //Util.arrayCopyNonAtomic(mac, (short)0, ct, ptlen, LEN);
      for(i = 0; i  < 16; i++) check |= (mac[i] ^ ct[(short)(ctlen - 16 + i)]);
    
      if (check == 0)  return SUCCESS;
      else return -1;
    
  }
      
  
}

