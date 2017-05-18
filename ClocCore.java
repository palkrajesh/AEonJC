package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 *
 * @author Rajesh Kumar Pal
 * 15 Apr 2017
 */
public class ClocCore {
  //AES engine for CLOC
  //private   JavaCardAES aesCipher = null;   
  private   AESKey         m_aesKey = null;
  private   Cipher         m_encryptCipher = null;
  private   Cipher         m_decryptCipher = null;
   
  // Defines
  public final static byte PARAM = (byte)0xc0;
  public final static byte STATE_LEN = 16;
  public final static byte AD_ERROR = -2;
  public final static byte KEY_ERROR = -1;
  public final static byte SUCCESS = 0;
  public final static byte ENC = 1;
  public final static byte DEC = 2;
  public final static byte RETURN_SUCCESS = 0;
  public final static byte RETURN_TAG_NO_MATCH = -1;
  public final static byte RETURN_MEMORY_FAIL = -2;
  public final static byte RETURN_KEYSIZE_ERR = -3;
  
  private byte[] block = null;     // 16 bytes (l:8 Byte +r:8 Byte) 
  private byte[] es = null;        // encryption state
  private byte[] ts = null;        // tag processing state
  private byte[] ekey = null;      // expanded scheduled keys
  private byte[] userkey = null;    // user inputed encryption key
  private short klen = 0;
  private byte[] ad = null;         // authenticated data
  private short adlen = 0;
  private byte[] nounce = null;     // public message number
  private short nlen = 0;
  private byte[] pt = null;         // plaintext
  private short ptlen = 0;
  private byte[] ct = null;         // ciphertext
  private short ctlen = 0;
  private byte[] tag = null;        // authentication tag
  private short tlen = 0;
  private byte[] tempbuf = null;
  
  public ClocCore(){
      block = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
      es = JCSystem.makeTransientByteArray(STATE_LEN, JCSystem.CLEAR_ON_DESELECT);
      ts = JCSystem.makeTransientByteArray(STATE_LEN, JCSystem.CLEAR_ON_DESELECT);
      ekey = JCSystem.makeTransientByteArray((short)240, JCSystem.CLEAR_ON_DESELECT);
      tag = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
      tempbuf = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
      
      /* CREATE AES KEY OBJECT
      aesCipher = new JavaCardAES();
      // set array with initialization vector
      byte[] array_with_IV = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
      Util.arrayFillNonAtomic(array_with_IV, (short)0, (short)16, (byte)0);
      aesCipher.m_IV = array_with_IV;
      aesCipher.m_IVOffset = 0; */
      
      // CREATE AES KEY OBJECT
      m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
      // CREATE OBJECTS FOR CBC CIPHERING
      m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
      m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
      
  }
  
  public byte ClocCoreInitialization(byte[] cipher, short cipherlen, byte[] message, short messagelen, byte[] authdata, short authdatalen,
      byte[] nsecret, byte[] npublic, byte[] key, short keylen){
      
      // change endiannesss of key
      //changeEndianness((short)0, (short)16, key);
      if(keylen != STATE_LEN){
          return KEY_ERROR;
      }
      userkey = key;
      klen = keylen;
      //aesCipher.RoundKeysSchedule(userkey, (short)0, ekey);     //derive scheduled keys in ekey
      // SET KEY VALUE
      m_aesKey.setKey(userkey, (short) 0);

      // INIT CIPHERS WITH NEW KEY
      m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
      m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
      
      //changeEndianness((short)0, (short)240, ekey);
      // change endianness of authdata
      //changeEndianness((short)0, authdatalen, authdata);
      ad = authdata;
      adlen = authdatalen;
      // change endiannesss of cipher not required
      ct = cipher;
      ctlen = cipherlen;
      // change endiannesss of message
      //changeEndianness((short)0, messagelen, message);
      
      pt = message;
      ptlen = messagelen;
      // change endiannesss of nsec     -**- Not applicable for Cloc
      //changeEndianness((short)0, (short)16, nsecret);
      //nsec = nsecret;
      // change endiannesss of npub
      //changeEndianness((short)0, (short)16, npublic);
      nounce = npublic;
      nlen = (short)nounce.length;  //max can be 12 as per specifications
      return SUCCESS;
  }
  
  public void changeEndianness(short startIndex, short endIndex, byte[] src) {
      byte temp;
      for(short k=startIndex; (short)(k+3)<endIndex; k=(short)(k+4)){
            temp = src[k];
            src[k] = src[(short)(k+3)];
            src[(short)(k+3)] = temp;
            temp = src[(short)(k+1)];
            src[(short)(k+1)] = src[(short)(k+2)];
            src[(short)(k+2)] = temp;
        }
  }
  
  public byte crypto_aead_encrypt() {
      // set ciphertext length
      ctlen = (short)(ptlen + 8);
      
      //process the associated data
      process_ad();
      
      // encrypt message
      ae_encrypt(ENC);   // 1=encryption, 2=decryption
      
      // copy the tag to the end of ciphertext
      Util.arrayCopyNonAtomic(tag, (short)0, ct, ptlen, (short)8);
      
      return SUCCESS;
  }
  
  public byte crypto_aead_decrypt() {
      // set plaintext length
      ptlen = (short)(ctlen - 8);
      
      //process the associated data
      process_ad();
      
      // decrypt ciphertext
      ae_encrypt(DEC);   // 1=encryption, 2=decryption
      
      // compare the tag 
      byte ret = Util.arrayCompare(tag, (short)0, ct, ptlen, (short)8);
      if(ret !=0 ) return RETURN_TAG_NO_MATCH;
      
      return SUCCESS;
  }
  
  public byte process_ad() {
      // process the first block
      byte ozp = 0;
      if(adlen < STATE_LEN){       // less than one block
        Util.arrayFillNonAtomic(es, (short)0, (short)16, (byte)0x00);
        Util.arrayCopyNonAtomic(ad, (short)0, es, (short)0,  adlen);
        es[adlen] = (byte)0x80;
        ozp = 1;
      }
      else{     // full first block
        Util.arrayCopyNonAtomic(ad, (short)0, es, (short)0,  STATE_LEN); 
      }
      
      // apply fix0 and the E_k
      byte fix0 = (byte)(es[0] & (byte)0x80);    // test if the MSB is zero
      es[0] &= (byte)0x7f;
      
      // apply the first encryption
      //aesCipher.AESEncryptBlock(es, (short)0, ekey, aesCipher.N_ROUNDS);
      m_encryptCipher.doFinal(es, (short)0, (short)16, es, (short) 0);
      
      // when fix0 works, apply h
      if(fix0 == 1) h();
      
      // process the middle normal blocks of ad
      short j;
      for(j=1; j<(short)(adlen/STATE_LEN); j++) {
          xor_block(j);
          //aesCipher.AESEncryptBlock(es, (short)0, ekey, aesCipher.N_ROUNDS);
          m_encryptCipher.doFinal(es, (short)0, (short)16, es, (short) 0);
      }
      // process the last block partial block if any
      short lastblocklen = (short)(adlen % STATE_LEN);
      if((adlen > STATE_LEN) && lastblocklen != 0){
          xor_bytes_ad(j, lastblocklen);
          es[lastblocklen] ^= 0x80;
          //aesCipher.AESEncryptBlock(es, (short)0, ekey, aesCipher.N_ROUNDS);
          m_encryptCipher.doFinal(es, (short)0, (short)16, es, (short) 0);
          ozp = 1;
      }
      
      // * process the nonce
      // * 1. first byte is: PARAM
      // * 2. then the nonce value
      // * 3. padding if any (at the moment, the parameter set
      // contains padding for all choices)
      es[0] ^= PARAM;
      xor_bytes_nonce();
      // apply padding to nonce
      if((short)(nlen+1) != STATE_LEN)
      es[(short)(nlen+1)] ^= 0x80;
      if(ozp == 1) G();
      else f1();
      Util.arrayCopyNonAtomic(es, (short)0, ts, (short)0,  STATE_LEN); 
      //aesCipher.AESEncryptBlock(es, (short)0, ekey, aesCipher.N_ROUNDS);
      m_encryptCipher.doFinal(es, (short)0, (short)16, es, (short) 0);
      
      return SUCCESS;
  }
  
  public byte ae_encrypt(byte enc_dec) {
      if(ptlen != 0) {
          G2();
          //aesCipher.AESEncryptBlock(ts, (short)0, ekey, aesCipher.N_ROUNDS);
          m_encryptCipher.doFinal(ts, (short)0, (short)16, ts, (short) 0);
      }
      else {
          g1();
          //aesCipher.AESEncryptBlock(ts, (short)0, ekey, aesCipher.N_ROUNDS);
          m_encryptCipher.doFinal(ts, (short)0, (short)16, ts, (short) 0);
          Util.arrayCopyNonAtomic(ts, (short)0, tag, (short)0,  (short)8);
      }
      
      short pc = 0;
      while((short)(pc + STATE_LEN) < ptlen){
          if(enc_dec == ENC){ // encryption
              xor_block_msg(pc);
              Util.arrayCopyNonAtomic(es, (short)0, ct, pc, STATE_LEN);
          }
          else{ // decryption
              xor_bytes_cipher(pc);
              Util.arrayCopyNonAtomic(ct, pc, es, (short)0, STATE_LEN);
          
          }
          xor_block_ts();
          //aesCipher.AESEncryptBlock(ts, (short)0, ekey, aesCipher.N_ROUNDS);
          m_encryptCipher.doFinal(ts, (short)0, (short)16, ts, (short) 0);
          // apply fix1
          es[0] |= (byte)0x80;
          //aesCipher.AESEncryptBlock(es, (short)0, ekey, aesCipher.N_ROUNDS);
          m_encryptCipher.doFinal(es, (short)0, (short)16, es, (short) 0);
          pc += STATE_LEN;
      }
      
      // process the last block
      short lastblocklen = (short)(ptlen - pc);
      if(enc_dec == ENC){ // encryption
          xor_bytes_msg(pc, lastblocklen);
          Util.arrayCopyNonAtomic(es, (short)0, ct, pc, lastblocklen);
      }
      else{ // decryption
          xor_bytes_cipher1(pc, lastblocklen);
          Util.arrayCopyNonAtomic(ct, pc, es, (short)0, lastblocklen);
      
      }
      xor_bytes_msg1(lastblocklen);
      if(lastblocklen != STATE_LEN){ // apply f2
          ts[lastblocklen] ^= (byte)0x80;
          G2();
      }
      else{ // apply f1
          F1();
      }
      
      //aesCipher.AESEncryptBlock(ts, (short)0, ekey, aesCipher.N_ROUNDS);
      m_encryptCipher.doFinal(ts, (short)0, (short)16, ts, (short) 0);
      Util.arrayCopyNonAtomic(ts, (short)0, tag, (short)0, (short)8);
      
      return SUCCESS;
  }
  
  public void xor_block_msg(short j) {
      for(short i=0; i<16; i++)
         es[i] ^= pt[(short)(i + j)];
  }
  
  public void xor_bytes_cipher(short j) {
      for(short i = 0; i < 16; i++)
         pt[(short)(i + j)] = (byte)(es[i] ^ ct[(short)(i + j)]);
  }
  
  public void xor_bytes_cipher1(short j, short lb) {
      for(short i = 0; i < lb; i++)
         pt[(short)(i + j)] = (byte)(es[i] ^ ct[(short)(i + j)]);
  }
  
  public void xor_bytes_msg(short j, short lb) {
      for(short i = 0; i < lb; i++)
         es[i] = (byte)(es[i] ^ pt[(short)(i + j)]);
  }
  
  public void xor_bytes_msg1(short lb) {
      for(short i = 0; i < lb; i++)
         ts[i] = (byte)(ts[i] ^ es[i]);
  }
  
  public void xor_block_ts() {
      for(short i=0; i<16; i++)
         ts[i] ^= es[i];
  }
  
  public void xor_block(short j) {
      for(short i=0; i<16; i++)
         es[i] ^= ad[(short)(i + (short)(16*j))];
  }
  
  public void xor_bytes_ad(short j, short nb) {
      for(short i = 0; i < nb; i++)
         es[i] = (byte)(es[i] ^ ad[(short)(i + (short)(16*j))]);
  }
  
  public void xor_bytes_nonce() {
      for(short i = 0; i < nlen; i++)
         es[(short)(i+1)] = (byte)(es[(short)(i+1)] ^ nounce[i]);
  }
  
  public void f1() {
      es[0] ^= es[8]; es[1] ^= es[9]; es[2] ^= es[10]; es[3] ^= es[11];         
      byte t1, t2, t3, t4;
      t1 = es[4]; t2 = es[5]; t3 = es[6]; t4 = es[7];      
      es[4] ^= es[12]; es[5] ^= es[13]; es[6] ^= es[14]; es[7] ^= es[15];         
      es[12] = (byte)(es[8] ^ es[4]); es[13] = (byte)(es[9] ^ es[5]); es[14] = (byte)(es[10] ^ es[6]); es[15] = (byte)(es[11] ^ es[7]);         
      es[8] = (byte)(t1 ^ es[0]); es[9] = (byte)(t2 ^ es[1]); es[10] = (byte)(t3 ^ es[2]); es[11] = (byte)(t4 ^ es[3]);
  }
  
  public void F1() {
      ts[0] ^= ts[8]; ts[1] ^= ts[9]; ts[2] ^= ts[10]; ts[3] ^= ts[11];         
      byte t1, t2, t3, t4;
      t1 = ts[4]; t2 = ts[5]; t3 = ts[6]; t4 = ts[7];      
      ts[4] ^= ts[12]; ts[5] ^= ts[13]; ts[6] ^= ts[14]; ts[7] ^= ts[15];         
      ts[12] = (byte)(ts[8] ^ ts[4]); ts[13] = (byte)(ts[9] ^ ts[5]); ts[14] = (byte)(ts[10] ^ ts[6]); ts[15] = (byte)(ts[11] ^ ts[7]);         
      ts[8] = (byte)(t1 ^ ts[0]); ts[9] = (byte)(t2 ^ ts[1]); ts[10] = (byte)(t3 ^ ts[2]); ts[11] = (byte)(t4 ^ ts[3]);
  }
  
  public void G() {
      byte t1, t2, t3, t4;
      t1 = (byte)(es[0] ^ es[4]); t2 = (byte)(es[1] ^ es[5]); t3 = (byte)(es[2] ^ es[6]); t4 = (byte)(es[3] ^ es[7]);         
      es[0] = es[4]; es[1] = es[5]; es[2] = es[6]; es[3] = es[7];         
      es[4] = es[8]; es[5] = es[9]; es[6] = es[10]; es[7] = es[11];          
      es[8] = es[12]; es[9] = es[13]; es[10] = es[14]; es[11] = es[15];          
      es[12] = t1; es[13] = t2; es[14] = t3; es[15] = t4;
  }
  
  public void G2() {
      byte t1, t2, t3, t4;
      t1 = (byte)(ts[0] ^ ts[4]); t2 = (byte)(ts[1] ^ ts[5]); t3 = (byte)(ts[2] ^ ts[6]); t4 = (byte)(ts[3] ^ ts[7]);         
      ts[0] = ts[4]; ts[1] = ts[5]; ts[2] = ts[6]; ts[3] = ts[7];         
      ts[4] = ts[8]; ts[5] = ts[9]; ts[6] = ts[10]; ts[7] = ts[11];          
      ts[8] = ts[12]; ts[9] = ts[13]; ts[10] = ts[14]; ts[11] = ts[15];          
      ts[12] = t1; ts[13] = t2; ts[14] = t3; ts[15] = t4;
  }
  
  // f2 = G
  
  public void g1() {
      byte t1, t2, t3, t4;
      t1 = ts[0]; t2 = ts[1]; t3 = ts[2]; t4 = ts[3];         
      ts[0] = ts[8]; ts[1] = ts[9]; ts[2] = ts[10]; ts[3] = ts[11];         
      ts[8] = (byte)(t1 ^ ts[4]); ts[9] = (byte)(t2 ^ ts[5]); ts[10] = (byte)(t3 ^ ts[6]); ts[11] = (byte)(t4 ^ ts[7]);         
      t1 = ts[4]; t2 = ts[5]; t3 = ts[6]; t4 = ts[7];      
      ts[4] = ts[12]; ts[5] = ts[13]; ts[6] = ts[14]; ts[7] = ts[15];         
      ts[12] = (byte)(ts[0] ^ t1); ts[13] = (byte)(ts[1] ^ t2); ts[14] = (byte)(ts[2] ^ t3); ts[15] = (byte)(ts[3] ^ t4);
  }
  
  // g2 = f2
  
  public void h() {
      es[0] ^= es[4]; es[1] ^= es[5]; es[2] ^= es[6]; es[3] ^= es[7];         
      es[4] ^= es[8]; es[5] ^= es[9]; es[6] ^= es[10]; es[7] ^= es[11];          
      es[8] ^= es[12]; es[9] ^= es[13]; es[10] ^= es[14]; es[11] ^= es[15];          
      es[12] ^= es[0]; es[13] ^= es[1]; es[14] ^= es[2]; es[15] ^= es[3];
  }
  
}

