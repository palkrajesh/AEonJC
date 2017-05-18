package applets;

import javacard.framework.*;

public class MorusCore {

  // Defines
  public final static short CRYPTO_KEYBYTES = 16;
  public final static short CRYPTO_NSECBYTES = 0;
  public final static short CRYPTO_NPUBBYTES = 16;
  public final static short CRYPTO_ABYTES = 16;
  public final static short CRYPTO_NOOVERLAP = 1;
  public final static short n1 = 5;
  public final static short n2 = 31;
  public final static short n3 = 7;
  public final static short n4 = 22;
  public final static short n5 = 13;
  
  public byte i = 0;

  private byte[] state = null;
  private byte[] plaintextblock = null;
  private byte[] ciphertextblock = null;
  private byte[] c = null;
  private short clen = 0;
  private byte[] m = null;
  private short mlen = 0;
  private byte[] ad = null;
  private short adlen = 0;
  private byte[] nsec = null;
  private byte[] npub= null;
  private byte[] k = null;
  private byte[] kk = null;
  private byte temp1, temp2, temp3, temp4;
  private byte[] tempbuf = null;
  
  public MorusCore(){
      state = JCSystem.makeTransientByteArray((short)80, JCSystem.CLEAR_ON_DESELECT);
      plaintextblock = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
      ciphertextblock = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
      tempbuf = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
  }
  
  public void MorusCoreInitialization(byte[] cipher, short cipherlen, byte[] message, short messagelen, byte[] authdata, short authdatalen,
      byte[] nsecret, byte[] npublic, byte[] key){
      
      // change endiannesss of key
      changeEndianness((short)0, (short)16, key);
      k = key;
      // change endianness of authdata
      changeEndianness((short)0, authdatalen, authdata);
      ad = authdata;
      adlen = authdatalen;
      // change endiannesss of cipher not required
      c = cipher;
      clen = cipherlen;
      // change endiannesss of message
      changeEndianness((short)0, messagelen, message);
      m = message;
      mlen = messagelen;
      // change endiannesss of nsec
      changeEndianness((short)0, (short)16, nsecret);
      nsec = nsecret;
      // change endiannesss of npub
      changeEndianness((short)0, (short)16, npublic);
      npub = npublic;
  }
  
  public void changeEndianness(short startIndex, short endIndex, byte[] src) {
      for(short k=startIndex; (short)(k+3)<endIndex; k=(short)(k+4)){
            temp1 = src[k];
            src[k] = src[(short)(k+3)];
            src[(short)(k+3)] = temp1;
            temp1 = src[(short)(k+1)];
            src[(short)(k+1)] = src[(short)(k+2)];
            src[(short)(k+2)] = temp1;
        }
  }
  
  
  public void xor(byte srcdstIndex, byte inpIndex){
        for(i=0; i<16; i++)
            state[(byte)(srcdstIndex+i)] ^= state[(byte)(inpIndex+i)];
    }
    
    public void xorMsg(byte Index, byte[] msgblk){
        for(i=0; i<16; i++)
            state[(byte)(Index+i)] ^= msgblk[i];
    }
    
    public void andxor(byte dstIndex, byte inp1Index, byte inp2Index){
        for(i=0; i<16; i++)
            state[(byte)(dstIndex+i)] ^= (byte)(state[(byte)(inp1Index+i)] & state[(byte)(inp2Index+i)]);
    }
    
    public void changeEndiannessState(){
        for(i=0; i<80; i=(byte)(i+4)){
            if(i<16 || i>=32){
                temp1 = state[i];
                state[i] = state[(byte)(i+3)];
                state[(byte)(i+3)] = temp1;
                temp1 = state[(byte)(i+1)];
                state[(byte)(i+1)] = state[(byte)(i+2)];
                state[(byte)(i+2)] = temp1;
            }
        }
    }
    
    public void rotl5(){
        for(byte j=0; j<16; j=(byte)(j+4)){
            temp1 = state[j];
            for(i=j; i<(byte)(j+4); i++){
                if((i+1)%4 != 0){
                state[i] = (byte)( state[i] << (byte)5  | (byte)( state[(byte)(i+1)] >>> (byte)3  & (byte)0x1F ) );
                }
                else
                state[i] = (byte)( state[i] << (byte)5  | (byte)( (byte)( temp1 >>> (byte)3 ) & (byte)0x1F ) );
            }
        }
    }
    
    public void rotl31(){
        for(byte j=16; j<32; j=(byte)(j+4)){
            temp1 = state[(byte)(j+3)];
            for(i=(byte)(j+3); i>=j; i--){
                if(i%4 != 0){
                    state[i] = (byte)( (byte)( (byte)( state[i] >>> (byte)1 ) & (byte)0x7F ) | (byte)(state[(byte)(i-1)] << (byte)7) );
                }
                else
                   state[i] = (byte)( (byte)( (byte)( state[i] >>> (byte)1 ) & (byte)0x7F ) | (byte)(temp1 << (byte)(7)) );
            }
        }
    }
    
    public void rotl7(){
        for(byte j=32; j<48; j=(byte)(j+4)){
            temp1 = state[j];
            for(i=j; i<(byte)(j+4); i++){
                if((i+1)%4 != 0){
                state[i] = (byte)( (byte)( state[i] << (byte)7 ) | (byte)( (byte)( state[(byte)(i+1)] >>> (byte)1 ) & (byte)0x7F ) );
                }
                else
                state[i] = (byte)( (byte)( state[i] << (byte)7 ) | (byte)( (byte)( temp1 >>> (byte)1 ) & (byte)0x7F ) );
            }
        }
    }
    
    public void rotl22(){ // equivalent to rotr10
        for(byte j=48; j<64; j=(byte)(j+4)){
            temp1 = state[(byte)(j+3)];
            temp2 = state[(byte)(j+2)];
            for(i=(byte)(j+3); i>=j; i--){
                if(i%4 == 3)
                    state[i] = (byte)( (byte)( (byte)( state[(byte)(i-1)] >>> (byte)2 ) & (byte)0x3F ) | (byte)(state[(byte)(i-2)] << (byte)6) );
                else if(i%4 == 2)
                    state[i] = (byte)( (byte)( (byte)( state[(byte)(i-1)] >>> (byte)2 ) & (byte)0x3F ) | (byte)(state[(byte)(i-2)] << (byte)6) );
                else if(i%4 == 1)
                    state[i] = (byte)( (byte)( (byte)( state[(byte)(i-1)] >>> (byte)2 ) & (byte)0x3F ) | (byte)(temp1 << (byte)(6)) );
                else if(i%4 == 0)
                   state[i] = (byte)( (byte)( (byte)( temp1 >>> (byte)2 ) & (byte)0x3F ) | (byte)(temp2 << (byte)(6)) );
            }
        }
    }
    
    public void rotl13(){
        for(byte j=64; j<80; j=(byte)(j+4)){
            temp1 = state[j];
            temp2 = state[(byte)(j+1)];
            for(i=j; i<(byte)(j+4); i++){
                if(i%4 == 0)
                    state[i] = (byte)( (byte)( state[(byte)(i+1)] << (byte)5 )  | (byte)( (byte)(state[(byte)(i+2)] >>> (byte)3) & (byte)0x1F ) );
                else if(i%4 == 1)
                    state[i] = (byte)( (byte)( state[(byte)(i+1)] << (byte)5 )  | (byte)( (byte)(state[(byte)(i+2)] >>> (byte)3) & (byte)0x1F ) );
                else if(i%4 == 2)
                    state[i] = (byte)( (byte)( state[(byte)(i+1)] << (byte)5 )  | (byte)( (byte)(temp1 >>> (byte)3) & (byte)0x1F ) );
                else if(i%4 == 3)
                   state[i] = (byte)( (byte)( temp1 << (byte)5 ) | (byte)( (byte)(temp2 >>> (byte)3) & (byte)0x1F ) );
            }
        }
    }
    
    public void byteRot(byte Index){
        Util.arrayCopyNonAtomic(state, (short)Index, tempbuf, (short)0, (short)16);
        Util.arrayCopyNonAtomic(tempbuf, (short)12, state, (short)Index, (short)4);
        Util.arrayCopyNonAtomic(tempbuf, (short)0, state, (short)(Index+4), (short)12);
    }
    
    public void byteRot1(byte Index){
        Util.arrayCopyNonAtomic(state, (short)Index, tempbuf, (short)0, (short)16);
        Util.arrayCopyNonAtomic(tempbuf, (short)4, state, (short)Index, (short)4);
        Util.arrayCopyNonAtomic(tempbuf, (short)8, state, (short)(Index+4), (short)8);   
        Util.arrayCopyNonAtomic(tempbuf, (short)0, state, (short)(Index+12), (short)4);
    }
    
    public void swap(byte Index){
        Util.arrayCopyNonAtomic(state, Index, tempbuf, (short)0, (short)16);
        Util.arrayCopyNonAtomic(tempbuf, (short)4, state, (short)(Index+12), (short)4);
        Util.arrayCopyNonAtomic(tempbuf, (short)12, state, (short)(Index+4), (short)4);
        Util.arrayCopyNonAtomic(tempbuf, (short)0, state, (short)(Index+8), (short)4);
        Util.arrayCopyNonAtomic(tempbuf, (short)8, state, (short)Index, (short)4);
    }
    
    public void morus_stateupdate(byte[] msgblk){
        xor((byte)0, (byte)48);
        andxor((byte)0, (byte)16, (byte)32);
        rotl5();
        byteRot((byte)48);
        
        xorMsg((byte)16, msgblk);
        xor((byte)16, (byte)64);
        andxor((byte)16, (byte)32, (byte)48);
        rotl31();
        swap((byte)64);
        
        xorMsg((byte)32, msgblk);
        xor((byte)32, (byte)0);
        andxor((byte)32, (byte)48, (byte)64);
        rotl7();
        byteRot1((byte)0);
        
        xorMsg((byte)48, msgblk);
        xor((byte)48, (byte)16);
        andxor((byte)48, (byte)64, (byte)0);
        rotl22();
        swap((byte)16);
        
        xorMsg((byte)64, msgblk);
        xor((byte)64, (byte)32);
        andxor((byte)64, (byte)0, (byte)16);
        rotl13();
        byteRot((byte)32);
    }
  
    public void morus_initialization(){
        byte[] temp = { (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 };
        byte[] con0 = {(byte)0x00,(byte)0x01,(byte)0x01,(byte)0x02,(byte)0x03,(byte)0x05,(byte)0x08,(byte)0x0d,(byte)0x15,(byte)0x22,(byte)0x37,(byte)0x59,(byte)0x90,(byte)0xe9,(byte)0x79,(byte)0x62};
        byte[] con1 = {(byte)0xdb, (byte)0x3d, (byte)0x18, (byte)0x55, (byte)0x6d, (byte)0xc2, (byte)0x2f, (byte)0xf1, (byte)0x20, (byte)0x11, (byte)0x31, (byte)0x42, (byte)0x73, (byte)0xb5, (byte)0x28, (byte)0xdd};
        
        Util.arrayCopyNonAtomic(npub, (short)0, state, (short)0, (short)16);
        Util.arrayCopyNonAtomic(k, (short)0, state, (short)16, (short)16);
        Util.arrayFillNonAtomic(state, (short)32, (short)16, (byte)0xff);
        Util.arrayCopyNonAtomic(con0, (short)0, state, (short)48, (short)16);
        Util.arrayCopyNonAtomic(con1, (short)0, state, (short)64, (short)16);
        Util.arrayFillNonAtomic(temp, (short)0, (short)16, (byte)0x00);
        
        changeEndiannessState();
        
        for(short k=0; k<16; k++) morus_stateupdate(temp);
        for(i=0; i<16; i++)
            state[(byte)(i+16)] ^= k[i];
    }   
    
    public void morus_enc_auth_step() {
        //encryption
        for(short k=0; k<4; k++){
            ciphertextblock[(byte)(0+k)] = (byte)(plaintextblock[(byte)(0+k)] ^ state[(byte)(0+k)] ^ state[(byte)(20+k)] ^ (byte)(state[(byte)(32+k)] & state[(byte)(48+k)]));
            ciphertextblock[(byte)(4+k)] = (byte)(plaintextblock[(byte)(4+k)] ^ state[(byte)(4+k)] ^ state[(byte)(24+k)] ^ (byte)(state[(byte)(36+k)] & state[(byte)(52+k)]));
            ciphertextblock[(byte)(8+k)] = (byte)(plaintextblock[(byte)(8+k)] ^ state[(byte)(8+k)] ^ state[(byte)(28+k)] ^ (byte)(state[(byte)(40+k)] & state[(byte)(56+k)]));
            ciphertextblock[(byte)(12+k)] = (byte)(plaintextblock[(byte)(12+k)] ^ state[(byte)(12+k)] ^ state[(byte)(16+k)] ^ (byte)(state[(byte)(44+k)] & state[(byte)(60+k)]));
        }
        //System.out.println(bytesToHex(ciphertextblock));
        morus_stateupdate(plaintextblock);
    }
    
    public void morus_dec_auth_step() {
        //decryption
        for(short k=0; k<4; k++){
            plaintextblock[(byte)(0+k)] = (byte)(ciphertextblock[(byte)(0+k)] ^ state[(byte)(0+k)] ^ state[(byte)(20+k)] ^ (byte)(state[(byte)(32+k)] & state[(byte)(48+k)]));
            plaintextblock[(byte)(4+k)] = (byte)(ciphertextblock[(byte)(4+k)] ^ state[(byte)(4+k)] ^ state[(byte)(24+k)] ^ (byte)(state[(byte)(36+k)] & state[(byte)(52+k)]));
            plaintextblock[(byte)(8+k)] = (byte)(ciphertextblock[(byte)(8+k)] ^ state[(byte)(8+k)] ^ state[(byte)(28+k)] ^ (byte)(state[(byte)(40+k)] & state[(byte)(56+k)]));
            plaintextblock[(byte)(12+k)] = (byte)(ciphertextblock[(byte)(12+k)] ^ state[(byte)(12+k)] ^ state[(byte)(16+k)] ^ (byte)(state[(byte)(44+k)] & state[(byte)(60+k)]));
        }
        //System.out.println(bytesToHex(ciphertextblock));
        morus_stateupdate(plaintextblock);
    }
    
    public void morus_tag_generation() {
        Util.arrayCopyNonAtomic(state, (short)48, tempbuf, (short)0, (short)16);
        Util.arrayFillNonAtomic(plaintextblock, (short)0, (short)16, (byte)0x00);
        Util.arrayFillNonAtomic(ciphertextblock, (short)0, (short)16, (byte)0x00);
        Util.setShort(plaintextblock, (byte)2, (short)(adlen<<3));
        Util.setShort(ciphertextblock, (byte)2, (short)(mlen<<3));
        for(i=0; i<8; i++){
            tempbuf[i] ^= plaintextblock[i];
            tempbuf[(byte)(i+8)] ^= ciphertextblock[i];
        }
        Util.arrayCopyNonAtomic(tempbuf, (short)0, plaintextblock, (short)0, (short)16);
        
        xor((byte)64, (byte)0);
        for(short k=0; k<8; k++) morus_stateupdate(plaintextblock);
        
        for (i = 2; i < 5; i++) {
        for (byte j = 0; j < 4; j++) { 
            state[(byte)(16+(byte)(4*j))] ^= state[(byte)((byte)(16*i)+(byte)(4*j))];
            state[(byte)(16+(byte)(4*j)+1)] ^= state[(byte)((byte)(16*i)+(byte)((byte)(4*j)+1))];
            state[(byte)(16+(byte)(4*j)+2)] ^= state[(byte)((byte)(16*i)+(byte)((byte)(4*j)+2))];
            state[(byte)(16+(byte)(4*j)+3)] ^= state[(byte)((byte)(16*i)+(byte)((byte)(4*j)+3))];
        }}
        // copy the tag at the end of cipher
        Util.arrayCopyNonAtomic(state, (short)16, c, mlen, (short)16);
    }
    
    public byte morus_tag_verification() {
        Util.arrayCopyNonAtomic(state, (short)48, tempbuf, (short)0, (short)16);
        Util.arrayFillNonAtomic(plaintextblock, (short)0, (short)16, (byte)0x00);
        Util.arrayFillNonAtomic(ciphertextblock, (short)0, (short)16, (byte)0x00);
        Util.setShort(plaintextblock, (byte)2, (short)(adlen<<3));
        Util.setShort(ciphertextblock, (byte)2, (short)(mlen<<3));
        for(i=0; i<8; i++){
            tempbuf[i] ^= plaintextblock[i];
            tempbuf[(byte)(i+8)] ^= ciphertextblock[i];
        }
        Util.arrayCopyNonAtomic(tempbuf, (short)0, plaintextblock, (short)0, (short)16);
        
        xor((byte)64, (byte)0);
        for(short k=0; k<8; k++) morus_stateupdate(plaintextblock);
        
        for (i = 2; i < 5; i++) {
        for (byte j = 0; j < 4; j++) { 
            state[(byte)(16+(byte)(4*j))] ^= state[(byte)((byte)(16*i)+(byte)(4*j))];
            state[(byte)(16+(byte)(4*j)+1)] ^= state[(byte)((byte)(16*i)+(byte)((byte)(4*j)+1))];
            state[(byte)(16+(byte)(4*j)+2)] ^= state[(byte)((byte)(16*i)+(byte)((byte)(4*j)+2))];
            state[(byte)(16+(byte)(4*j)+3)] ^= state[(byte)((byte)(16*i)+(byte)((byte)(4*j)+3))];
        }}
        // verify the tag (calculated tag is in state[16:31] & stored tag is in c[clen-16:clen]
        temp1 = 0;
        Util.arrayCopyNonAtomic(c, (short)(clen-16), plaintextblock, (short)0, (short)16);
        for (i = 0; i < 1; i++){
            //System.out.println(bytesToHex(plaintextblock));
            temp1 |=  (byte)( plaintextblock[i] ^ state[(byte)(16+i)] );
        }
        if (temp1 == (byte)0) return (byte)0; 
        else return (byte)-1;
    }
    
    
    public byte crypto_aead_encrypt() {
        
        // initialization
        morus_initialization();
        
        // process the associated data
        for (i = 0; (i+16) <= adlen; i += 16) {
            Util.arrayCopyNonAtomic(ad, i, plaintextblock, (short)0, (short)16);
            morus_enc_auth_step();
        }
        if (  (adlen%16) != 0 )  {
            Util.arrayFillNonAtomic(plaintextblock, (short)0, (short)16, (byte)0);
            Util.arrayCopyNonAtomic(ad, i, plaintextblock, (short)0, (short)(adlen%16));
            morus_enc_auth_step();
        }
        
        // encrypt the plaintext
        short k=0;
        for (k = 0; (short)(k+16) <= mlen; k += 16) {
            Util.arrayCopyNonAtomic(m, k, plaintextblock, (short)0, (short)16);
            morus_enc_auth_step();
            Util.arrayCopyNonAtomic(ciphertextblock, (short)0, c, k, (short)16);
        }
        if (  (mlen%16) != 0 )  {
            Util.arrayFillNonAtomic(plaintextblock, (short)0, (short)16, (byte)0);
            Util.arrayCopyNonAtomic(m, k, plaintextblock, (short)0, (short)(mlen%16));
            morus_enc_auth_step();
            Util.arrayCopyNonAtomic(ciphertextblock, (short)0, c, k, (short)(mlen%16));
        }
        
        morus_tag_generation();
        
        return (byte)0;
    }
    
    public byte crypto_aead_decrypt() {
        
        if (clen < 16) return -1;
        
        // initialization
        morus_initialization();
        
        // process the associated data
        for (i = 0; (short)(i+16) <= adlen; i += 16) {
            Util.arrayCopyNonAtomic(ad, i, plaintextblock, (short)0, (short)16);
            morus_enc_auth_step();
        }
        if (  (adlen%16) != 0 )  {
            Util.arrayFillNonAtomic(plaintextblock, (short)0, (short)16, (byte)0);
            Util.arrayCopyNonAtomic(ad, i, plaintextblock, (short)0, (short)(adlen%16));
            morus_enc_auth_step();
        }
        
        // decrypt the ciphertext
        short k=0;
        for (k = 0; (short)(k+16) <= (short)(clen-16); k += 16) {
            Util.arrayCopyNonAtomic(c, k, ciphertextblock, (short)0, (short)16);
            morus_dec_auth_step();
            Util.arrayCopyNonAtomic(plaintextblock, (short)0, m, k, (short)16);
        }
        if (  (clen%16) != 0 )  {
            Util.arrayFillNonAtomic(ciphertextblock, (short)0, (short)16, (byte)0);
            Util.arrayCopyNonAtomic(c, k, ciphertextblock, (short)0, (short)(clen%16));
            morus_dec_auth_step();
            Util.arrayCopyNonAtomic(plaintextblock, (short)0, m, k, (short)(clen%16));
        }
        changeEndianness((short)0, (short)(clen-16), m);
        
        // tag verification
        temp2 = morus_tag_verification();
        
        return temp2;
    }
    
}

