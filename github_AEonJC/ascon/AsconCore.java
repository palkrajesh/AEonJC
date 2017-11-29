
package ascon;

import javacard.framework.*;

public class AsconCore {
    
    // Defines
    public final static short CRYPTO_KEYBYTES = 16;
    public final static short CRYPTO_NSECBYTES = 0;
    public final static short CRYPTO_NPUBBYTES = 16;
    public final static short CRYPTO_ABYTES = 16;
    public final static short CRYPTO_NOOVERLAP = 1;
    public final static short EIGHT = 8;
    public final static short FORTY = 40;
    
    private byte[] x0 = null;
    private byte[] x1 = null;
    private byte[] x2 = null;
    private byte[] x3 = null;
    private byte[] x4 = null;
    private byte[] t0 = null;
    private byte[] t1 = null;
    private byte[] t2 = null;
    private byte[] t3 = null;
    private byte[] t4 = null;
    private byte[] tempbuf = null;
    private byte[] S = null;
    
    public AsconCore(){
        x0 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        x1 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        x2 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        x3 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        x4 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        t0 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        t1 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        t2 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        t3 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        t4 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        tempbuf = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        S = JCSystem.makeTransientByteArray(FORTY, JCSystem.CLEAR_ON_DESELECT);
    }
    
    public void xor(byte[] in1, byte[] in2, byte[] out){
        for(short i=0; i<8; i++)
            out[i] = (byte)(in1[i] ^ in2[i]);
    }
    
    public void and(byte[] in1, byte[] in2, byte[] out){
        for(short i=0; i<8; i++)
            out[i] = (byte)(in1[i] & in2[i]);
    }
    
    public void not(byte[] in1, byte[] out){
        for(short i=0; i<8; i++)
            out[i] = (byte)(~in1[i]);
    }
    
    // get the bit value
    public short getBit(byte[] data, short pos) {
        short posByte = (short)(pos/8);
        short posBit = (short)(pos%8);
        byte valByte = data[posByte];
        short valShort = (short)(valByte>>(8-(posBit+1)) & 0x0001);
        return valShort;
    }
    
    // set the bit value
    public void setBit(byte[] data, short pos, short val) {
        short posByte = (short)(pos/8);
        short posBit = (short)(pos%8);
        byte oldByte = data[posByte];
        oldByte = (byte) ((((short)0xFF7F>>posBit) & oldByte) & 0x00FF);
        byte newByte = (byte) ((val<<(8-(posBit+1))) | oldByte);
        data[posByte] = newByte;
    }
    
    // right rotate the byte array with step bits
    public byte[] rotateRight(byte[] in, short len, short step) {
        //short numOfBytes = (short)((short)((short)(len-1)/8) + 1);
        //byte[] out = new byte[numOfBytes];
        for (short i=0; i<len; i++) {
            short val = getBit(in,(short)((short)(i-step+len)%len));
            //setBit(out,i,val);
            setBit(tempbuf,i,val);
        }
        return tempbuf;
    }
    
    
    public void permutation(short rounds) {
        short i;
        
        Util.arrayCopyNonAtomic(S, (short)0, x0, (short)0, (short)8);
        Util.arrayCopyNonAtomic(S, (short)8, x1, (short)0, (short)8);
        Util.arrayCopyNonAtomic(S, (short)16, x2, (short)0, (short)8);
        Util.arrayCopyNonAtomic(S, (short)24, x3, (short)0, (short)8);
        Util.arrayCopyNonAtomic(S, (short)32, x4, (short)0, (short)8);
        
        for (i = 0; i < rounds; ++i) {
            //ISOException.throwIt((byte)0x0008); //    230 ms (since start)
            // addition of round constant
            short tmp2 = (short)((short)((short)((short)(0xf) - i) << 4) | i);
            Util.arrayFillNonAtomic(t0, (short)0, (short)8, (byte)0);
            Util.setShort(t0, (short)6, tmp2);
            xor(x2, t0, x2);
            
            //ISOException.throwIt((byte)0x0009); //     5 ms
            // substitution layer
            xor(x0, x4, x0);  xor(x4, x3, x4);  xor(x2, x1, x2);
            Util.arrayCopyNonAtomic(x0, (short)0, t0, (short)0, (short)8);
            Util.arrayCopyNonAtomic(x1, (short)0, t1, (short)0, (short)8);
            Util.arrayCopyNonAtomic(x2, (short)0, t2, (short)0, (short)8);
            Util.arrayCopyNonAtomic(x3, (short)0, t3, (short)0, (short)8);
            Util.arrayCopyNonAtomic(x4, (short)0, t4, (short)0, (short)8);
            not(t0, t0); not(t1, t1); not(t2, t2); not(t3, t3); not(t4, t4);
            and(t0, x1, t0); and(t1, x2, t1); and(t2, x3, t2); and(t3, x4, t3); and(t4, x0, t4);
            xor(x0, t1, x0);  xor(x1, t2, x1);  xor(x2, t3, x2); xor(x3, t4, x3);  xor(x4, t0, x4);
            xor(x1, x0, x1);  xor(x0, x4, x0);  xor(x3, x2, x3); not(x2, x2);
            
            //ISOException.throwIt((byte)0x0010); //     53 ms
            // linear diffusion layer
            t0 = rotateRight(x0, (short)64, (short)19); t1 = rotateRight(x0, (short)64, (short)28); xor(t0, t1, t2); xor(x0, t2, x0);
            t0 = rotateRight(x1, (short)64, (short)61); t1 = rotateRight(x1, (short)64, (short)39); xor(t0, t1, t2); xor(x1, t2, x1);
            t0 = rotateRight(x2, (short)64, (short)1); t1 = rotateRight(x2, (short)64, (short)6); xor(t0, t1, t2); xor(x2, t2, x2);
            t0 = rotateRight(x3, (short)64, (short)10); t1 = rotateRight(x3, (short)64, (short)17); xor(t0, t1, t2); xor(x3, t2, x3);
            t0 = rotateRight(x4, (short)64, (short)7); t1 = rotateRight(x4, (short)64, (short)41); xor(t0, t1, t2); xor(x4, t2, x4);
            //ISOException.throwIt((byte)0x0011); //    135275 ms (Mistake:with new used for out in rotateRight); 982 ms (post optimisation)
        }
        Util.arrayCopyNonAtomic(x0, (short)0, S, (short)0, (short)8);
        Util.arrayCopyNonAtomic(x1, (short)0, S, (short)8, (short)8);
        Util.arrayCopyNonAtomic(x2, (short)0, S, (short)16, (short)8);
        Util.arrayCopyNonAtomic(x3, (short)0, S, (short)24, (short)8);
        Util.arrayCopyNonAtomic(x4, (short)0, S, (short)32, (short)8);
    }
    
    
    public short crypto_aead_encrypt(byte c[], short clen, byte m[], short mlen, byte ad[], short adlen,
                                     byte nsec[], byte npub[], byte k[]) {
        
        short klen = CRYPTO_KEYBYTES;
        //short size = (short)(320 / 8);
        short capacity = (short)((short)2 * klen);
        short rate = (short)(FORTY - capacity);
        short a = (short)12;
        short b = (klen == (short)16) ? (short)6 : (short)8;
        short s = (short)((short)(adlen / rate) + 1);
        short t = (short)((short)(mlen / rate) + 1);
        short l = (short)(mlen % rate);
        
        //byte S[] = new byte[size];
        byte A[] = JCSystem.makeTransientByteArray((short) (s * rate), JCSystem.CLEAR_ON_DESELECT);
        //new byte[(short) (s * rate)];
        byte M[] = JCSystem.makeTransientByteArray((short) (t * rate), JCSystem.CLEAR_ON_DESELECT);
        //new byte[(short) (t * rate)];
        short i, j;
        
        // pad associated data
        for (i = 0; i < adlen; ++i)
            A[i] = ad[i];
        A[adlen] = (byte) 0x80;
        for (i = (short)(adlen + 1); i < (short)(s * rate); ++i)
            A[i] = 0;
        // pad plashortext
        for (i = 0; i < mlen; ++i)
            M[i] = m[i];
        M[mlen] = (byte) 0x80;
        for (i = (short)(mlen + 1); i < (short)(t * rate); ++i)
            M[i] = 0;
        
        //ISOException.throwIt((byte)0x0001); //    211 ms (since start)
        // initialization
        S[0] = (byte) (klen * 8);
        S[1] = (byte) (rate * 8);
        S[2] = (byte) a;
        S[3] = (byte) b;
        for (i = 4; i < rate; ++i)
            S[i] = 0;
        for (i = 0; i < klen; ++i)
            S[(short)(rate + i)] = k[i];
        for (i = 0; i < klen; ++i)
            S[(short)(rate + klen + i)] = npub[i];
        
        //ISOException.throwIt((byte)0x0002); //    15 ms
        permutation(a);
        //ISOException.throwIt((byte)0x0003); //    ; 12574 ms (post optimisation)
        
        for (i = 0; i < klen; ++i)
            S[(short)(rate + klen + i)] ^= k[i];
        //ISOException.throwIt((byte)0x0004); //    8 ms (initialisation: 12597 ms)
        
        // process associated data
        if (adlen != 0) {
            for (i = 0; i < s; ++i) {
                for (j = 0; j < rate; ++j)
                    S[j] ^= A[(short)(i * rate + j)];
                permutation(b);
            }
        }
        S[(short)(FORTY - 1)] ^= 1;
        //ISOException.throwIt((byte)0x0005); //     ; 6289 ms (post optimisation)
        
        // process plaintext
        for (i = 0; i < (short) (t - 1); ++i) {
            for (j = 0; j < rate; ++j) {
                S[j] ^= M[(short)(i * rate + j)];
                c[(short)(i * rate + j)] = S[j];
            }
            permutation(b);     // permutation(b) takes 6290 ms per iteration
        }
        //ISOException.throwIt((byte)0x0006);  // 103972 ms
        for (j = 0; j < rate; ++j)
            S[j] ^= M[(short) ((short) (t - 1) * rate + j)];
        for (j = 0; j < l; ++j)
            c[(short) ((short) (t - 1) * rate + j)] = S[j];
        //ISOException.throwIt((byte)0x0007); //    ; 67 ms (plaintext-- post optimisation)
        
        // finalization & tag generation
        for (i = 0; i < klen; ++i)
            S[(short)(rate + i)] ^= k[i];
        permutation(a);
        for (i = 0; i < klen; ++i)
            S[(short)(rate + klen + i)] ^= k[i];
        // return tag
        for (i = 0; i < klen; ++i)
            c[(short)(mlen + i)] = S[(short)(rate + klen + i)];
        clen = (short)(mlen + klen);
        //ISOException.throwIt((byte)0x0008); //     ; 12404 ms (total: 135540 ms)
        return clen;
    }
    
    public short crypto_aead_decrypt(byte m[], short mlen, byte nsec[], byte c[], short clen, byte ad[],
                                     short adlen, byte npub[], byte k[]) {
        
        mlen = 0;
        if (clen < CRYPTO_KEYBYTES)
            return -1;
        
        short klen = CRYPTO_KEYBYTES;
        //short size = (short)(320 / 8);
        short capacity = (short)(2 * klen);
        short rate = (short)(FORTY - capacity);
        short a = (short) 12;
        short b = (klen == (short) 16) ? (short)6 : (short)8;
        short s = (short)((short)(adlen / rate) + 1);
        short t = (short)((short)((short)(clen - klen) / rate) + 1);
        short l = (short)((short)(clen - klen) % rate);
        
        //byte S[] = new byte[size];
        //byte A[] = new byte[(short) (s * rate)];
        byte A[] = JCSystem.makeTransientByteArray((short) (s * rate), JCSystem.CLEAR_ON_DESELECT);
        //byte M[] = new byte[(short) (t * rate)];
        byte M[] = JCSystem.makeTransientByteArray((short) (t * rate), JCSystem.CLEAR_ON_DESELECT);
        short i, j;
        
        // pad associated data
        for (i = 0; i < adlen; ++i)
            A[i] = ad[i];
        A[adlen] = (byte) 0x80;
        for (i = (short)(adlen + 1); i < (short) (s * rate); ++i)
            A[i] = 0;
        
        // initialization
        S[0] = (byte) (klen * 8);
        S[1] = (byte) (rate * 8);
        S[2] = (byte) a;
        S[3] = (byte) b;
        for (i = 4; i < rate; ++i)
            S[i] = 0;
        for (i = 0; i < klen; ++i)
            S[(short) (rate + i)] = k[i];
        for (i = 0; i < klen; ++i)
            S[(short) (rate + klen + i)] = npub[i];
        permutation(a);
        for (i = 0; i < klen; ++i)
            S[(short) (rate + klen + i)] ^= k[i];
        
        // process associated data
        if (adlen != 0) {
            for (i = 0; i < s; ++i) {
                for (j = 0; j < rate; ++j)
                    S[j] ^= A[(short) (i * rate + j)];
                permutation(b);
            }
        }
        S[(short) (FORTY - 1)] ^= 1;
        
        // process plaintext
        for (i = 0; i < (short)(t - 1); ++i) {
            for (j = 0; j < rate; ++j) {
                M[(short)(i * rate + j)] = (byte) (S[j] ^ c[(short)(i * rate + j)]);
                S[j] = c[(short)(i * rate + j)];
            }
            permutation(b);
        }
        for (j = 0; j < l; ++j)
            M[(short) ((short)(t - 1) * rate + j)] = (byte) (S[j] ^ c[(short) ((short)(t - 1) * rate + j)]);
        for (j = 0; j < l; ++j)
            S[j] = c[(short) ((short)(t - 1) * rate + j)];
        S[l] ^= 0x80;
        
        // finalization
        for (i = 0; i < klen; ++i)
            S[(short)(rate + i)] ^= k[i];
        permutation(a);
        for (i = 0; i < klen; ++i)
            S[(short)(rate + klen + i)] ^= k[i];
        
        // return -1 if verification fails
        for (i = 0; i < klen; ++i)
            if (c[(short)(clen - klen + i)] != S[(short)(rate + klen + i)])
                return -1;
        
        // return plaintext
        mlen = (short)(clen - klen);
        for (i = 0; i < mlen; ++i)
            m[i] = M[i];
        
        return mlen;
    }
}
