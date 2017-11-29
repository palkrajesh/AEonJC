/*
 * PACKAGEID: 41 45 47 49 53 3A  // AEGIS:
 * APPLETID: 41 45 47 49 53 3A 50 04 47   // AEGIS:PKG
 */
package aegis;

import javacard.framework.*;

/**
 *
 * @author rajesh
 */
public class AegisApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET               = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_AEGISENCRYPTION              = (byte) 0x61;
    final static byte INS_AEGISDECRYPTION              = (byte) 0x62;

    final static short ARRAY_LENGTH                  = (short) 0xff;
    final static byte  AES_BLOCK_LENGTH              = (short) 0x16;

    final static short SW_BAD_TEST_DATA_LEN          = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD             = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD     = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE       = (short) 0x6711;
    final static short SW_BAD_PIN                    = (short) 0x6900;

    private   OwnerPIN   m_pin = null;
    private   AegisCore  myaegis = null;           //AEGIS engine
    
    //AEGIS Parameters-- Encryption
     byte[] AD = {(byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02};
     short ADLEN = (short)AD.length;
     byte[] NSEC = {(byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01};
     byte[] NPUB = {(byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02};
     byte[] KEY = {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06};
     short KEYLEN = (short)KEY.length;
     
     /*AEGIS Parameters-- Decryption
     byte[] AD1 = {(byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02};
     short ADLEN1 = (short)AD1.length;
     byte[] NSEC1 = {(byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01};
     byte[] NPUB1 = {(byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02};
     byte[] KEY1 = {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06};
     short KEYLEN1 = (short)KEY1.length;*/
     
    // TEMPORARRY ARRAY IN RAM
    private byte m_ramArrayPt[] = null;
    private byte m_ramArrayCt[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private byte m_dataArray[] = null;

    /**
     * AegisApplet constructor
     * Only this class's install method should create the applet object.
     */
    protected AegisApplet(byte[] buffer, short offset, byte length)
    {
	
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {
            // Install parameter detail. Compliant with OP 2.0.1.

            // | size | content
            // |------|---------------------------
            // |  1   | [AID_Length]
            // | 5-16 | [AID_Bytes]
            // |  1   | [Privilege_Length]
            // | 1-n  | [Privilege_Bytes] (normally 1Byte)
            // |  1   | [Application_Proprietary_Length]
            // | 0-m  | [Application_Proprietary_Bytes]

            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);

           // go to proprietary data
            dataOffset++;

            // PERSISTENT BUFFER IN EEPROM
            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);
            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArrayPt = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);
            m_ramArrayCt = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

            //Create ASCON OBJECT
            myaegis = new AegisCore();
            
            m_pin = new OwnerPIN((byte) 5, (byte) 4);
            m_pin.update(m_dataArray, (byte) 0, (byte) 4);

            // update flag
            isOP2 = true;

        } else {
           // ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH + length));
          }

            // <PUT YOUR CREATION ACTION HERE>
            // register this instance
            register();
    }

    /**
     * Method installing the applet.
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        // applet  instance creation
        new AegisApplet(bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
        // <PUT YOUR SELECTION ACTION HERE>
        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {
        // <PUT YOUR DESELECTION ACTION HERE>
        return;
    }

    /**
     * Method processing an incoming APDU.
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException
    {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();
        
        // ignore the applet select command dispatched to the process
        if (selectingApplet())
            return;

        // APDU instruction parser
        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
            switch ( apduBuffer[ISO7816.OFFSET_INS] )
            {
                case INS_AEGISENCRYPTION: AEGISEncryption(apdu); break;
                case INS_AEGISDECRYPTION: AEGISDecryption(apdu); break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;

            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    
    public void AEGISEncryption(APDU apdu){
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        
        // Copy message to m_ramArrayPt for encryption
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_ramArrayPt, (short)0, dataLen);
        
	//ISOException.throwIt((short) 0x6060); 
        myaegis.AegisCoreInitialization(m_ramArrayCt, (short)0, m_ramArrayPt, dataLen, AD, ADLEN, NSEC, NPUB, KEY, KEYLEN);
	ISOException.throwIt((short) 0x6061); 
        
        // AEGIS Encryption
        myaegis.crypto_aead_encrypt();
        
        // Copy ciphertext
        Util.arrayCopyNonAtomic(m_ramArrayCt, (short)0, apdubuf, (short)0, (short)(dataLen+16));
        
        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend((short)0, (short)(dataLen+16));
    }

    
    public void AEGISDecryption(APDU apdu){
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        
        // Copy cipher to m_ramArrayCt for decryption
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_ramArrayCt, (short)0, dataLen);
        
        //myaegis.AegisCoreInitialization(m_ramArrayCt, dataLen, m_ramArrayPt, (short)0, AD1, ADLEN1, NSEC1, NPUB1, KEY1, KEYLEN1);
        myaegis.AegisCoreInitialization(m_ramArrayCt, dataLen, m_ramArrayPt, (short)0, AD, ADLEN, NSEC, NPUB, KEY, KEYLEN);
        // AEGIS Decryption
        myaegis.crypto_aead_decrypt();
        
        // Copy retrieved message (plaintext)
        Util.arrayCopyNonAtomic(m_ramArrayPt, (short)0, apdubuf, (short)0, (short)(dataLen-16));
        
        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend((short)0, (short)(dataLen-16));
    }
}
