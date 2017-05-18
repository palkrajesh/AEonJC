//////////////////////////////SIMULATOR//////////////////////////////////////////////////
/*package host;

import applets.MorusApplet;                                                       //req for simulator 1
import java.util.Scanner;
import java.io.File;
import org.apache.commons.io.FileUtils;

//* @author Rajesh Kumar Pal
public class MorusMain {
    static CardMngr cardManager = new CardMngr();

    private static final byte APPLET_AID[] = {(byte) 0x4D, (byte) 0x4F, (byte) 0x52, (byte) 0x55, (byte) 0x53, (byte) 0x3A, (byte) 0x50, (byte) 0x4B, (byte) 0x47};
    
    private static final byte SELECT_PALAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x09, 
        (byte) 0x4D, (byte) 0x4F, (byte) 0x52, (byte) 0x55, (byte) 0x53, (byte) 0x3A, (byte) 0x50, (byte) 0x4B, (byte) 0x47};

    public static char toHexChar(int i) {
        if ((0 <= i) && (i <= 9)) {
            return (char) ('0' + i);
        } else {
            return (char) ('a' + (i - 10));
        }
    }
    
    public static String byteToHex(byte data) {
        StringBuilder buf = new StringBuilder();
        buf.append(toHexChar((data >>> 4) & 0x0F));
        buf.append(toHexChar(data & 0x0F));
        return buf.toString();
    }
    
    public static String bytesToHex(byte[] data) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            buf.append(byteToHex(data[i]));
            buf.append(" ");
            if((i+1)%16 == 0) buf.append("\n");
        }
        return (buf.toString());
    }
    
    public static void main(String[] args) {
        try {
            //get cardManager object
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, SELECT_PALAPPLET, MorusApplet.class); //req for simulator 2
            
            //timing parameters
            //double timeKeyGen=0;
            double timeEnc=0;
            double timeDec=0;
            double timePayload=0;
            long startTime=0, endTime=0, elapsedTime=0;
            byte[] response = new byte[256];
                                     
            //get user input
            int mode = 0;  //0:Encryption, 1:Decryption
            Scanner in = new Scanner(System.in);
            while(mode == 0 || mode == 1){
            System.out.println("Oncard Morus encryption/decryption on Smart card");
            System.out.println("Choose encryption (0) or decryption (1) or any key to exit:");
            mode = in.nextInt();
            if(mode != 0 && mode != 1) return;
            System.out.println("Enter the filename:");
            String filename = in.next();
            String outputFilename = filename + ".out";
            short payloadLengthEnc = 232;  //try optimizing by different payload size (16, 32, 64, 128, 240)
            short payloadLengthDec = 248;
            File inputFile = new File(filename);
            File outputFile = new File(outputFilename);
            if(outputFile.exists()) outputFile.delete();
            
            if(mode == 0){ //encryption
                //read file and prepare for encrypting
                System.out.println("Preparing data for encryption.");
                byte[] inputData = FileUtils.readFileToByteArray(inputFile);
                //number of APDU
                short numOperations = (short) (inputData.length / payloadLengthEnc);
                short lastPktLength = (short) (inputData.length % payloadLengthEnc);
                if(lastPktLength > 0) numOperations++;
            
                int padLength=0;
                for(short k=0; k<numOperations; k++){
                // Prepare APDU command for encryption
                if(lastPktLength > 0 && k == numOperations-1){
                    //process the last payload for encryption
                    padLength = 16 - (lastPktLength % 16); //padLength is equals to padValue
                    
                    byte apdu_enc1[] = new byte[CardMngr.HEADER_LENGTH + lastPktLength + padLength];
                    apdu_enc1[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                    apdu_enc1[CardMngr.OFFSET_INS] = (byte) 0x61; //encryption
                    apdu_enc1[CardMngr.OFFSET_P1] = (byte) 0x00; //00=CBC mode of operation
                    apdu_enc1[CardMngr.OFFSET_P2] = (byte) 0x00;
                    apdu_enc1[CardMngr.OFFSET_LC] = (byte) (lastPktLength + padLength);
                    for(short i=0; i<lastPktLength; i++)
                    apdu_enc1[CardMngr.OFFSET_DATA+i] = (byte) inputData[k*payloadLengthEnc+i];
                    for(short pp=0; pp<padLength; pp++)
                        apdu_enc1[CardMngr.OFFSET_DATA+lastPktLength+pp] = (byte) padLength;
                    startTime = System.nanoTime();
                    //responseAPDU = cardManager.sendAPDU(apdu_enc1);           //needed for real card
                    response = cardManager.sendAPDUSimulator(apdu_enc1);        //req for simulator 4
                    endTime = System.nanoTime();
                    elapsedTime = endTime - startTime; 
                    timePayload = elapsedTime / 1.0E06;
                    timeEnc = timeEnc + timePayload;
                    //System.out.println("Reached Here " + lastPktLength + " " + byteToHex((byte)padLength));
                    //response = responseAPDU.getBytes();                       //needed for real card
                    System.out.println("timeEnc: " + timeEnc + "msec");
                    byte[] encData = new byte[response.length-2];
                    System.arraycopy(response, 0, encData, 0, response.length-2);
                    //System.out.println("encData: "+ bytesToHex(encData));
                    FileUtils.writeByteArrayToFile(outputFile, encData, true);
                }
                else{
                    //packetize to send through APDU for encryption
                    byte apdu_enc[] = new byte[CardMngr.HEADER_LENGTH + payloadLengthEnc];
                    apdu_enc[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                    apdu_enc[CardMngr.OFFSET_INS] = (byte) 0x61; //encryption
                    apdu_enc[CardMngr.OFFSET_P1] = (byte) 0x00; //00=CBC mode of operation
                    apdu_enc[CardMngr.OFFSET_P2] = (byte) 0x00;
                    apdu_enc[CardMngr.OFFSET_LC] = (byte) payloadLengthEnc;
                    for(short i=0; i<payloadLengthEnc; i++)
                    apdu_enc[CardMngr.OFFSET_DATA+i] = (byte) inputData[k*payloadLengthEnc+i];
                    startTime = System.nanoTime();
                    //responseAPDU = cardManager.sendAPDU(apdu_enc);            //needed for real card
                    response = cardManager.sendAPDUSimulator(apdu_enc);         //req for simulator 5  
                    endTime = System.nanoTime();
                    elapsedTime = endTime - startTime; 
                    timePayload = elapsedTime / 1.0E06;
                    timeEnc = timeEnc + timePayload;
                    
                    //response = responseAPDU.getBytes();                       //needed for real card
                    byte[] encData = new byte[response.length - 2];
                    System.arraycopy(response, 0, encData, 0, response.length - 2);
                    FileUtils.writeByteArrayToFile(outputFile, encData, true);
                }
              }
                //System.out.println("timeKeyGen: " + timeKeyGen + "msec");
                System.out.println("Total timeEnc: " + timeEnc/1000 + "sec");
                System.out.println("Average timeEnc: " + timeEnc/numOperations + "msec\n");
            }
            else if(mode == 1){  //decryption
                //read file and prepare for decrypting
                System.out.println("Preparing data for decryption.");
                byte[] inputData = FileUtils.readFileToByteArray(inputFile);
                //System.out.println(" inputEnc: " + bytesToHex(inputData));
            
                //number of APDU
                short numOperations = (short) (inputData.length / payloadLengthDec);
                short lastPktLength = (short) (inputData.length % payloadLengthDec);
                if(lastPktLength > 0) numOperations++;
            
                for(short k=0; k<numOperations; k++){
                // Prepare APDU command for decryption
                if(lastPktLength > 0 && k == numOperations-1){
                    //process the last payload for encryption
                    byte apdu_dec1[] = new byte[CardMngr.HEADER_LENGTH + lastPktLength];
                    apdu_dec1[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                    apdu_dec1[CardMngr.OFFSET_INS] = (byte) 0x62; //decryption
                    apdu_dec1[CardMngr.OFFSET_P1] = (byte) 0x00; //00=CBC mode of operation
                    apdu_dec1[CardMngr.OFFSET_P2] = (byte) 0x00;
                    apdu_dec1[CardMngr.OFFSET_LC] = (byte) lastPktLength;
                    for(short i=0; i<lastPktLength; i++)
                    apdu_dec1[CardMngr.OFFSET_DATA+i] = (byte) inputData[k*payloadLengthDec+i];
                    startTime = System.nanoTime();
                    //responseAPDU = cardManager.sendAPDU(apdu_dec1);           //needed for real card
                    response = cardManager.sendAPDUSimulator(apdu_dec1);        //req for simulator 6
                    //System.out.println("response: " + bytesToHex(response));
                    endTime = System.nanoTime();
                    elapsedTime = endTime - startTime; 
                    timePayload = elapsedTime / 1.0E06;
                    timeDec = timeDec + timePayload;
                    
                    //response = responseAPDU.getBytes();                       //needed for real card
                    byte padValue = response[lastPktLength-16-1];    //remove 16 0s
                    //System.out.println("Reached Here " + lastPktLength + " " + byteToHex(padValue));
                    byte[] decData = new byte[lastPktLength-16-padValue];
                    System.arraycopy(response, 0, decData, 0, lastPktLength-16-padValue);
                    FileUtils.writeByteArrayToFile(outputFile, decData, true);
                }
                else{
                    //packetize to send through APDU for decryption
                    byte apdu_dec[] = new byte[CardMngr.HEADER_LENGTH + payloadLengthDec];
                    apdu_dec[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                    apdu_dec[CardMngr.OFFSET_INS] = (byte) 0x62; //decryption
                    apdu_dec[CardMngr.OFFSET_P1] = (byte) 0x00; //00=CBC mode of operation
                    apdu_dec[CardMngr.OFFSET_P2] = (byte) 0x00;
                    apdu_dec[CardMngr.OFFSET_LC] = (byte) payloadLengthDec;
                    for(short i=0; i<payloadLengthDec; i++)
                    apdu_dec[CardMngr.OFFSET_DATA+i] = (byte) inputData[k*payloadLengthDec+i];
                    startTime = System.nanoTime();
                    //responseAPDU = cardManager.sendAPDU(apdu_dec);              //needed for real card
                    response = cardManager.sendAPDUSimulator(apdu_dec);         //req for simulator 6
                    endTime = System.nanoTime();
                    elapsedTime = endTime - startTime; 
                    timePayload = elapsedTime / 1.0E06;
                    timeDec = timeDec + timePayload;
                    
                    //response = responseAPDU.getBytes();                       //needed for real card
                    byte[] decData = new byte[response.length - 2];
                    System.arraycopy(response, 0, decData, 0, response.length - 2);
                    FileUtils.writeByteArrayToFile(outputFile, decData, true);
                }
              }
                //System.out.println("timeKeyGen: " + timeKeyGen + "msec");
                System.out.println("Total timeDec: " + timeDec/1000 + "sec");
                System.out.println("Average timeDec: " + timeDec/numOperations + "msec\n");
            }  
            }  
                      
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
} */

///////////////////////////////////REAL CARD/////////////////////////////////////////////
package host;
//import applets.AezApplet;                                                       //req for simulator 1
import java.util.Scanner;
import javax.smartcardio.ResponseAPDU;
import java.io.File;
//import java.util.Base64;
import org.apache.commons.io.FileUtils;

// @author Rajesh Kumar Pal
public class MorusMain {
    static CardMngr cardManager = new CardMngr();

    private static final byte APPLET_AID[] = {(byte) 0x4D, (byte) 0x4F, (byte) 0x52, (byte) 0x55, (byte) 0x53, (byte) 0x3A, (byte) 0x50, (byte) 0x4B, (byte) 0x47};
    
    private static final byte SELECT_PALAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x09, 
        (byte) 0x4D, (byte) 0x4F, (byte) 0x52, (byte) 0x55, (byte) 0x53, (byte) 0x3A, (byte) 0x50, (byte) 0x4B, (byte) 0x47};

    public static char toHexChar(int i) {
        if ((0 <= i) && (i <= 9)) {
            return (char) ('0' + i);
        } else {
            return (char) ('a' + (i - 10));
        }
    }
    
    public static String byteToHex(byte data) {
        StringBuilder buf = new StringBuilder();
        buf.append(toHexChar((data >>> 4) & 0x0F));
        buf.append(toHexChar(data & 0x0F));
        return buf.toString();
    }
    
    public static String bytesToHex(byte[] data) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            buf.append(byteToHex(data[i]));
            buf.append(" ");
            if((i+1)%16 == 0) buf.append("\n");
        }
        return (buf.toString());
    }
    
    public static void main(String[] args) {
        try {
            //get cardManager object
            //cardManager.prepareLocalSimulatorApplet(APPLET_AID, SELECT_PALAPPLET, AezApplet.class); //req for simulator 2
            //Fun with REAL CARDS
            if (cardManager.ConnectToCard()) {                                //needed for real card
                
            // Select our application on card
            cardManager.sendAPDU(SELECT_PALAPPLET);                           //needed for real card
            
            //timing parameters
            //double timeKeyGen=0;
            double timeEnc=0;
            double timeDec=0;
            double timePayload=0;
            long startTime=0, endTime=0, elapsedTime=0;
            byte[] response = new byte[256];
            //ResponseAPDU responseAPDU = null;
                                     
            //get user input
            int mode = 0;  //0:Encryption, 1:Decryption
            Scanner in = new Scanner(System.in);
            while(mode == 0 || mode == 1){
            System.out.println("Oncard Morus encryption/decryption on Smart card");
            System.out.println("Choose encryption (0) or decryption (1) or any key to exit:");
            mode = in.nextInt();
            if(mode != 0 && mode != 1) return;
            System.out.println("Enter the filename:");
            String filename = in.next();
            String outputFilename = filename + ".out";
            short payloadLengthEnc = 232;  //try optimizing by different payload size (16, 32, 64, 128, 240)
            short payloadLengthDec = 248;
            File inputFile = new File(filename);
            File outputFile = new File(outputFilename);
            if(outputFile.exists()) outputFile.delete();
            
            
            if(mode == 0){ //encryption
                //read file and prepare for encrypting
                System.out.println("Preparing data for encryption.");
                byte[] inputData = FileUtils.readFileToByteArray(inputFile);
                //number of APDU
                short numOperations = (short) (inputData.length / payloadLengthEnc);
                short lastPktLength = (short) (inputData.length % payloadLengthEnc);
                if(lastPktLength > 0) numOperations++;
            
                int padLength=0;
                for(short k=0; k<numOperations; k++){
                // Prepare APDU command for encryption
                if(lastPktLength > 0 && k == numOperations-1){
                    //process the last payload for encryption
                    padLength = 16 - (lastPktLength % 16); //padLength is equals to padValue
                    
                    byte apdu_enc1[] = new byte[CardMngr.HEADER_LENGTH + lastPktLength + padLength];
                    apdu_enc1[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                    apdu_enc1[CardMngr.OFFSET_INS] = (byte) 0x61; //encryption
                    apdu_enc1[CardMngr.OFFSET_P1] = (byte) 0x00; //00=CBC mode of operation
                    apdu_enc1[CardMngr.OFFSET_P2] = (byte) 0x00;
                    apdu_enc1[CardMngr.OFFSET_LC] = (byte) (lastPktLength + padLength);
                    for(short i=0; i<lastPktLength; i++)
                    apdu_enc1[CardMngr.OFFSET_DATA+i] = (byte) inputData[k*payloadLengthEnc+i];
                    for(short pp=0; pp<padLength; pp++)
                        apdu_enc1[CardMngr.OFFSET_DATA+lastPktLength+pp] = (byte) padLength;
                    startTime = System.nanoTime();
                    ResponseAPDU responseAPDU = cardManager.sendAPDU(apdu_enc1);           //needed for real card
                    //response = cardManager.sendAPDUSimulator(apdu_enc1);        //req for simulator 4
                    endTime = System.nanoTime();
                    elapsedTime = endTime - startTime; 
                    timePayload = elapsedTime / 1.0E06;
                    timeEnc = timeEnc + timePayload;
                    
                    response = responseAPDU.getBytes();                       //needed for real card
                    System.out.println("timeEnc: " + timeEnc + "msec");
                    byte[] encData = new byte[response.length-2];
                    System.arraycopy(response, 0, encData, 0, response.length-2);
                    //System.out.println("encData: "+ bytesToHex(encData));
                    FileUtils.writeByteArrayToFile(outputFile, encData, true);
                }
                else{
                    //packetize to send through APDU for encryption
                    byte apdu_enc[] = new byte[CardMngr.HEADER_LENGTH + payloadLengthEnc];
                    apdu_enc[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                    apdu_enc[CardMngr.OFFSET_INS] = (byte) 0x61; //encryption
                    apdu_enc[CardMngr.OFFSET_P1] = (byte) 0x00; //00=CBC mode of operation
                    apdu_enc[CardMngr.OFFSET_P2] = (byte) 0x00;
                    apdu_enc[CardMngr.OFFSET_LC] = (byte) payloadLengthEnc;
                    for(short i=0; i<payloadLengthEnc; i++)
                    apdu_enc[CardMngr.OFFSET_DATA+i] = (byte) inputData[k*payloadLengthEnc+i];
                    startTime = System.nanoTime();
                    ResponseAPDU responseAPDU = cardManager.sendAPDU(apdu_enc);            //needed for real card
                    //response = cardManager.sendAPDUSimulator(apdu_enc);         //req for simulator 5  
                    endTime = System.nanoTime();
                    elapsedTime = endTime - startTime; 
                    timePayload = elapsedTime / 1.0E06;
                    timeEnc = timeEnc + timePayload;
                    
                    response = responseAPDU.getBytes();                       //needed for real card
                    byte[] encData = new byte[response.length - 2];
                    System.arraycopy(response, 0, encData, 0, response.length - 2);
                    FileUtils.writeByteArrayToFile(outputFile, encData, true);
                }
              }
                //System.out.println("timeKeyGen: " + timeKeyGen + "msec");
                System.out.println("Total timeEnc: " + timeEnc/1000 + "sec");
                System.out.println("Average timeEnc: " + timeEnc/numOperations + "msec\n");
            }
            else if(mode == 1){  //decryption
                //read file and prepare for decrypting
                System.out.println("Preparing data for decryption.");
                byte[] inputData = FileUtils.readFileToByteArray(inputFile);
                //System.out.println(" inputEnc: " + bytesToHex(inputData));
            
                //number of APDU
                short numOperations = (short) (inputData.length / payloadLengthDec);
                short lastPktLength = (short) (inputData.length % payloadLengthDec);
                if(lastPktLength > 0) numOperations++;
            
                for(short k=0; k<numOperations; k++){
                // Prepare APDU command for encryption
                if(lastPktLength > 0 && k == numOperations-1){
                    //process the last payload for encryption
                    byte apdu_dec1[] = new byte[CardMngr.HEADER_LENGTH + lastPktLength];
                    apdu_dec1[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                    apdu_dec1[CardMngr.OFFSET_INS] = (byte) 0x62; //decryption
                    apdu_dec1[CardMngr.OFFSET_P1] = (byte) 0x00; //00=CBC mode of operation
                    apdu_dec1[CardMngr.OFFSET_P2] = (byte) 0x00;
                    apdu_dec1[CardMngr.OFFSET_LC] = (byte) lastPktLength;
                    for(short i=0; i<lastPktLength; i++)
                    apdu_dec1[CardMngr.OFFSET_DATA+i] = (byte) inputData[k*payloadLengthDec+i];
                    startTime = System.nanoTime();
                    ResponseAPDU responseAPDU = cardManager.sendAPDU(apdu_dec1);           //needed for real card
                    //response = cardManager.sendAPDUSimulator(apdu_dec1);        //req for simulator 6
                    endTime = System.nanoTime();
                    elapsedTime = endTime - startTime; 
                    timePayload = elapsedTime / 1.0E06;
                    timeDec = timeDec + timePayload;
                    
                    response = responseAPDU.getBytes();                       //needed for real card
                    byte padValue = response[lastPktLength-16-1];    //remove 16 0s
                    byte[] decData = new byte[lastPktLength-16-padValue];
                    System.arraycopy(response, 0, decData, 0, lastPktLength-16-padValue);
                    FileUtils.writeByteArrayToFile(outputFile, decData, true);
                }
                else{
                    //packetize to send through APDU for decryption
                    byte apdu_dec[] = new byte[CardMngr.HEADER_LENGTH + payloadLengthDec];
                    apdu_dec[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                    apdu_dec[CardMngr.OFFSET_INS] = (byte) 0x62; //decryption
                    apdu_dec[CardMngr.OFFSET_P1] = (byte) 0x00; //00=CBC mode of operation
                    apdu_dec[CardMngr.OFFSET_P2] = (byte) 0x00;
                    apdu_dec[CardMngr.OFFSET_LC] = (byte) payloadLengthDec;
                    for(short i=0; i<payloadLengthDec; i++)
                    apdu_dec[CardMngr.OFFSET_DATA+i] = (byte) inputData[k*payloadLengthDec+i];
                    startTime = System.nanoTime();
                    ResponseAPDU responseAPDU = cardManager.sendAPDU(apdu_dec);              //needed for real card
                    //response = cardManager.sendAPDUSimulator(apdu_dec);         //req for simulator 6
                    endTime = System.nanoTime();
                    elapsedTime = endTime - startTime; 
                    timePayload = elapsedTime / 1.0E06;
                    timeDec = timeDec + timePayload;
                    
                    response = responseAPDU.getBytes();                       //needed for real card
                    byte[] decData = new byte[response.length - 2];
                    System.arraycopy(response, 0, decData, 0, response.length - 2);
                    FileUtils.writeByteArrayToFile(outputFile, decData, true);
                }
              }
                //System.out.println("timeKeyGen: " + timeKeyGen + "msec");
                System.out.println("Total timeDec: " + timeDec/1000 + "sec");
                System.out.println("Average timeDec: " + timeDec/numOperations + "msec\n");
            }  
            }  
                   
            System.out.println("Exiting...");             //needed for real card
            cardManager.DisconnectFromCard();             //needed for real card
            
            } else {                                      //needed for real card
                System.out.println("Failed to connect to card");  //needed for real card
            }                                             //needed for real card
            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
} 
