package com.client;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.Key;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.json.JSONException;
import org.json.JSONObject;

import com.sun.org.apache.bcel.internal.classfile.InnerClass;

import jdk.internal.org.objectweb.asm.tree.IntInsnNode;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Client {
	private static Socket soc;
	 static DataInputStream dis;
	 static DataOutputStream dos;
	static ArrayList<Character> demouse;
	 //static String output;
	static int count=0;
	static Key secretKey;
	static byte[] original;
	static String status;
	static InitClass initclass;
	
	public static void main(String[] args) {
		
		try {
			 soc=new Socket("192.168.0.145",5056);
		} catch (IOException e) {
			System.out.println("Unable to connect the server");
		
			System.exit(1);
		}do {
			handleClient();
		}while(true);
		
	}
	
	private static void handleClient() {
		try {
			
			 // obtaining input and out streams 
          
		
				dis = new DataInputStream(soc.getInputStream());
			
             dos = new DataOutputStream(soc.getOutputStream());
            
            //performs the exchange of information between client and client handler
            
            //read a json
            
            JSONObject jsonObj=new JSONObject();
             if(initclass==null) {
           
            initclass=new InitClass();
            try {
				jsonObj.put("status", "connect");
				 
			} catch (JSONException e) {
				
				e.printStackTrace();
			}
            }
             else {
            	 if(initclass.statusCipher) {
            		 //////// result found
            		 try {
          				jsonObj.put("status", "success");
          				JSONObject jsonInner=new JSONObject();
          				jsonInner.put("key", initclass.key);
          				jsonInner.put("output", initclass.output);
          				jsonInner.put("threadkey",initclass.threadStatus);
          				
          			} catch (JSONException e) {
          				
          				e.printStackTrace();
          			} 
            		 initclass.statusCipher=false;
            	 }
            	 else {
            		 //result not found
            		 try {
         				jsonObj.put("status", "reconnect");
         				JSONObject threadIden=new JSONObject();
         				threadIden.put("threadkey",initclass.threadStatus);
         				
         			} catch (JSONException e) {
         				
         				e.printStackTrace();
         			}
            		 }
            	 }
             dos.writeUTF(jsonObj.toString());

            String tosend = dis.readUTF();
            try {
				JSONObject jobj=new JSONObject(tosend);
				String cipherText=String.valueOf(jobj.get("CipherText"));
				String algo=String.valueOf(jobj.get("algo"));
				String padding=String.valueOf(jobj.get("padding"));
				String blockName=String.valueOf(jobj.get("block"));
				String startk=String.valueOf(jobj.get("StartKey"));
				int identifyThread=jobj.getInt("threadkey");
				double start=Integer.parseInt(startk);
				//Integer chunk=Integer.valueOf((String) jobj.get("chunkSize"));
				String keybit=String.valueOf(jobj.get("chunkSize"));
				double ke=Integer.parseInt(keybit);
				int keySizeBits=Integer.valueOf(String.valueOf(jobj.get("keySize")));
				//double allottedBlockNumber=Double.valueOf((String) jobj.get("StartKey"));
				//double distributionBlockSiz=Double.valueOf( (String) jobj.get("chunkSize"));
				String keySpace=String.valueOf(jobj.get("keySpace"));
				System.out.println("print jobject : =----"+jobj.toString());
				
				Client.keygenerator(start,ke,keySpace,algo,padding,blockName,keySizeBits,cipherText,identifyThread);
				
				
			} catch (JSONException e) {
				
				e.printStackTrace();
				
			}
		} catch (IOException e1) {
			try {
				dis.close();
				dos.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			e1.printStackTrace();
		} 
            ////////////////////////////////////////////////////
            
            /////////////////////////////////////////
          
            
		
	}
 public static void keygenerator(double start,double ke, String keySpace, String algo, String padding, String blockName, int keySizeBits, String cipherText,int identifyThread) {
	 //keyspace, how many no of possible make there

	 char[] set2 = keySpace.toCharArray();
		demouse=new ArrayList<Character>();
	for(char ch:set2) {		
		demouse.add(ch);
		}
	
	ArrayList<Integer> roundsArr=new ArrayList<Integer>();
	
	double data=start*ke+1;
	double point=data;//eeddecea
	System.out.println("point---------------->>>>"+point);
	//length
	for(int a=(keySizeBits/8)-1;a>=0;a--) {
		if(Math.pow(set2.length,a)>point) {
			//System.out.println("--------->"+Math.pow(set2.length,a)+","+point+",    "+a);
			roundsArr.add(0);
		}
		else {		
		//	System.out.println("else--------->"+Math.pow(set2.length,a)+","+point+",   "+a);
			Double aRound=  point/Math.pow(set2.length,a);
			point=point%Math.pow(set2.length,a) ;
			roundsArr.add(aRound.intValue());
		} 
		
	 
	 
 }
	System.out.println(roundsArr);
	StringBuilder sb=new StringBuilder();
	 for(int a:roundsArr) {
		sb.append( demouse.get(a));	 
	 }
 System.out.println("----->"+sb.toString()+"\n");

 //thP.printAllKLength(set2,k);
 String output=sb.toString();
 //key*chuncksize

 System.out.println("while ---->"+ke);
 //String result=null;
  count=0;
 while(count<ke) {
	 System.out.println("while ----> true ");

      output=Client.dotask(output.toCharArray());
      if(output==null) {
    	  break;
      }
    System.out.println("---->generated key: "+output);
 String  result= decrypt(cipherText,output,algo,padding,blockName);
   System.out.println("resuylt------------>>>"+result);
   if(result!=null) {
	   initclass.statusCipher=true;
	   initclass.key=output;
	   initclass.output=result;
	   break;
   }
   ////////////////////////////////////////
  
   //////////////////////////////////////////////
			
			try {  Thread.sleep(5000); 
			} 
			 catch (InterruptedException e) {
			
			e.printStackTrace(); }
			 
}
 
 
//////////////////////////////////////////////////////

 System.out.println("--------------------->>end");

	 
 } 
 

//////////////////////////////////////////////////////////
private static String dotask(char[] charArray ) {
	//	 System.out.println("-------------start "+charArray[0]+","+charArray[1]+","+charArray[2]);
		String temp;
	if(charArray[charArray.length-1]==demouse.get(demouse.size()-1))
	{
		char[]  charArr=new char[charArray.length-1];
		for(int a=0;a<charArr.length;a++) {
			charArr[a]=charArray[a];
		}
		//charArr[charArr.length-1]=demouse.indexOf(charArr[charArr.length-1])
		String newTemp=String.valueOf(demouse.get(0));
		  temp=dotaskInner(charArr,newTemp);
		count++; 
		
        //String result=temp+ " "+count;
		//return result;
		System.out.println("\n---------end f-:"+temp+"  count::"+count);
		 
		// dotask(temp.toCharArray());
	} 
	else {
		charArray[charArray.length-1]=demouse.get(demouse.indexOf(charArray[charArray.length-1])+1);
		count++;
		 System.out.println("---------end  -:"+new String(charArray)+"  count::"+count);
		temp= new String(charArray);
		//return temp;
				
	}
	return temp;	
	
	}


///////////////////////////////////////////////////////////

private static String dotaskInner(char[] subArr, String substr) {
 	try {
	if(subArr[subArr.length-1]==demouse.get(demouse.size()-1)) {
 		char[]  charArr=new char[subArr.length-1];
		for(int a=0;a<charArr.length;a++) {
			charArr[a]=subArr[a];
		}
	 	String newTemp=substr+String.valueOf(demouse.get(0));
		String ret =dotaskInner(charArr,newTemp);
		return ret;
	}else {
	 	subArr[subArr.length-1]=demouse.get(demouse.indexOf(subArr[subArr.length-1])+1);
	 	return ""+new String(subArr)+substr;
	}
	}catch (Exception e) {
		
		return null;
	}
	
}


	
	public static String decrypt(String encrypted, String generatedKey, String algo, String padding, String blockName) {
		try {
		System.out.println("enc text:>> "+encrypted);
			//SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
			 DESKeySpec dks = new DESKeySpec(generatedKey.getBytes());
			   SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
		        Key secretKey = keyFactory.generateSecret(dks);
			 
			//SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "DES");
		        String format=algo+ "/" +blockName+"/"+padding;
			Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));

			return new String(original);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		//SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "DES");
		      
		 

		return null;
		}
	
	private static class InitClass{
		Boolean statusCipher=false;
		String key;
		String output;
		int threadStatus;
	} 
	
	
}

