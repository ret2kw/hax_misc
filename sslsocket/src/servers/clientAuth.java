package servers;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.CertificateException;
import org.apache.commons.io.FileUtils;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.net.ssl.*;




public class clientAuth {

    //http://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/JSSERefGuide.html#X509TrustManager
	public static class MyX509TrustManager implements X509TrustManager {

	     /*
	      * The default PKIX X509TrustManager.  We'll delegate
	      * decisions to it, and fall back to the logic in this class if the
	      * default X509TrustManager doesn't trust it.
	      */
	    	X509TrustManager pkixTrustManager;
	    	//reading in a PEM cert from filesystem
			FileInputStream is = null;
			CertificateFactory certFactory = null;
			X509Certificate cert = null;
			
			File clientCert = new File("/root/mycerts/cert.pem");
			
			private byte[] getFingerprint()
			{
			try {
				is = new FileInputStream(clientCert);
				certFactory = CertificateFactory.getInstance("X.509");
				cert = (X509Certificate)certFactory.generateCertificate(is);

			    //System.out.println(cert.toString());
			    
			    MessageDigest md = MessageDigest.getInstance("SHA1");
			    md.reset();
			    byte[] fingerPrint = md.digest(cert.getEncoded());
			    
			    //System.out.println(fingerPrint);
			    
			    return fingerPrint;
			
			}catch (Exception e) {
		         System.err.println(e.toString());
		         return null;
		      }
			}
			
			
			private void checkFingerprint(X509Certificate[] chain) throws CertificateException
			{
				boolean found = false;
				byte[] fingerPrint = null;
				byte[] allowedFinger = getFingerprint();
				X509Certificate cert = chain[0];
				
				System.out.println("[*] Recieved Client Cert from: " + cert.getSubjectDN());
				
				MessageDigest md;
				try {
					md = MessageDigest.getInstance("SHA1");
				    md.reset();
				    fingerPrint = md.digest(cert.getEncoded());
				    
				} catch (Exception e) {
					e.printStackTrace();
				}
				    //see if the cert fingerprints match
				    if (Arrays.equals(fingerPrint, allowedFinger))
				    {
				    	System.out.println("[*] Fingerprints matched!!!!!");
				    } else {
				    	throw new CertificateException("[*] Certificate with unknown fingerprint: " + cert.getSubjectDN());
				    	
				    }
			}

	     MyX509TrustManager() throws Exception {
	         // create a "default" JSSE X509TrustManager so we can call it for stuff we don't implement

	    	 //create an emtpy keystore since we aren't really using it
	         KeyStore ks = KeyStore.getInstance("JKS");
	         ks.load(null, null);

	         //create the TrustManagerFactory for doing PKIX, again, only doing this so we can call things we don't implement
	         TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
	         tmf.init(ks);

	         TrustManager tms [] = tmf.getTrustManagers();

	         /*
	          * Iterate over the returned trustmanagers, look
	          * for an instance of X509TrustManager.  If found,
	          * use that as our "default" trust manager.
	          */
	         for (int i = 0; i < tms.length; i++) {
	             if (tms[i] instanceof X509TrustManager) {
	                 pkixTrustManager = (X509TrustManager) tms[i];
	                 return;
	             }
	         }

	         /*
	          * Find some other way to initialize, or else we have to fail the
	          * constructor.
	          */
	         throw new Exception("[*] Couldn't initialize");
	     }

	     //This is where we implement our custom certificate pinning logic
	     public void checkClientTrusted(X509Certificate[] chain, String authType)
	                 throws CertificateException {
	             checkFingerprint(chain);
	     }

	     //we aren't doing server side checking as we are the server, so just pass this through
	     public void checkServerTrusted(X509Certificate[] chain, String authType)
	                 throws CertificateException {
	    	 
	    	 pkixTrustManager.checkServerTrusted(chain, authType);
	     }

         //passing this through again	   
	     public X509Certificate[] getAcceptedIssuers() {
	         return pkixTrustManager.getAcceptedIssuers();
	     }
	}
	

	
	public static void main(String[] args) {
		
		
		//Create KeyStore and SSL Socket Server
		try {
			
			//password for keystore
			char ksPass[] = "password".toCharArray();
			//password for private key in keystore
			char privPass[] = "Testing123!".toCharArray();
			//path of my keystore
			String ksName = "/root/mycerts/keystore.jks";
			
			//create and load a keystore
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(ksName), ksPass);
			
			//create and init the KeyManager
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, privPass);
			
			//create our custom TrustManager for cert pinning
			TrustManager[] myTMs = new TrustManager [] {
                    new MyX509TrustManager() };
			
			SSLContext sc = SSLContext.getInstance("TLS");
			//initialize the SSLContext with the keymanager (server certs) and our custom Trustmanager for cert pinning
			sc.init(kmf.getKeyManagers(), myTMs, null);
			//setup the ssl socket server
			SSLServerSocketFactory ssf = sc.getServerSocketFactory();
			SSLServerSocket s = (SSLServerSocket) ssf.createServerSocket(443);
			//we require client certificates
			s.setNeedClientAuth(true);
			//accept a connection
			SSLSocket c = (SSLSocket) s.accept();
			
			
			//http://stackoverflow.com/questions/10687200/java-7-and-could-not-generate-dh-keypair
			//This is mainly a fix for working with openssl s_client
			c.setEnabledCipherSuites(new String[] {
			        "SSL_RSA_WITH_RC4_128_MD5",
			        "SSL_RSA_WITH_RC4_128_SHA",
			        "TLS_RSA_WITH_AES_128_CBC_SHA",
			        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
			        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
			        "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
			        "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
			        "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
			        });
			
			BufferedWriter w = new BufferedWriter(new OutputStreamWriter(c.getOutputStream()));
			
			String m = "[*] Authenticated your certificate, Welcome to the NCC Test SSL Socket Server";
		         w.write(m,0,m.length());
		         w.newLine();
		         w.flush();
		         
		    System.out.println("[*] Done serving, shutting down");
		
		//we hit this when the client does not present any certificates         
		}catch (SSLHandshakeException e) {
			
			System.out.println("[*] Failed checking client certificate shutting down");
		
		//we hit this when the certificate validation fails
		}catch (CertificateException e) {
			
			System.out.println("[*] Failed checking client certificate shutting down");
		         
		}catch (Exception e) {
	         System.err.println("Exception in socketcreation " + e.toString());
	      }	
		
	}

}
