package servers;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStreamWriter;
import java.net.SocketAddress;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import javax.xml.bind.DatatypeConverter;



public class clientAuth {

	static X509TrustManager pkixTrustManager = null;
	static FileInputStream is = null;
	static CertificateFactory certFactory = null;
	static X509Certificate cert = null;
	//read in the client certificate we are matching against
	static File clientCert = new File("/root/mycerts/cert.pem");

	public static void main(String[] args) 
	{
		//Create KeyStore and SSL Socket Server
		try {
			
			//password for keystore
			char keyPass[] = "password".toCharArray();
			//password for private key in keystore
			char privPass[] = "Testing123!".toCharArray();
			//path of my keystore
			String keyPath = "/root/mycerts/keystore.jks";
			
			//create and load a keystore
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(keyPath), keyPass);
			
			//create and init the KeyManager
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, privPass);
			
			//create our custom TrustManager for cert pinning
			TrustManager[] fpm = new TrustManager [] {
					new FingerprintManager() };
			
			//explicitly specifying the securerandom to pass into the SSLContext
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			
			SSLContext sc = SSLContext.getInstance("TLS");
			//initialize the SSLContext with the keymanager (server certs) and our custom Trustmanager for cert pinning
			sc.init(kmf.getKeyManagers(), fpm, secureRandom);
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
			
			SocketAddress remoteAddr = c.getRemoteSocketAddress();
			System.out.println("[*] Recieved connection from: " + remoteAddr.toString().substring(1));
			
			BufferedWriter w = new BufferedWriter(new OutputStreamWriter(c.getOutputStream()));
			String m = "[*] Authenticated your certificate, Welcome to the NCC Test SSL Socket Server";
			w.write(m,0,m.length());
			w.newLine();
			w.flush();
		    
			c.close();
			System.out.println("[*] Done serving, shutting down");
				
		//we hit this when the certificate validation fails
		}catch (SSLHandshakeException e) 
		{	
			Exception cause = (Exception) e.getCause();
			
			if (cause instanceof CertificateException)
			{
				System.out.println("[*] Failed Auth, " + cause.getMessage());
			}else 
			{
				System.out.println("[*] Failed Auth, client did not present any certificate");
			}
		         
		}catch (Exception e) 
		{		
			System.err.println("[*] Exception in socketcreation " + e.toString());
		}	
	}
	
	
	private static byte[] getFingerprint()
	{
		try {
			is = new FileInputStream(clientCert);
			certFactory = CertificateFactory.getInstance("X.509");
			cert = (X509Certificate)certFactory.generateCertificate(is);

			//System.out.println(cert.toString());
	    
			//create our SHA256
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.reset();
			byte[] fingerPrint = md.digest(cert.getEncoded());
	    
			//System.out.println(fingerPrint);
	    
			return fingerPrint;
	
		}catch (Exception e) {
			System.err.println(e.toString());
			return null;
      }
	}
	
	private static boolean checkFingerprint(X509Certificate[] chain) throws CertificateException
	{
		byte[] fingerPrint = null;
		byte[] allowedFinger = getFingerprint();
		X509Certificate cert = chain[0];
		
		System.out.println("[*] Recieved Client Cert from: " + cert.getSubjectDN());
		
		MessageDigest md = null;

		try 
		{
			md = MessageDigest.getInstance("SHA-256");
		}catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		fingerPrint = md.digest(cert.getEncoded());
		md.reset();
	    
		System.out.println("[*] Client Certificate Fingerprint:\t" + DatatypeConverter.printHexBinary(fingerPrint));
		System.out.println("[*] Allowed Certificate Fingerprint:\t" + DatatypeConverter.printHexBinary(allowedFinger));
		    
		//see if the cert fingerprints match
		if (md.isEqual(fingerPrint, allowedFinger))
		{
			System.out.println("[*] Fingerprints matched!!!!!");
			return true;	
		}else 
		{
			throw new CertificateException("client certificate with unknown fingerprint: " + cert.getSubjectDN());
		}
	}
	
	//http://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/JSSERefGuide.html#X509TrustManager
	public static class FingerprintManager implements X509TrustManager {
		
		private FingerprintManager() throws Exception {
			// create a "default" JSSE X509TrustManager so we can call it for stuff we don't implement

	    	//create an empty keystore since we aren't really using it
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
	        for (int i = 0; i < tms.length; i++)
	        {
	        	if (tms[i] instanceof X509TrustManager) 
	        	{
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
				throws CertificateException 
		{
			checkFingerprint(chain); 
		}

	    //we aren't doing server side checking as we are the server, so just pass this through
	    public void checkServerTrusted(X509Certificate[] chain, String authType)
	    		throws CertificateException 
	    {
	    	pkixTrustManager.checkServerTrusted(chain, authType);
	    }

	    //passing this through again	   
	    public X509Certificate[] getAcceptedIssuers() {
	    	return pkixTrustManager.getAcceptedIssuers();
	    }
	}
}
