package implementation;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.RSAKey;
import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;
import x509.v3.GuiV3;

public class MyCode extends CodeV3 {
	
	private KeyStore keyStore;
	private String myPassword = "lozinka";
	private SubjectPublicKeyInfo toBeSignedPUInfo = null;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
		try {
			keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(null, null);
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	@SuppressWarnings("deprecation")
	@Override
	public boolean canSign(String arg0) {
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(arg0);
			if(cert.getIssuerDN().getName().equals("")) return false; //sertifikat nije potpisan
			if(cert.getExtensionValue(X509Extensions.BasicConstraints.toString()) == null) return false;
			if(keyStore.isCertificateEntry(arg0)) return false;
			PublicKey key = cert.getPublicKey();
			cert.verify(key);   //proverava da li je self-signed
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	@Override
	public boolean exportCSR(String arg0, String arg1, String arg2) {
		try {
			X500NameBuilder nameBuilder = new X500NameBuilder();
			nameBuilder.addRDN(new ASN1ObjectIdentifier("2.5.4.6"), access.getSubjectCountry());
			nameBuilder.addRDN(new ASN1ObjectIdentifier("2.5.4.8"), access.getSubjectState());
			nameBuilder.addRDN(new ASN1ObjectIdentifier("2.5.4.7"), access.getSubjectLocality());
			nameBuilder.addRDN(new ASN1ObjectIdentifier("2.5.4.10"), access.getSubjectOrganization());
			nameBuilder.addRDN(new ASN1ObjectIdentifier("2.5.4.11"), access.getSubjectOrganizationUnit());
			nameBuilder.addRDN(new ASN1ObjectIdentifier("2.5.4.3"), access.getSubjectCommonName());
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(arg1);
			//nameBuilder.addRDN(new ASN1ObjectIdentifier(cert.getSigAlgOID()), cert.getSigAlgName());
			X500Name subject = nameBuilder.build();
			PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, cert.getPublicKey());
			//Add extensions
			ExtensionsGenerator extGen = new ExtensionsGenerator();
			Set<String> criticalOids = cert.getCriticalExtensionOIDs();
			Iterator<String> i = criticalOids.iterator();
			while(i.hasNext()) {
				String id = i.next();
				extGen.addExtension(new ASN1ObjectIdentifier(id), true, cert.getExtensionValue(id));
			}
			Set<String> nonCriticalOids = cert.getNonCriticalExtensionOIDs();
			i = nonCriticalOids.iterator();
			while(i.hasNext()) {
				String id = i.next();
				extGen.addExtension(new ASN1ObjectIdentifier(id), false, cert.getExtensionValue(id));
			}
			builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
			//Build the csr
			JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(arg2);
			ContentSigner signer = csBuilder.build((PrivateKey)keyStore.getKey(arg1, myPassword.toCharArray()));
			PKCS10CertificationRequest csr = builder.build(signer);
			File outFile = new File(arg0);
			if(!outFile.exists()) outFile.createNewFile();
			FileOutputStream out = new FileOutputStream(outFile);
			out.write(csr.getEncoded());
			out.close();
			return true;
		} catch (Exception e) {
			GuiV3.reportError(e);
		}
		return false;
	}

	@Override
	public boolean exportCertificate(String arg0, String arg1, int arg2, int arg3) {
		try {
			 if(!keyStore.containsAlias(arg1)) throw new Exception("Alias nije pronadjen!");
			 File outFile = new File(arg0);
			 if(!outFile.exists()) outFile.createNewFile();
			 FileOutputStream out = new FileOutputStream(outFile);
			 if(arg3 == 0) {
				 X509Certificate cert = (X509Certificate) keyStore.getCertificate(arg1);
				 byte[] derCert = cert.getEncoded();
				 if(arg2 == 0) {
					 out.write(derCert);
					 out.close();
					 return true;
				 }
				 if(arg2 == 1) {
					 Base64.Encoder encoder = Base64.getEncoder();
					 String cert_begin = "-----BEGIN CERTIFICATE-----\n";
					 String end_cert = "\n-----END CERTIFICATE-----";
					 String cert_middle = encoder.encodeToString(derCert);
					 String pemCert = cert_begin + cert_middle + end_cert;
					 out.write(pemCert.getBytes());
					 out.close();
					 return true;
				 } 
			 }
			 if(arg3 == 1) {
				 Certificate[] chain = keyStore.getCertificateChain(arg1);
				 if(chain != null) {
					 for(int i = 0; i < chain.length; i++) {
						 X509Certificate cert = (X509Certificate) chain[i];
						 byte[] derCert = cert.getEncoded();
						 if(arg2 == 0) {
							 out.write(derCert);
						 }
						 if(arg2 == 1) {
							 Base64.Encoder encoder = Base64.getEncoder();
							 String cert_begin = "-----BEGIN CERTIFICATE-----\n";
							 String end_cert = "\n-----END CERTIFICATE-----";
							 String cert_middle = encoder.encodeToString(derCert);
							 String pemCert = cert_begin + cert_middle + end_cert;
							 out.write(pemCert.getBytes());
						 } 
					 }
					 out.close();
					 return true;
				 }
				 out.close();
			 }
		} catch (Exception e) {
			GuiV3.reportError(e);
		}
		return false;
	}

	@Override
	public boolean exportKeypair(String arg0, String arg1, String arg2) {
		try {
			if(keyStore.containsAlias(arg0)) {
				KeyStore outStore = KeyStore.getInstance("PKCS12");
				outStore.load(null, null);
				PrivateKey pKey = (PrivateKey)keyStore.getKey(arg0, myPassword.toCharArray());
				outStore.setKeyEntry(arg0, pKey, arg2.toCharArray(), keyStore.getCertificateChain(arg0));
				File outFile = new File(arg1);
				if(!outFile.exists()) outFile.createNewFile();
				OutputStream out = new FileOutputStream(outFile, false);
				outStore.store(out, arg2.toCharArray());
				out.flush();
				out.close();
				return true;
			}
		} catch (Exception e) {
			GuiV3.reportError(e);
		}
		return false;
	}

	@Override
	public String getCertPublicKeyAlgorithm(String arg0) {
		try {
			X509Certificate cert = (X509Certificate)keyStore.getCertificate(arg0);
			return cert.getPublicKey().getAlgorithm();
		} catch (KeyStoreException e) {
			GuiV3.reportError(e);
		}
		return null;
	}

	@Override
	public String getCertPublicKeyParameter(String arg0) {
		try {
			X509Certificate cert = (X509Certificate)keyStore.getCertificate(arg0);
			String publicKeyAlgorithm = getCertPublicKeyAlgorithm(arg0);
			if(publicKeyAlgorithm.equals("RSA")) {
				RSAKey key = (RSAKey) cert.getPublicKey();
				return ((Integer)key.getModulus().bitLength()).toString();
			}
			if(publicKeyAlgorithm.equals("DSA")) {
				DSAParams params = ((DSAKey)cert.getPublicKey()).getParams();
				return ((Integer)(params.getP().bitLength() + params.getQ().bitLength())).toString();
			}
			if(publicKeyAlgorithm.equals("EC")) {
				ECParameterSpec param = ((ECKey)cert.getPublicKey()).getParams();
				return param.getCurve().toString();
			}
		} catch (KeyStoreException e) {
			GuiV3.reportError(e);
		}
		return null;
	}

	@Override
	public String getSubjectInfo(String arg0) {
		X509Certificate cert;
		try {
			cert = (X509Certificate)keyStore.getCertificate(arg0);
			return cert.getSubjectX500Principal().getName("RFC2253");
		} catch (KeyStoreException e) {
			GuiV3.reportError(e);
		}
		return null;
	}

	@Override
	public boolean importCAReply(String arg0, String arg1) {
		try {
			 FileInputStream in = new FileInputStream(arg0);
			 CertificateFactory cf = CertificateFactory.getInstance("X.509");
			 Collection c = cf.generateCertificates(in);
			 Iterator it = c.iterator();
			 X509Certificate[] chain = new X509Certificate[c.size()];
			 int i = 0;
			 while (it.hasNext()) {
			    X509Certificate cert = (X509Certificate)it.next();
			    chain[i] = cert;
			    i++;
			 }
			 keyStore.setKeyEntry(arg1, (PrivateKey)keyStore.getKey(arg1, myPassword.toCharArray()),myPassword.toCharArray(), chain);

			 in.close();
			 return true;
		} catch (Exception e) {
			GuiV3.reportError(e);
		}
		return false;
	}

	@Override
	public String importCSR(String arg0) {
		try {
			File file = new File(arg0);
			if(!file.exists()) throw new Exception("The specified file was not found!");
			byte[] encodedCsr = new byte[(int) file.length()];
			FileInputStream in = new FileInputStream(file);
			if (in.read(encodedCsr) == -1) {
				in.close();
	            throw new IOException("EOF reached while trying to read the whole file");         
	        }
			in.close();
			JcaPKCS10CertificationRequest csr = new JcaPKCS10CertificationRequest(encodedCsr);
			toBeSignedPUInfo = csr.getSubjectPublicKeyInfo();
			String subjectInfo = csr.getSubject().toString();
			return subjectInfo;
		} catch (Exception e) {
			GuiV3.reportError(e);
		}
		return null;
	}

	@Override
	public boolean importCertificate(String arg0, String arg1) {
		try {
			FileInputStream fis = new FileInputStream(arg0);
			BufferedInputStream bis = new BufferedInputStream(fis);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			while (bis.available() > 0) {
			    Certificate cert = cf.generateCertificate(bis);
			    keyStore.setCertificateEntry(arg1, cert);
			 }
			fis.close();
			return true;
		} catch (Exception e) {
			GuiV3.reportError(e);
		}
		return false;
	}

	@Override
	public boolean importKeypair(String arg0, String arg1, String arg2) {
		try {
			if(keyStore.containsAlias(arg0)) throw new Exception("Par kljuceva sa zadatim aliasom vec postoji!");
			KeyStore temp = KeyStore.getInstance("PKCS12");
			FileInputStream in = new FileInputStream(arg1);
			temp.load(in, arg2.toCharArray());
			String alias = temp.aliases().nextElement();
			PrivateKey pKey = (PrivateKey)temp.getKey(alias, arg2.toCharArray());
			keyStore.setKeyEntry(arg0, pKey, myPassword.toCharArray(), temp.getCertificateChain(alias));
			in.close();
			return true;
		} catch (Exception e) {
			GuiV3.reportError(e);
		}
		return false;
	}

	@SuppressWarnings("deprecation")
	@Override
	public int loadKeypair(String arg0) {
		try {
			if(keyStore.containsAlias(arg0)) {
				X509Certificate cert = (X509Certificate)keyStore.getCertificate(arg0);
				String publicKeyAlgorithm = getCertPublicKeyAlgorithm(arg0);
				access.setPublicKeyAlgorithm(publicKeyAlgorithm);
				if(publicKeyAlgorithm.equals("RSA") || publicKeyAlgorithm.equals("DSA"))
					access.setPublicKeyParameter(getCertPublicKeyParameter(arg0));
				else if(publicKeyAlgorithm.equals("EC"))
					access.setPublicKeyECCurve(getCertPublicKeyParameter(arg0));
				String digestAlgorithm = cert.getSigAlgName();
				access.setPublicKeyDigestAlgorithm(digestAlgorithm);
				access.setSubject(getSubjectInfo(arg0)); 
				String subjectSignatureAlgorithm = cert.getSigAlgName();
				access.setSubjectSignatureAlgorithm(subjectSignatureAlgorithm);	
				access.setIssuer(cert.getIssuerX500Principal().getName("RFC2253"));
				access.setIssuerSignatureAlgorithm(cert.getSigAlgName());
				access.setVersion(cert.getVersion() - 1);
				access.setSerialNumber(cert.getSerialNumber().toString());
				access.setNotBefore(cert.getNotBefore());
				access.setNotAfter(cert.getNotAfter());
				
				if(cert.getVersion() == 3) {
					Set<String> critical = cert.getCriticalExtensionOIDs();
					byte[] encoded;
					//Ako postoji CertificatePolicies extension, ispisi njene podatke na GUI
					if((encoded = cert.getExtensionValue(X509Extensions.CertificatePolicies.toString())) != null) {
						if(critical.contains(X509Extensions.CertificatePolicies.toString())) {
							access.setCritical(Constants.CP, true);
						}
						CertificatePolicies cp = CertificatePolicies.getInstance(X509ExtensionUtil.fromExtensionValue(encoded));
						PolicyInformation pInfo = (cp.getPolicyInformation())[0];
						ASN1Sequence pQualifier = (ASN1Sequence) pInfo.getPolicyQualifiers().getObjectAt(0);
						access.setCpsUri(pQualifier.getObjectAt(1).toString());
						access.setAnyPolicy(true);
					}
					//Ako postoji SubjectDirectoryAttributes extension, ispisi njene podatke na GUI
					if((encoded = cert.getExtensionValue(X509Extensions.SubjectDirectoryAttributes.toString())) != null) {
						if(critical.contains(X509Extensions.SubjectDirectoryAttributes.toString())) {
							access.setCritical(Constants.SDA, true);
						}
						SubjectDirectoryAttributes sda = SubjectDirectoryAttributes.getInstance(X509ExtensionUtil.fromExtensionValue(encoded));
						Vector<Attribute> attributes = sda.getAttributes();
						for(Attribute attribute : attributes) {
							if(attribute.getAttrType().toString().equals("1.3.6.1.5.5.7.9.1")) {
								access.setDateOfBirth(attribute.getAttrValues().getObjectAt(0).toString());
							}
							else if(attribute.getAttrType().toString().equals("1.3.6.1.5.5.7.9.2")) {
								access.setSubjectDirectoryAttribute(0, attribute.getAttrValues().getObjectAt(0).toString());
							}
							else if(attribute.getAttrType().toString().equals("1.3.6.1.5.5.7.9.4")) {
								access.setSubjectDirectoryAttribute(1, attribute.getAttrValues().getObjectAt(0).toString());
							}
							else if(attribute.getAttrType().toString().equals("1.3.6.1.5.5.7.9.3")) {
								access.setGender(attribute.getAttrValues().getObjectAt(0).toString());
							}
						}
					}
					//Ako postoji InhibitAnyPolicy extension, ispisi njene podatke na GUI
					if((encoded = cert.getExtensionValue(X509Extensions.InhibitAnyPolicy.toString())) != null) {
						if(critical.contains(X509Extensions.InhibitAnyPolicy.toString())) {
							access.setCritical(Constants.IAP, true);
						}
						ASN1Integer asnInt = ASN1Integer.getInstance(X509ExtensionUtil.fromExtensionValue(encoded));
						access.setSkipCerts(asnInt.getValue().toString());
					}
				}
				if(canSign(arg0)) return 2;
				if(cert.getIssuerDN().getName().equals("")) return 0;
				return 1;
			}
			else {
				throw new Exception("Alias nije pronadjen!");
			}
		} catch (Exception e) {
			GuiV3.reportError(e);
		}
		return -1;
	}
	

	@Override
	public Enumeration<String> loadLocalKeystore() {
		try {
			if(keyStore != null) return keyStore.aliases();
			else return null;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean removeKeypair(String arg0) {
		try {
			if(!keyStore.containsAlias(arg0)) return false;
			keyStore.deleteEntry(arg0);
			if(!keyStore.containsAlias(arg0)) return true;
		} catch (KeyStoreException e) {
			GuiV3.reportError(e);
		}
		return false;
	}

	@Override
	public void resetLocalKeystore() {
		try {
			Enumeration<String> aliases = keyStore.aliases();
			while(aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				keyStore.deleteEntry(alias);
			}
		} catch (KeyStoreException e) {
			GuiV3.reportError(e);
		}
	}

	@SuppressWarnings("deprecation")
	@Override
	public boolean saveKeypair(String arg0) {
		try {
			if(keyStore.containsAlias(arg0)) throw new Exception("Par kljuceva sa zadatim aliasom vec postoji!");
			if(access.getVersion() != Constants.V3) throw new Exception("Only version 3 is supported!");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(Integer.parseInt(access.getPublicKeyParameter()));  //podesavanje velicine kljuca
			KeyPair keyPair = kpg.generateKeyPair();
			X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();
			certGen.setSerialNumber(new BigInteger(access.getSerialNumber()));
			X500Principal issuer = new X500Principal(access.getSubject());
			certGen.setIssuerDN(issuer);
			certGen.setNotBefore(access.getNotBefore());
			certGen.setNotAfter(access.getNotAfter());
			certGen.setSubjectDN(new X500Principal(access.getSubject()));
			certGen.setPublicKey(keyPair.getPublic());
			certGen.setSignatureAlgorithm(access.getPublicKeyDigestAlgorithm());
			boolean critical;
			//CertificatePolicies extension
			if(access.getAnyPolicy()) {
				critical = access.isCritical(Constants.CP);
				PolicyQualifierInfo policyQInfo = new PolicyQualifierInfo(access.getCpsUri());
				PolicyInformation policyInfo = new PolicyInformation(PolicyQualifierId.id_qt_cps, new DERSequence(policyQInfo));
				certGen.addExtension(X509Extensions.CertificatePolicies, critical, new CertificatePolicies(policyInfo));
			}
			//SubjectDirectoryAttributes extension
			critical = access.isCritical(Constants.SDA);
			Vector<Attribute> attributes = new Vector<>();
			DERPrintableString dateOfBirth = new DERPrintableString(access.getDateOfBirth());
			attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1"), new DERSet(dateOfBirth)));
			DERPrintableString placeOfBirth = new DERPrintableString(access.getSubjectDirectoryAttribute(0));
			attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2"), new DERSet(placeOfBirth)));
			DERPrintableString countryOfCitizenship = new DERPrintableString(access.getSubjectDirectoryAttribute(1));
			attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4"), new DERSet(countryOfCitizenship)));
			DERPrintableString gender = new DERPrintableString(access.getGender());
			attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3"), new DERSet(gender)));
			certGen.addExtension(X509Extensions.SubjectDirectoryAttributes, critical, new SubjectDirectoryAttributes(attributes));
			
			//InhibitAnyPolicy extension
			if(access.getInhibitAnyPolicy()) {
				critical = access.isCritical(Constants.IAP);
				int skipCerts = Integer.parseInt(access.getSkipCerts());
				if(skipCerts < 0) throw new IOException("Invalid value for skipCerts");
				ASN1Integer asnInt = new ASN1Integer(skipCerts);
				certGen.addExtension(X509Extensions.InhibitAnyPolicy, critical, asnInt.getEncoded());
			}
			X509Certificate cert = certGen.generate(keyPair.getPrivate());
			keyStore.setKeyEntry(arg0, keyPair.getPrivate(), myPassword.toCharArray(), new X509Certificate[] {cert});
			return true;
		} catch (Exception e) {
			GuiV3.reportError(e);
		}
		return false;
	}

	@Override
	public boolean signCSR(String arg0, String arg1, String arg2) {
		try {
			if(!keyStore.containsAlias(arg1)) throw new Exception("Alias of the CA was not found!");
			if(!canSign(arg1)) throw new Exception("Specified alias does not belong to a CA!");
			JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(arg2);
			ContentSigner signer = signerBuilder.build((PrivateKey)keyStore.getKey(arg1, myPassword.toCharArray()));
			X500Name subject = new X500Name(access.getSubject());
			X509Certificate ca = (X509Certificate) keyStore.getCertificate(arg1);
			X500Name issuer = new JcaX509CertificateHolder(ca).getSubject();
			BigInteger serialNum = new BigInteger(access.getSerialNumber());
			Date notBefore = access.getNotBefore();
			Date notAfter = access.getNotAfter();
			X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, serialNum, notBefore, 
																				notAfter, subject, toBeSignedPUInfo);
			X509CertificateHolder certHolder = certBuilder.build(signer);
			X509Certificate[] chain = new X509Certificate[2];
			chain[0] = new JcaX509CertificateConverter().getCertificate(certHolder);;
			chain[1] = ca;
			File file = new File(arg0);
			if(!file.exists()) file.createNewFile();
			FileOutputStream out = new FileOutputStream(file);
			for(int i = 0; i < chain.length; i++) {
				out.write(chain[i].getEncoded());
			}
			
			out.close();
			return true;
		} catch (Exception e) {
			GuiV3.reportError(e);
		}
		return false;
	}

}
