package org.bouncycastle.bcpg;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

/**
 * Holds configuration for PGP stream encryption/decryption.
 * 
 * @author ehodges@usdataworks.com
 * 
 */
public class EncryptionConfig {
	private int symmetricKeyAlgorithm; // see org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
	private int publicKeyAlgorithm; // see org.bouncycastle.bcpg.PublicKeyAlgorithmTags
	private PublicKey publicKey; // the public key.
	private PrivateKey privateKey; // the private key.
	private Date publicKeyTime; // the time the public key was created.

	public int getSymmetricKeyAlgorithm() {
		return symmetricKeyAlgorithm;
	}

	public void setSymmetricKeyAlgorithm(int symmetricKeyAlgorithm) {
		this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
	}

	public int getPublicKeyAlgorithm() {
		return publicKeyAlgorithm;
	}

	public void setPublicKeyAlgorithm(int publicKeyAlgorithm) {
		this.publicKeyAlgorithm = publicKeyAlgorithm;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public Date getPublicKeyTime() {
		return publicKeyTime;
	}

	public void setPublicKeyTime(Date publicKeyTime) {
		this.publicKeyTime = publicKeyTime;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public JcaPGPKeyPair getPGPKeyPair() throws PGPException {
		PublicKey pubKey = getPublicKey();
		PrivateKey privKey = getPrivateKey();
		KeyPair jcaKeyPair = new KeyPair(pubKey, privKey);
		return new JcaPGPKeyPair(getPublicKeyAlgorithm(), jcaKeyPair, getPublicKeyTime());
	}
}
