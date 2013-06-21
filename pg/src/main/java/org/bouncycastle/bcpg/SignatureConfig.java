package org.bouncycastle.bcpg;

/**
 * Holds configuration for PGP stream signing/verifying.
 * 
 * @author ehodges@usdataworks.com
 * 
 */
public class SignatureConfig extends EncryptionConfig {
	private int hashAlgorithm; // see org.bouncycastle.bcpg.HashAlgorithmTags

	public int getHashAlgorithm() {
		return hashAlgorithm;
	}

	public void setHashAlgorithm(int hashAlgorithm) {
		this.hashAlgorithm = hashAlgorithm;
	}
}
