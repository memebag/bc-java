package org.bouncycastle.bcpg;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;

/**
 * Holds multiple EncryptionConfig objects.
 * 
 * Note: Encryption configurations should not be modified after they are added to this collection. That could change
 * their public key ID, which is calculated when the config is added.
 * 
 * @author ehodges@usdataworks.com
 * 
 */
public class EncryptionConfigs {
	private List<EncryptionConfig> configList = new ArrayList<EncryptionConfig>();
	private Map<Long, PGPKeyPair> keyPairMap = new HashMap<Long, PGPKeyPair>();

	/**
	 * Get a PGP key pair by the ID of the public key.
	 * 
	 * @param keyID
	 *            the ID of the public key.
	 * @return the PGP key pair, or null of ID is not known.
	 */
	public PGPKeyPair getKeyPairByID(long keyID) {
		return keyPairMap.get(keyID);
	}

	/**
	 * Adds an encryption configuration to this collection.
	 * 
	 * @param encryptionConfig
	 *            the encryption configuration to add.
	 * @throws PGPException
	 */
	public void add(EncryptionConfig encryptionConfig) throws PGPException {
		PGPKeyPair pgpKeyPair = encryptionConfig.getPGPKeyPair();
		long keyID = pgpKeyPair.getKeyID();
		keyPairMap.put(keyID, pgpKeyPair);
		configList.add(encryptionConfig);
	}

	public EncryptionConfig get(int index) {
		return configList.get(index);
	}

	public boolean isEmpty() {
		return configList.isEmpty();
	}

}
