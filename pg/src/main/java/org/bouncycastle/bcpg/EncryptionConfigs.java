package org.bouncycastle.bcpg;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

public class EncryptionConfigs {
	List<EncryptionConfig> configList = new ArrayList<EncryptionConfig>();
	Map<Long, JcaPGPKeyPair> keyPairMap = new HashMap<Long, JcaPGPKeyPair>();

	public JcaPGPKeyPair getKeyPairByID(long keyID) throws PGPException {
		return keyPairMap.get(keyID);
	}

	public void add(EncryptionConfig encryptionConfig) throws PGPException {
		JcaPGPKeyPair pgpKeyPair = encryptionConfig.getPGPKeyPair();
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
