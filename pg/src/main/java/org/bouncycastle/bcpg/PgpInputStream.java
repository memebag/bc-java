package org.bouncycastle.bcpg;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SignatureException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

/**
 * Wraps the BouncyCastle PGP implementation in an input stream.
 * 
 * @author ehodges@usdataworks.com
 * 
 */
public class PgpInputStream extends InputStream {

	private InputStream literalDataInputStream;
	private PGPPublicKeyEncryptedData pbe = null;
	private PGPOnePassSignature onePassSignature;
	private PGPObjectFactory pgpFact;
	private InputStream originalInputStream;
	private final EncryptionConfig signatureConfig;
	private final boolean checkIntegrity;

	public PgpInputStream(InputStream in, boolean checkIntegrity, EncryptionConfigs encryptionConfigs, EncryptionConfigs signatureConfigs) throws IOException,
			PGPException {
		this.originalInputStream = in;
		this.checkIntegrity = checkIntegrity;
		if (signatureConfigs != null && !signatureConfigs.isEmpty()) {
			this.signatureConfig = signatureConfigs.get(0);
		} else {
			this.signatureConfig = null;
		}
		in = PGPUtil.getDecoderStream(in);
		PGPObjectFactory pgpF = new PGPObjectFactory(in);
		if (encryptionConfigs != null) {
			PGPEncryptedDataList enc;

			Object o = pgpF.nextObject();
			//
			// the first object might be a PGP marker packet.
			//
			if (o instanceof PGPEncryptedDataList) {
				enc = (PGPEncryptedDataList) o;
			} else {
				enc = (PGPEncryptedDataList) pgpF.nextObject();
			}

			//
			// find the secret key
			//
			Iterator<?> it = enc.getEncryptedDataObjects();
			PGPPrivateKey sKey = null;

			while (sKey == null && it.hasNext()) {
				pbe = (PGPPublicKeyEncryptedData) it.next();
				PGPKeyPair keyPair = encryptionConfigs.getKeyPairByID(pbe.getKeyID());
				if (keyPair == null) {
					throw new PGPException("Encryption key ID [" + pbe.getKeyID() + "] not found in configuration");
				}
				sKey = keyPair.getPrivateKey();
			}
			in = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
		}

		PGPObjectFactory plainFact = new PGPObjectFactory(in);

		PGPCompressedData cData = (PGPCompressedData) plainFact.nextObject();

		InputStream compressedStream = new BufferedInputStream(cData.getDataStream());
		pgpFact = new PGPObjectFactory(compressedStream);

		Object message = pgpFact.nextObject();
		if (message instanceof PGPOnePassSignatureList) {
			PGPOnePassSignatureList sigList = (PGPOnePassSignatureList) message;
			for (int index = 0; index < sigList.size(); ++index) {
				onePassSignature = sigList.get(index);
				PGPKeyPair keyPair = signatureConfigs.getKeyPairByID(onePassSignature.getKeyID());
				if (keyPair==null) {
					throw new PGPException("Signature key ID [" + onePassSignature.getKeyID() + "] not found in configuration");
				}
				onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), keyPair.getPublicKey());
			}
			message = pgpFact.nextObject();
		}

		if (message instanceof PGPLiteralData) {
			PGPLiteralData ld = (PGPLiteralData) message;
			literalDataInputStream = ld.getInputStream();
		} else {
			throw new PGPException("Unexpected message part of type [" + message.getClass() + "] received.");
		}
	}

	@Override
	public int read() throws IOException {
		int val = literalDataInputStream.read();
		if (onePassSignature != null) {
			try {
				onePassSignature.update((byte) val);
			} catch (SignatureException e) {
				throw new IOException(e);
			}
		}
		return val;
	}

	@Override
	public int read(byte[] b) throws IOException {
		int bytesRead = literalDataInputStream.read(b);
		if (bytesRead != -1 && onePassSignature != null) {
			try {
				onePassSignature.update(b, 0, bytesRead);
			} catch (SignatureException e) {
				throw new IOException(e);
			}
		}
		return bytesRead;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		int bytesRead = literalDataInputStream.read(b, off, len);
		if (bytesRead != -1 && onePassSignature != null) {
			try {
				onePassSignature.update(b, off, bytesRead);
			} catch (SignatureException e) {
				throw new IOException(e);
			}
		}
		return bytesRead;
	}

	@Override
	public void close() throws IOException {
		if (signatureConfig != null) {
			if (onePassSignature == null) {
				throw new IOException("Stream expects signed data, but PGP data is not signed.");
			}
			PGPSignatureList signatureList = (PGPSignatureList) pgpFact.nextObject();
			if (signatureList == null) {
				throw new IOException("Stream expects signed data, but the signature is missing from the PGP data.");
			}
			PGPSignature pgpSig = signatureList.get(0);
			boolean sigVerify;
			try {
				sigVerify = onePassSignature.verify(pgpSig);
			} catch (Exception e) {
				throw new IOException("Failed to verify PGP stream signature.", e);
			}
			if (!sigVerify) {
				throw new IOException("Failed to verify PGP stream signature.");
			}
		}
		if (checkIntegrity) {
			if (pbe == null) {
				throw new IOException("Stream requires integrity check, but message was not encrypted.");
			}
			if (!pbe.isIntegrityProtected()) {
				throw new IOException("Stream requires integrity check, but integrity check is missing from PGP data.");
			} else {
				boolean integrityCheck;
				try {
					integrityCheck = pbe.verify();
				} catch (PGPException e) {
					throw new IOException("Could not verify PGP stream using an integrity check.", e);
				}
				if (!integrityCheck) {
					throw new IOException("Could not verify PGP stream using an integrity check.");
				}
			}
		}
		if (literalDataInputStream != null) {
			literalDataInputStream.close();
		}
		if (originalInputStream != null) {
			originalInputStream.close();
		}

	}

}
