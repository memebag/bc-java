package org.bouncycastle.bcpg;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

/**
 * Wraps the BouncyCastle PGP implementation in an output stream.
 * 
 * @author ehodges@usdataworks.com
 * 
 */
public class PgpOutputStream extends FilterOutputStream {
	private static final int BUFFER_SIZE = 1 << 16;
	private OutputStream encryptOut;
	private PGPCompressedDataGenerator compressor;
	private ArmoredOutputStream armoredOut;
	private OutputStream originalOut;
	private OutputStream compressedOut;
	private PGPSignatureGenerator sGen;
	private OutputStream literalDataOutputStream;
	private final boolean armored;
	private final SignatureConfig signatureConfig;

	/**
	 * Constructor.
	 * 
	 * @param out
	 *            the output stream to wrap.
	 * @throws PGPException
	 * @throws IOException
	 */
	public PgpOutputStream(OutputStream out, boolean armored, boolean checkIntegrity, int compressionAlgorithm, char dataFormat,
			EncryptionConfigs encryptionConfigs, EncryptionConfigs signatureConfigs) throws PGPException, IOException {
		super(out);
		originalOut = out;
		this.armored = armored;
		if (signatureConfigs != null && !signatureConfigs.isEmpty()) {
			this.signatureConfig = (SignatureConfig) signatureConfigs.get(0);
		} else {
			this.signatureConfig = null;
		}
		if (armored) {
			armoredOut = new ArmoredOutputStream(out);
			out = armoredOut;
		}
		if (encryptionConfigs != null && !encryptionConfigs.isEmpty()) {
			EncryptionConfig encryptionConfig = encryptionConfigs.get(0);
			JcaPGPKeyPair keyPair = encryptionConfig.getPGPKeyPair();
			PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(
					encryptionConfig.getSymmetricKeyAlgorithm()).setWithIntegrityPacket(checkIntegrity).setSecureRandom(new SecureRandom()).setProvider("BC"));
			encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(keyPair.getPublicKey()).setProvider("BC"));
			encryptOut = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]);
			out = encryptOut;
		}
		compressor = new PGPCompressedDataGenerator(compressionAlgorithm);
		PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
		compressedOut = compressor.open(out);
		byte[] buffer = new byte[BUFFER_SIZE];
		if (signatureConfig != null) {
			sGen = new PGPSignatureGenerator(
					new JcaPGPContentSignerBuilder(signatureConfig.getPublicKeyAlgorithm(), signatureConfig.getHashAlgorithm()).setProvider("BC"));
			JcaPGPKeyPair sigKeyPair = signatureConfig.getPGPKeyPair();
			sGen.init(PGPSignature.BINARY_DOCUMENT, sigKeyPair.getPrivateKey());
			Iterator<?> it = sigKeyPair.getPublicKey().getUserIDs();
			if (it.hasNext()) {
				PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
				spGen.setSignerUserID(false, (String) it.next());
				sGen.setHashedSubpackets(spGen.generate());
			}
			sGen.generateOnePassVersion(false).encode(compressedOut);

		}
		literalDataOutputStream = lData.open(compressedOut, dataFormat, "", new Date(), buffer);
		this.out = literalDataOutputStream;
	}

	@Override
	public void write(int b) throws IOException {
		if (signatureConfig != null) {
			try {
				sGen.update((byte) b);
			} catch (SignatureException e) {
				throw new IOException("Could not update signature.", e);
			}
		}
		super.write(b);
	}

	@Override
	public void close() throws IOException {
		if (literalDataOutputStream != null) {
			literalDataOutputStream.close();
		}
		if (signatureConfig != null) {
			try {
				PGPSignature sig = sGen.generate();
				sig.encode(compressedOut);
			} catch (Exception e) {
				throw new IOException("Could not generate signature.", e);
			}
		}
		if (compressor != null) {
			compressor.close();
		}
		if (encryptOut != null) {
			encryptOut.close();
		}
		if (armored) {
			if (armoredOut != null) {
				armoredOut.close();
			}
		}
		originalOut.close();
	}

}
