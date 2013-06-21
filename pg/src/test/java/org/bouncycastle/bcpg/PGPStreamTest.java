package org.bouncycastle.bcpg;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;

import junit.framework.TestCase;

/**
 * Demonstrate basic PGP stream functionality.
 * 
 * @author ehodges@usdataworks.com
 *
 */
public class PGPStreamTest extends TestCase {

	private static final int MESSAGE_SIZE = 500000;

	public void testEncryptionWithoutArmor() throws Exception {
		EncryptionConfig encryptionConfig = createEncryptionConfig();
		byte[] message = createRandomMessage();
		byte[] encryptedMessage = encryptMessage(encryptionConfig, null, message, false, true);
		byte[] decryptedMessage = decryptMessage(encryptionConfig, null, encryptedMessage, true);
		assertContentEquals(message, decryptedMessage);
	}

	public void testEncryptionArmored() throws Exception {
		EncryptionConfig encryptionConfig = createEncryptionConfig();
		byte[] message = createRandomMessage();
		byte[] encryptedMessage = encryptMessage(encryptionConfig, null, message, true, true);
		byte[] decryptedMessage = decryptMessage(encryptionConfig, null, encryptedMessage, true);
		assertContentEquals(message, decryptedMessage);
	}

	public void testSignature() throws Exception {
		SignatureConfig signatureConfig = createSignatureConfig();
		byte[] message = createRandomMessage();
		byte[] encryptedMessage = encryptMessage(null, signatureConfig, message, true, false);
		byte[] decryptedMessage = decryptMessage(null, signatureConfig, encryptedMessage, false);
		assertContentEquals(message, decryptedMessage);
	}

	public void testEncryptionAndSignature() throws Exception {
		EncryptionConfig encryptionConfig = createEncryptionConfig();
		SignatureConfig signatureConfig = createSignatureConfig();
		byte[] message = createRandomMessage();
		byte[] encryptedMessage = encryptMessage(encryptionConfig, signatureConfig, message, true, true);
		byte[] decryptedMessage = decryptMessage(encryptionConfig, signatureConfig, encryptedMessage, true);
		assertContentEquals(message, decryptedMessage);
	}

	private void assertContentEquals(byte[] originalBytes, byte[] decryptedBytes) {
		assertEquals("Lengths not equal", originalBytes.length, decryptedBytes.length);
		for (int index = 0; index < originalBytes.length; ++index) {
			assertEquals("Bytes not equal at position " + index, originalBytes[index], decryptedBytes[index]);
		}
	}

	private static byte[] createRandomMessage() {
		SecureRandom random = new SecureRandom();
		byte[] message = new byte[MESSAGE_SIZE];
		random.nextBytes(message);
		return message;
	}

	private static byte[] decryptMessage(EncryptionConfig encryptionConfig, SignatureConfig signatureConfig, byte[] encryptedMessage, boolean checkIntegrity) throws IOException,
			PGPException {
		byte[] decryptedMessage;
		ByteArrayInputStream bais = new ByteArrayInputStream(encryptedMessage);
		try {
			PgpInputStream in = new PgpInputStream(bais, checkIntegrity, encryptionConfig, signatureConfig);
			try {
				ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
				try {
					byte[] buffer = new byte[10000];
					int bytesRead = -1;
					while ((bytesRead = in.read(buffer)) != -1) {
						baos2.write(buffer, 0, bytesRead);
					}
				} finally {
					baos2.close();
				}
				decryptedMessage = baos2.toByteArray();
			} finally {
				in.close();
			}
		} finally {
			bais.close();
		}
		return decryptedMessage;
	}

	private static byte[] encryptMessage(EncryptionConfig encryptionConfig, SignatureConfig signatureConfig, byte[] message, boolean armored, boolean checkIntegrity) throws PGPException, IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			PgpOutputStream out = new PgpOutputStream(baos, armored, checkIntegrity, CompressionAlgorithmTags.ZIP, PGPLiteralData.BINARY, encryptionConfig, signatureConfig);
			try {
				out.write(message);
			} finally {
				out.close();
			}
		} finally {
			baos.close();
		}
		byte[] encryptedMessage = baos.toByteArray();
		return encryptedMessage;
	}

	private static SignatureConfig createSignatureConfig() throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
		gen.initialize(1024, new SecureRandom());
		KeyPair sigPair = gen.generateKeyPair();
		SignatureConfig signatureConfig = new SignatureConfig();
		signatureConfig.setHashAlgorithm(HashAlgorithmTags.SHA256);
		signatureConfig.setPrivateKey(sigPair.getPrivate());
		signatureConfig.setPublicKey(sigPair.getPublic());
		signatureConfig.setPublicKeyAlgorithm(PublicKeyAlgorithmTags.RSA_GENERAL);
		signatureConfig.setPublicKeyTime(new Date());
		signatureConfig.setSymmetricKeyAlgorithm(SymmetricKeyAlgorithmTags.AES_256);
		return signatureConfig;
	}

	private static EncryptionConfig createEncryptionConfig() throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
		gen.initialize(1024, new SecureRandom());
		KeyPair encPair = gen.generateKeyPair();
		EncryptionConfig encryptionConfig = new EncryptionConfig();
		encryptionConfig.setPrivateKey(encPair.getPrivate());
		encryptionConfig.setPublicKey(encPair.getPublic());
		encryptionConfig.setPublicKeyAlgorithm(PublicKeyAlgorithmTags.RSA_GENERAL);
		encryptionConfig.setPublicKeyTime(new Date());
		encryptionConfig.setSymmetricKeyAlgorithm(SymmetricKeyAlgorithmTags.AES_256);
		return encryptionConfig;
	}
}
