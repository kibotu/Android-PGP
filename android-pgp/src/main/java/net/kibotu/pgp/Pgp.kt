package net.kibotu.pgp

import org.spongycastle.bcpg.ArmoredInputStream
import org.spongycastle.bcpg.ArmoredOutputStream
import org.spongycastle.bcpg.HashAlgorithmTags
import org.spongycastle.bcpg.SymmetricKeyAlgorithmTags
import org.spongycastle.bcpg.sig.Features
import org.spongycastle.bcpg.sig.KeyFlags
import org.spongycastle.crypto.generators.RSAKeyPairGenerator
import org.spongycastle.crypto.params.RSAKeyGenerationParameters
import org.spongycastle.jce.provider.BouncyCastleProvider
import org.spongycastle.openpgp.*
import org.spongycastle.openpgp.operator.bc.*
import org.spongycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder
import org.spongycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.nio.charset.Charset
import java.security.SecureRandom
import java.security.Security
import java.util.*

/**
 * Based on https://stackoverflow.com/a/33308732/1006741
 */
object Pgp {

    private const val KEY_RING_ID = "jan.rabe@kibotu.net"

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    private var publicKey: ByteArray? = null
    private var privateKey: ByteArray? = null

    private val bcKeyFingerprintCalculator = BcKeyFingerprintCalculator()

    private val pgpPublicKeyRing: PGPPublicKeyRing
        @Throws(IOException::class)
        get() {
            val ais = ArmoredInputStream(ByteArrayInputStream(publicKey))
            val pgpObjectFactory = PGPObjectFactory(ais, bcKeyFingerprintCalculator)
            return pgpObjectFactory.nextObject() as PGPPublicKeyRing
        }

    private val pgpSecretKeyRing: PGPSecretKeyRing
        @Throws(IOException::class)
        get() {
            val ais = ArmoredInputStream(ByteArrayInputStream(privateKey))
            return PGPObjectFactory(ais, bcKeyFingerprintCalculator).nextObject() as PGPSecretKeyRing
        }

    private fun getPublicKey(publicKeyRing: PGPPublicKeyRing): PGPPublicKey? {
        val kIt = publicKeyRing.publicKeys
        while (kIt.hasNext()) {
            val k = kIt.next() as PGPPublicKey
            if (k.isEncryptionKey) {
                return k
            }
        }
        return null
    }

    @Throws(PGPException::class)
    private fun getPrivateKey(keyRing: PGPSecretKeyRing, keyID: Long, pass: CharArray): PGPPrivateKey {
        val secretKey = keyRing.getSecretKey(keyID)
        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(pass)
        return secretKey.extractPrivateKey(decryptor)
    }

    /**
     * @param privateKey Private Key in PGP format.
     */
    @JvmStatic
    fun setPrivateKey(privateKey: String) {
        Pgp.privateKey = privateKey.toByteArray()
    }

    /**
     * @param privateKey Public Key in PGP format.
     */
    @JvmStatic
    fun setPublicKey(publicKey: String) {
        Pgp.publicKey = publicKey.toByteArray()
    }

    /**
     * @param encrypted Encrypted message.
     * @param password Password on PGP Key
     * @return decrypted message
     */
    @JvmStatic
    @Throws(Exception::class)
    fun decrypt(encrypted: ByteArray, password: String): ByteArray? {
        var inputStream: InputStream = ByteArrayInputStream(encrypted)
        inputStream = PGPUtil.getDecoderStream(inputStream)
        val pgpF = PGPObjectFactory(inputStream, bcKeyFingerprintCalculator)
        val enc: PGPEncryptedDataList
        val o = pgpF.nextObject()
        if (o is PGPEncryptedDataList) {
            enc = o
        } else {
            enc = pgpF.nextObject() as PGPEncryptedDataList
        }
        var sKey: PGPPrivateKey? = null
        var pbe: PGPPublicKeyEncryptedData? = null
        while (sKey == null && enc.encryptedDataObjects.hasNext()) {
            pbe = enc.encryptedDataObjects.next() as PGPPublicKeyEncryptedData
            sKey = getPrivateKey(pgpSecretKeyRing, pbe.keyID, password.toCharArray())
        }
        if (pbe != null) {
            val clear = pbe.getDataStream(BcPublicKeyDataDecryptorFactory(sKey))
            var pgpFact = PGPObjectFactory(clear, bcKeyFingerprintCalculator)
            val cData = pgpFact.nextObject() as PGPCompressedData
            pgpFact = PGPObjectFactory(cData.dataStream, bcKeyFingerprintCalculator)
            val ld = pgpFact.nextObject() as PGPLiteralData
            val unc = ld.inputStream
            val out = ByteArrayOutputStream()
            var ch = 0
            while (ch >= 0) {
                ch = unc.read()
                out.write(ch)
            }
            val returnBytes = out.toByteArray()
            out.close()
            return returnBytes
        }
        return null
    }

    /**
     * @param encryptedText Encrypted message.
     * @param password Password on PGP Key
     * @return decrypted message
     */
    @JvmStatic
    @Throws(Exception::class)
    fun decrypt(encryptedText: String, password: String): String? {
        return decrypt(encryptedText.toByteArray(), password)?.let { return String(it) }
    }

    /**
     * @param msg Plain message.
     * @return PGP encrypted message.
     */
    @JvmStatic
    @Throws(IOException::class, PGPException::class)
    fun encrypt(msg: ByteArray): ByteArray? {
        val pgpPublicKeyRing = pgpPublicKeyRing
        val encKey = getPublicKey(pgpPublicKeyRing)
        val encOut = ByteArrayOutputStream()
        val out = ArmoredOutputStream(encOut)
        val bOut = ByteArrayOutputStream()
        val comData = PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP)
        val cos = comData.open(bOut)
        val lData = PGPLiteralDataGenerator()
        val pOut = lData.open(cos, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, msg.size.toLong(), Date())
        pOut.write(msg)
        lData.close()
        comData.close()
        val encGen = PGPEncryptedDataGenerator(
                JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithIntegrityPacket(true).setSecureRandom(
                        SecureRandom()).setProvider(BouncyCastleProvider.PROVIDER_NAME))
        if (encKey != null) {
            encGen.addMethod(JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(BouncyCastleProvider.PROVIDER_NAME))
            val bytes = bOut.toByteArray()
            val cOut = encGen.open(out, bytes.size.toLong())
            cOut.write(bytes)
            cOut.close()
        }
        out.close()
        return encOut.toByteArray()
    }
    /**
     * @param msg Plain message.
     * @return PGP encrypted message.
     */
    @JvmStatic
    @Throws(IOException::class, PGPException::class)
    fun encrypt(msgText: String): String? {
        return encrypt(msgText.toByteArray())?.let { return String(it) }
    }

    @JvmStatic
    @Throws(PGPException::class)
    fun generateKeyRingGenerator(pass: CharArray): PGPKeyRingGenerator {
        val kpg = RSAKeyPairGenerator()
        kpg.init(RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), SecureRandom(), 2048, 12))
        val rsakp_sign = BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), Date())
        val rsakp_enc = BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), Date())
        val signhashgen = PGPSignatureSubpacketGenerator()
        signhashgen.setKeyFlags(false, KeyFlags.SIGN_DATA or KeyFlags.CERTIFY_OTHER or KeyFlags.SHARED)
        signhashgen.setPreferredSymmetricAlgorithms(false, intArrayOf(SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128))
        signhashgen.setPreferredHashAlgorithms(false, intArrayOf(HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA1, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA224))
        signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION)
        val enchashgen = PGPSignatureSubpacketGenerator()
        enchashgen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
        val sha1Calc = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
        val sha256Calc = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256)
        val pske = BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc, 0xc0).build(pass)
        val keyRingGen = PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsakp_sign,
                KEY_RING_ID, sha1Calc, signhashgen.generate(), null, BcPGPContentSignerBuilder(rsakp_sign.publicKey.algorithm,
                HashAlgorithmTags.SHA1), pske)
        keyRingGen.addSubKey(rsakp_enc, enchashgen.generate(), null)
        return keyRingGen
    }

    /**
     * @param krgen PGP Key Ring Generator
     * @return Public Key in PGP format.
     */
    @JvmStatic
    @Throws(IOException::class)
    fun genPGPPublicKey(krgen: PGPKeyRingGenerator): String {
        val baosPkr = ByteArrayOutputStream()
        val pkr = krgen.generatePublicKeyRing()
        val armoredStreamPkr = ArmoredOutputStream(baosPkr)
        pkr.encode(armoredStreamPkr)
        armoredStreamPkr.close()
        return String(baosPkr.toByteArray(), Charset.defaultCharset())
    }

    /**
     * @param krgen PGP Key Ring Generator
     * @return Private Key in PGP format.
     */
    @JvmStatic
    @Throws(IOException::class)
    fun genPGPPrivKey(krgen: PGPKeyRingGenerator): String {
        val baosPriv = ByteArrayOutputStream()
        val skr = krgen.generateSecretKeyRing()
        val armoredStreamPriv = ArmoredOutputStream(baosPriv)
        skr.encode(armoredStreamPriv)
        armoredStreamPriv.close()
        return String(baosPriv.toByteArray(), Charset.defaultCharset())
    }
}