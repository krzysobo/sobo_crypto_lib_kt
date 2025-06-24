package com.krzysobo.sobocryptolib.crypto.service

// TODO FIXME - we should really move apptpl to another library now also, and bring this back
//import com.krzysobo.soboapptpl.widgets.isHexSpecifiedLength
import org.bouncycastle.crypto.CipherKeyGenerator
import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.security.SecureRandom
import java.util.regex.Matcher
import java.util.regex.Pattern


class InvalidKeySizeBitsException(message: String) : Exception(message)
class InvalidPortableHexFormatException(message: String) : Exception(message)

val PATTERN_HEX_ANY_LENGTH = Pattern.compile("\\p{XDigit}+")
val PATTERN_HEX_SPECIFIED_LENGTH = { it: Int -> Pattern.compile("\\p{XDigit}{${it}}") }

fun isHex(input: String, patt: Pattern = PATTERN_HEX_ANY_LENGTH): Boolean {
    val matcher: Matcher = patt.matcher(input)
    return matcher.matches()
}

fun isHexSpecifiedLength(input: String, length: Int, patt: Pattern = PATTERN_HEX_SPECIFIED_LENGTH(length)): Boolean {
    val matcher: Matcher = patt.matcher(input)
    return matcher.matches()
}

class CryptoService {
//    fun generateAESKey(keySizeBits: Int = 256): ByteArray {
//        val keyGen = CipherKeyGenerator()
//        val random = SecureRandom() // Secure random source
//        keyGen.init(KeyGenerationParameters(random, keySizeBits))
//        return keyGen.generateKey()
//    }

    private val PATTERN_SCC_CIPHERDATA_FORMAT_ZIG =
        { cipherHex: String,
          tagHex: String,
          aadTextHex: String,
          saltHex: String,
          nonceHex: String ->
            "S${cipherHex}H${tagHex}H${aadTextHex}H${saltHex}H${nonceHex}S"
        }
    private val PATTERN_SCC_CIPHERDATA_FORMAT_KT =
        { cipherHexWithTag: String,
          aadTextHex: String,
          saltHex: String,
          nonceHex: String ->
            "K${cipherHexWithTag}I${aadTextHex}I${saltHex}I${nonceHex}K"
        }

    val SCC_CIPHERDATA_FORMAT_ZIG = "FORMAT_ZIG"
    val SCC_CIPHERDATA_FORMAT_KT = "FORMAT_KT"

    fun isAesKeyHexValid(keyHex: String, keySizeBits: Int = 256): Boolean {
        if (keySizeBits % 8 != 0) {
            throw InvalidKeySizeBitsException("invalid key size in bits (${keySizeBits}). Must be a number that divides by 8 without modulo")
        }
        val keySizeBytes: Int = keySizeBits / 8
        return isHexSpecifiedLength(keyHex, keySizeBytes * 2)
    }

    fun makeRandomAesKey(keySizeBits: Int = 256): ByteArray {
        val keyGenerator = CipherKeyGenerator()
        val random = SecureRandom()
        keyGenerator.init(KeyGenerationParameters(random, keySizeBits))
        return keyGenerator.generateKey()
    }

    fun makeNonce(nonceSizeBytes: Int = 13): ByteArray {
        val keyGenerator = CipherKeyGenerator()
        val random = SecureRandom()
        keyGenerator.init(KeyGenerationParameters(random, nonceSizeBytes * 8))
        return keyGenerator.generateKey()
    }

    fun makeAssociatedData(): ByteArray {
        return "ELDFE(O%RX#%R 12328453wltj43rlkety6tuy6SZXJDFKLDSX%#(FGSDRGQZFO(^RQ".toByteArray()
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun bytesToHex(bytes: ByteArray): String {
        return bytes.toHexString(HexFormat.UpperCase)
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun hexToBytes(hexString: String): ByteArray {
        return hexString.hexToByteArray(HexFormat.UpperCase)
    }

    fun aesGcmEncryptToPortableHex(
        plaintext: ByteArray,
        aesKey: ByteArray,
        nonce: ByteArray,
        associatedData: ByteArray? = null,
        plaintextStartOffset: Int = 0,
        ciphertextStartOffset: Int = 0,
        nonceSizeBits: Int = 8 * 13,
        macSizeBits: Int = 128,
        portableHexFormat: String = SCC_CIPHERDATA_FORMAT_KT
    ): String {
        // {ciphertext}{tag - 16 bytes}
        val ciphertextWithTag = aesGcmEncrypt(
            plaintext = plaintext,
            aesKey = aesKey,
            nonce = nonce,
            associatedData = associatedData,
            plaintextStartOffset = plaintextStartOffset,
            ciphertextStartOffset = ciphertextStartOffset,
            nonceSizeBits = nonceSizeBits,
            macSizeBits = macSizeBits
        )

        when (portableHexFormat) {
            SCC_CIPHERDATA_FORMAT_KT ->
                return PATTERN_SCC_CIPHERDATA_FORMAT_KT(
                    CryptoService().bytesToHex(ciphertextWithTag),
                    CryptoService().bytesToHex(associatedData ?: byteArrayOf()),
                    "",
                    CryptoService().bytesToHex(nonce)
                )

            SCC_CIPHERDATA_FORMAT_ZIG -> {
                val ctSize = ciphertextWithTag.size
                val ciphertext = ciphertextWithTag.copyOfRange(0, ctSize - 16)
                val tag = ciphertextWithTag.copyOfRange(ctSize - 16, ctSize)
                return PATTERN_SCC_CIPHERDATA_FORMAT_ZIG(
                    CryptoService().bytesToHex(ciphertext),
                    CryptoService().bytesToHex(tag),
                    CryptoService().bytesToHex(associatedData ?: byteArrayOf()),
                    "",
                    CryptoService().bytesToHex(nonce)
                )
            }

            else -> throw InvalidPortableHexFormatException("incorrect portable hex format")
        }
    }

    fun aesGcmEncrypt(
        plaintext: ByteArray,
        aesKey: ByteArray,
        nonce: ByteArray,
        associatedData: ByteArray? = null,
        plaintextStartOffset: Int = 0,
        ciphertextStartOffset: Int = 0,
        nonceSizeBits: Int = 8 * 13,
        macSizeBits: Int = 128
    ): ByteArray {
//        val cipher = GCMBlockCipher(AESEngine())
        val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
        val params = AEADParameters(KeyParameter(aesKey), macSizeBits, nonce, associatedData)

        cipher.init(true, params)
        val ciphertext = ByteArray(cipher.getOutputSize(plaintext.size))
        val dataLength = cipher.processBytes(
            plaintext,
            plaintextStartOffset,
            plaintext.size,
            ciphertext,
            ciphertextStartOffset
        )

        cipher.doFinal(ciphertext, dataLength)
        return ciphertext
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun aesGcmDecryptFromPortableHex(
        ciphertextHex: String,
        aesKeyHex: String,
        macSizeBits: Int = 128,
        plaintextStartOffset: Int = 0,
        ciphertextStartOffset: Int = 0,
    ): ByteArray {
        if (ciphertextHex.startsWith("K") &&
            ciphertextHex.endsWith("K") &&
            (Regex("I").findAll(ciphertextHex).count() == 3)
        ) { // KOTLIN
            val listHexes = ciphertextHex.trim('K').split("I")
            print("LIST HEXES KT: $listHexes")
            val ciphertextHexWithTag = listHexes[0]
            val aadTextHex = listHexes[1]
//            val saltHex = listHexes[2]
            val nonceHex = listHexes[3]

            return aesGcmDecrypt(
                ciphertextHexWithTag.hexToByteArray(),
                aesKeyHex.hexToByteArray(),
                nonceHex.hexToByteArray(),
                aadTextHex.hexToByteArray(),
                macSizeBits,
                plaintextStartOffset,
                ciphertextStartOffset
            )

        } else if (ciphertextHex.startsWith("S") &&
            ciphertextHex.endsWith("S") &&
            (Regex("H").findAll(ciphertextHex).count() == 4)
        ) { // ZIG
            val listHexes = ciphertextHex.trim('S').split("H")
            print("LIST HEXES ZIG: $listHexes")

            val ciphertextHexAlone = listHexes[0]
            val tagHex = listHexes[1]
            val aadTextHex = listHexes[2]
            // val saltHex = listHexes[3]
            val nonceHex = listHexes[4]

            val ciphertextAndTagHexes = "${ciphertextHexAlone}${tagHex}"

            return aesGcmDecrypt(
                ciphertextAndTagHexes.hexToByteArray(),
                aesKeyHex.hexToByteArray(),
                nonceHex.hexToByteArray(),
                aadTextHex.hexToByteArray(),
                macSizeBits,
                plaintextStartOffset,
                ciphertextStartOffset
            )

        } else {
            throw InvalidPortableHexFormatException("incorrect portable hex format")
        }
    }

    fun aesGcmDecrypt(
        ciphertext: ByteArray,
        aesKey: ByteArray,
        nonce: ByteArray,
        associatedData: ByteArray? = null,
        macSizeBits: Int = 128,
        plaintextStartOffset: Int = 0,
        ciphertextStartOffset: Int = 0,
    ): ByteArray {
        val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
        val params = AEADParameters(KeyParameter(aesKey), macSizeBits, nonce, associatedData)
        cipher.init(false, params)

        val plaintext = ByteArray(cipher.getOutputSize(ciphertext.size))
        val dataLength: Int = cipher.processBytes(
            ciphertext,
            ciphertextStartOffset,
            ciphertext.size,
            plaintext,
            plaintextStartOffset
        )
        cipher.doFinal(plaintext, dataLength)
        return plaintext
    }

//
//    fun makeAesKeyFromPassword(keySizeBits: Int = 256): SecretKey {
//        val keyGenerator = KeyGenerator.getInstance("AES")
//        keyGenerator.init(keySize)
//        return keyGenerator.generateKey()
//    }
}