package keytesting

import java.io._
import java.nio.file.{Files, Paths}
import java.security.{KeyFactory, Security}
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

import org.bouncycastle.cms.{CMSSignedDataGenerator, _}
import org.bouncycastle.cms.jcajce.{JcaSignerInfoGeneratorBuilder, JceCMSContentEncryptorBuilder, JceKeyTransRecipientInfoGenerator}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.{JcaContentSignerBuilder, JcaDigestCalculatorProviderBuilder}
import org.bouncycastle.cms.CMSEnvelopedDataParser
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient

object Sign2 extends App {
  Security.addProvider(new BouncyCastleProvider)

  val certPath = "src/main/scala/keytesting/veonBogusCert.pem"
  val inPublic = new FileInputStream(certPath)
  val factory = CertificateFactory.getInstance("X.509")
  val cert = factory.generateCertificate(inPublic).asInstanceOf[X509Certificate]


  val keyPrivatePath = "src/main/scala/keytesting/veonBogusPrivateKey.der"
  val keyBytes = Files.readAllBytes(Paths.get(keyPrivatePath))
  val spec = new PKCS8EncodedKeySpec(keyBytes)
  val kf = KeyFactory.getInstance("RSA")
  val privateKey = kf.generatePrivate(spec)

  // sign

  val msg = new CMSProcessableByteArray("timestamp=2017-06-21T08:03:21.131Z[UTC]|access_token=myToken|amount=0".getBytes())

  val sGen = new CMSSignedDataGenerator
  val sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey)
  sGen.addSignerInfoGenerator(
    new JcaSignerInfoGeneratorBuilder(
      new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
      .build(sha1Signer, cert)
  )
  val sd = sGen.generate(msg)

  println("signed data:")
  println(Base64.getEncoder.encodeToString(sd.getEncoded))
  val content = sd.getSignedContent.asInstanceOf[CMSProcessableByteArray]
  val contentBytes = content.getContent.asInstanceOf[Array[Byte]]
  println("message in the CMSSignedData: " +new String(contentBytes, "utf-8"))

  // encrypt
  val msg2 = new CMSProcessableByteArray(sd.getEncoded)
  val edGen: CMSEnvelopedDataGenerator = new CMSEnvelopedDataGenerator()
  edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider("BC"))
  val ed: CMSEnvelopedData = edGen.generate(
   msg2,
    new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
      .setProvider("BC").build())
  val encoded = Base64.getEncoder.encodeToString(ed.getEncoded)
  println("enveloped and signed data:")
  println(encoded)

  // decrypt

  val cmsEnvelopeParser = new CMSEnvelopedDataParser(Base64.getDecoder.decode(encoded))
  val keyDecoder = new JceKeyTransEnvelopedRecipient(privateKey)
  val recipients = cmsEnvelopeParser.getRecipientInfos
  val c = recipients.getRecipients
  val it = c.iterator

  if (it.hasNext) {
    val recipient = it.next
    val myDecoded = recipient.getContent(keyDecoder)

    println("decrypted (enveloped and signed data) in base64")
    println(Base64.getEncoder.encodeToString(myDecoded))

    // Here we try to parse as CMSSignedData
    val retrieved = new CMSSignedData(myDecoded)
    println(retrieved.getSignedContent) // Doesn't work, is null


  }
}
