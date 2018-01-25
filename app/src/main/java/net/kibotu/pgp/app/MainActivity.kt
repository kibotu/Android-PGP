package net.kibotu.pgp.app

import android.content.Intent
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.text.TextUtils.isEmpty
import kotlinx.android.synthetic.main.activity_main.*
import net.kibotu.pgp.Pgp


class MainActivity : AppCompatActivity() {

    private val TAG: String = javaClass.simpleName

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val krgen = Pgp.generateKeyRingGenerator("password".toCharArray())
        Pgp.setPublicKey(Pgp.genPGPPublicKey(krgen))
        Pgp.setPrivateKey(Pgp.genPGPPrivKey(krgen))

        decrypted.setText("decrypted.json".openFromAssets())
        encrypted.setText("encrypted.json".openFromAssets())

        encrypt.setOnClickListener {
            val decryptedText = decrypted.text.toString().trim()
            if (!isEmpty(decryptedText))
                encrypted.setText(Pgp.encrypt(decryptedText))
        }

        decrypt.setOnClickListener {
            val encryptedText = encrypted.text.toString().trim()
            if (!isEmpty(encryptedText))
                decrypted.setText(Pgp.decrypt(encryptedText, "password"))
        }

        share.setOnClickListener { share() }
        delete.setOnClickListener {
            encrypted.setText("")
            decrypted.setText("")
        }
    }

    private fun encryptDecryptAssets() {

        Pgp.setPublicKey("rsa.pub".openFromAssets())
        Pgp.setPrivateKey("rsa".openFromAssets())

        val encrypted = Pgp.encrypt("decrypted.json".openFromAssets())
        val decrypted = Pgp.decrypt("encrypted.txt".openFromAssets(), "password")
    }

    private fun share() {
        val intent = Intent()
        intent.action = Intent.ACTION_SEND
        intent.putExtra(Intent.EXTRA_TEXT, decrypted.text.toString().trim() + "\n\n" + encrypted.text.toString().trim())
        intent.type = "text/plain"
        startActivity(Intent.createChooser(intent, "Save Data with:"))
    }

    private fun String.openFromAssets(): String {
        try {
            return assets.open(this).bufferedReader().use { it.readText() }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return ""
    }
}