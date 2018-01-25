package net.kibotu.pgp

import android.content.Intent
import android.os.Bundle
import android.support.v7.app.AppCompatActivity


class MainActivity : AppCompatActivity() {

    private val TAG: String = javaClass.simpleName

    var encrypted: String? = null
    var decrypted: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val krgen = Pgp.generateKeyRingGenerator("password".toCharArray())
        Pgp.setPublicKey(Pgp.genPGPPublicKey(krgen))
        Pgp.setPrivateKey(Pgp.genPGPPrivKey(krgen))

        Pgp.setPublicKey("rsa.pub".openFromAssets())
        Pgp.setPrivateKey("rsa".openFromAssets())

        encrypted = Pgp.encrypt("decrypted.json".openFromAssets())
        decrypted = Pgp.decrypt("encrypted.txt".openFromAssets(), "password")
    }

    private fun share(encrypted: String?) {
        val intent = Intent()
        intent.action = Intent.ACTION_SEND
        intent.putExtra(Intent.EXTRA_TEXT, encrypted)
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