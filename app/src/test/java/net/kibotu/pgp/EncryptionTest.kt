package net.kibotu.pgp

import com.google.common.truth.Truth.assertThat
import net.kibotu.base.BaseTest
import org.junit.Before
import org.junit.Test
import java.security.Security

/**
 * Created by [Jan Rabe](https://about.me/janrabe).
 */

class EncryptionTest : BaseTest() {

    init {
        // https://stackoverflow.com/a/46857694/1006741
        Security.setProperty("crypto.policy", "unlimited")
    }

    @Before
    fun setSecurityPolicy() {


        Pgp.strength = 2048
    }

    @Test
    fun encryptionProvidedTest() {

        val password = "password"

        assertThat(privateKey).isNotEmpty()
        assertThat(publicKey).isNotEmpty()

        Pgp.setPrivateKey(privateKey)
        Pgp.setPublicKey(publicKey)

        // encrypting same message twice should never be the same
        assertThat(Pgp.decrypt(encryptedMessage, password)).isEqualTo(decryptedMessage)

        assertThat(Pgp.encrypt(decryptedMessage)).isNotEqualTo(encryptedMessage)

        // decrypting multiple encrypted different messages should always be the same decrypted
        (0 until 100).forEach {
            assertThat(Pgp.decrypt(Pgp.encrypt(decryptedMessage)!!, password)).isEqualTo(decryptedMessage)
        }
    }

    @Test
    fun encryptionStringTest() {

        val expected = "secret message"

        val password = "secret"
        val krg = Pgp.generateKeyRingGenerator(password.toCharArray())

        val privateKey = Pgp.genPGPPrivKey(krg)
        val publicKey = Pgp.genPGPPublicKey(krg)

        assertThat(privateKey).isNotEmpty()
        assertThat(publicKey).isNotEmpty()

        Pgp.setPrivateKey(privateKey)
        Pgp.setPublicKey(publicKey)

        val encrypt = Pgp.encrypt(expected)
        val decrypt = Pgp.decrypt(encrypt!!, password)

        assertThat(decrypt).isEqualTo(expected)
    }

    @Test
    fun encryptionBytesTest() {

        val expected = "secret message".toByteArray()

        val password = "secret"
        val krg = Pgp.generateKeyRingGenerator(password.toCharArray())

        val privateKey = Pgp.genPGPPrivKey(krg)
        val publicKey = Pgp.genPGPPublicKey(krg)

        assertThat(privateKey).isNotEmpty()
        assertThat(publicKey).isNotEmpty()

        Pgp.setPrivateKey(privateKey)
        Pgp.setPublicKey(publicKey)

        val encrypt = Pgp.encrypt(expected)
        val decrypt = Pgp.decrypt(encrypt!!, password)

        assertThat(decrypt).isEqualTo(expected)
    }
}


internal val privateKey = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: BCPG v@RELEASE_NAME@

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
Cv+3X6Bzi/rnqw==
=ciMK
-----END PGP PRIVATE KEY BLOCK-----
        """.trimMargin()

internal val publicKey = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG v@RELEASE_NAME@

mQENBFpqO+sDCACs757WV0/Z0+CWWZAs84+tIVsdIGky7Urs2vq1yIqlekV/t1EB
dx8/F00ixpha37DU5g4NosJ8rLjEMbcnypS2wQZDYWGwEvR0DWqqcEZ2H3maoWJm
I4togBghKZQqDyTEDzaPZVsmMIGvxegC3Yr+IRkkbe/4CtrtWgNfegZjeB4zkkjv
KyDIg8PutshFQyg8X0S3Mij+Yyq9PbWr1QU4Dk5ibWX7S1sVP5m/1CzKc66R2X/j
Ve4FAZ/XGrkG+yWPsxNHAaN9OAJI6zLkMMhfpFQHinFi4WOOlSKX2GxYzYYmHcr3
F20yh781Uh0T5B0940ZuNk9fLEuBo16cakczABEBAAG0E2phbi5yYWJlQGtpYm90
dS5uZXSJAS4EEwMCABgFAlpqO+sCG4MECwkIBwYVCAIJCgsCHgEACgkQslo1dc1W
Fzztjwf8Ds3L/+t+jtiXCCWX/Xq9nk72/vZ0qkalR+vEEWqlH3SdugOSFK70F6jQ
NpZQ7E71s4SCD6NIEmgf+ZIwRKLQkTWaTMoTUu5GboVxyG439a9c4g1RENfQxbGr
9KmdiXOvc6S3fgSLtNEta4xh9/NJOuQ/9UK4Rx9tNWxg2X5uD9fpdXLxsXuiMT5T
sYP8hMblv+IdmlPbvj99uGecjp/KmS+kLl04uFg6vyf4rpOhr8N9CotiM6ECF93w
ocaRRn/kXWc1nuouqtJPGKMPDBS0VGSyj6QvXw5CT81aMX3ZzLXwXl+9eroVrBuR
nRxNHMWAXdueqVkVhkTrwgrAGc8LKbkBDQRaajvrAggAlxsT+7cg97shf/OcZuGo
ad0T4NBcA4o1WS4/a3caASZKbmCskeywWRrEAN4/GLrzNVY/B1Au9BKI5nIcf9iQ
Ish4dLw+XDac4uK80L61yq8Zab7mflTXEwCqTiQ9JBK5a0I/tQs84xlEJjwL559F
p0C49+aCJkd7buTp4JxhqQO18MGNIoPdA2yM4Ed2sWWUHTCxOBce7HbLIpc+f2ep
O13rIyH8jBpTBpOCTG/hd+5IZDAM5g7Gz+B9G/UpOtGZV8C4dTDffM1rcLZnuL/Q
DDnlx13sOxVwtJir5pUGQ2IcZVjZAP4/u4GPAlbjvLH18C/LGaMHwQxl3HilkB1H
qQARAQABiQEfBBgDAgAJBQJaajvsAhsMAAoJELJaNXXNVhc8ricIAJ6F/bGtlmFW
WAxYIu8BSyB897Mg8klJca6O9ZltkLFPokdaouYGXuAQxYwgpwHrmwlrzEsUclJx
tS0iqb3ksEsoUECAzflRGWg6Dwb/mlVJtQ9IIMbqDI3Km3ZsXve6HzpsHmdpwLW4
UcR13ZhICyRJClQFwZ1/8i3b8yT/GiyXor58RE/iiaZ2X+WNwUGeBNwLfX22r8gz
vK8f1NFLjPq870a0Cogkgl3XM/tOnQt/39svPvLImB4iXHzTl+h2cadNG+4z3Gzo
NBvMa9TejqETTvTD3kruNb1hKZfo/GgWY79GGLewet17sMnLWlTSUxahwUyiygr/
t1+gc4v656s=
=Nraf
-----END PGP PUBLIC KEY BLOCK-----
        """.trimMargin()

internal val encryptedMessage = """
-----BEGIN PGP MESSAGE-----
Version: BCPG v@RELEASE_NAME@

hQEMA6McpTD8vLrdAgf+PVj0fbet/7sly3qTCIAW2jMbRAEjYr59NPCte2WmyxvY
DfMH40zg6sZT0P8C+3H5o18KARyac8Ul0kiI5gMAMVZlNbNID570j+6GuqjyNesG
QnBNcx02d8oQcUk5C/ko9Iknnvj4Am2GEg2hilXBuD21CPIsWYq9AFaaOyfF0oN6
+va0I8DZr+jd8nPyw1pAPYWlDtEQkMCOw9FlVgykRERCc9YHHnppjgM/Fn9u0qyp
sVxxL0JPaoMfUyNjVncsZE64kNB9HKxb8tStS/u/OXV6d++kTpVPYo6seU3j1gYy
nOS0ML3wp1sCaBgFZzHd90UkEPOwp/rt/l6tx0weJtLDdgFtxrhQaLzbUQQMZuad
rKEGbuACtl4j0AxW2vhuN14UgPw1kSQmHFFQVihQaocg2Ap4zwjCtNwoxYAq5Eao
LRQ93h1q1w9rkYrSXl/SgTHs978MRAr5DhKXogYMgdQpVdhmtAXXd5Qx2nY6j+Xb
qGZt9k/VmWaiNCaN5AwPldUk4TrrcfHJ0WnLcSpFGeZawMa4l6cpX1Mz6HxbnXcV
4cq27CGgIsFtDUvQoHj3+m6M6Jq0JlfcvO2lNxoC4taQ/QI2/uMbqePXUsb8RNJZ
nVOozKzv3t+lovk/L19rH2oEcYlybUbcMU05wHbASQ2aENun6G8JLB1Yl7AzdAxL
q/sAH8H9RxkC2Ob5Im0ynYV12xa2VNJ7hMdcr27uzdKKnHcBDQHxbyIJtMH0j0nH
cjn8c9xgVtKFCchA216EJOW9jTZ8kFm8oqiVY3nBla9hoREyOU5e7m1NS23+J5aJ
a2ixC3rae+Ub9Cbgz+pXfbpvst/velg5h/M1192U6xRWQY9cEZjwZbHeF076hY8i
miPhVUjUx93PCMO02hnQOx1W5UJmhAf5K44yYHPoree/R7JJYQt8IXA9BNpEb0V9
sOpXb8svtk29dgkGDs9UALMFVDSV7AUtzesOrBRvKXelowlzqC8nAsHX2YSJfabh
5QY3zrE+ZcsxK+zzDJLIGDimxNIc2Ldy0yQcvYVvO3txlPVA5Rt16pdF2WNEVCx/
zt8yo81+uftw0vpENeaQMtmPFWbuVATG06+qZI5VXPg8/TTpe3N5FcAEjQx8vFSR
/kaFtX5Dqo2a3pcXfMjh25xrU6/AC6dOeGoRfnRsTsRrt205B28+XKJh5mNQ1Tru
G8xoo8XH81KnuqGpfIAoG9jf7XgbOEeU9ry+cOPHPG6KTJ06m4Gkus6P5Lfj0EyY
tMMlv37IgdlHKgHhUpqXPxj2IzLvfO2M1wsmNezF6GONznBl20kjfKmuJx/3aSpr
rDqkkuaFhFihJocKaIyboioMTr+tab8ZpJK+V6j/lfbk5Rwl7XyXB6z771Anm2Qw
PiTVkZR54Y/8YbLSUdLvKDtnE82K+wnZakzXgnPLwF2ErXAKPrRM9RhzT2PlvLzC
2pYz9qVrweoKoC5C8o62n748xtbLZN4ZijtzHHdhK2NZxMlo0Up21IUmFUr+wb1I
sKoJEnHIKmCiDIVqWDFOpqtvd9kfiLPAjSvh45RdI/JD31IG+q1e6lh4CyHFVCnL
dqRphWSA7OeJCRTsIKnSQVXNQhp1QZs/QG8Q0vL7UKyWHL1iresaVgtKMHRLymfI
BrpTXoqX0+00CqsQUAZ7bTKDIRY/tSBo/TSirYKEmOLVHwIdN4WmyRutHQTS9Jlh
HdsHgWwqyfyyzyYl1wms9HqPPMyGhHnJgqp7tL8jnC2PhHNT6xfDc3L7k4PlVaZ6
S0PHjje67Oo=
=k22Q
-----END PGP MESSAGE-----
        """.trimMargin()

internal val decryptedMessage = """
[
  "Cillum elit tongue in, turducken brisket pariatur tempor hamburger dolore magna excepteur spare ribs irure ad.  Nostrud ipsum aliqua id.  Aliqua dolore aute quis, pork belly irure reprehenderit short ribs t-bone ground round short loin.  Qui corned beef pork chop, magna biltong swine flank doner chicken beef.  Ball tip porchetta andouille venison occaecat sint pancetta strip steak minim bresaola turducken tempor.  Ullamco velit boudin, spare ribs biltong sausage dolore.  Est consequat hamburger elit dolore jowl, proident prosciutto adipisicing.",
  "Corned beef porchetta tail fatback consectetur aliquip.  Pastrami labore tail flank laborum elit in consequat chicken commodo turducken drumstick ea deserunt anim.  Bresaola picanha commodo sunt leberkas salami.  Dolore ham hock tri-tip tenderloin.  Corned beef tri-tip pig, magna ut buffalo laboris frankfurter kevin flank pariatur ground round.  Excepteur ullamco et venison magna do strip steak eiusmod brisket cupidatat ipsum meatball hamburger tenderloin pig.  Nisi ipsum sirloin buffalo dolor anim bacon velit occaecat pig laboris kielbasa officia.",
  "Beef ribs voluptate adipisicing, pancetta nisi eiusmod et hamburger prosciutto turducken non laborum velit ullamco.  Ipsum officia prosciutto salami, corned beef incididunt shank excepteur.  Swine esse shank short ribs pancetta, magna laborum bacon labore tempor occaecat.  Buffalo aliqua pariatur, bresaola turducken in ex culpa minim mollit fatback.  Veniam adipisicing excepteur jowl commodo id.  Filet mignon capicola est consequat, exercitation shank pastrami eu rump.  Dolore corned beef laboris esse boudin shankle elit, pastrami turkey landjaeger salami andouille frankfurter.",
  "Porchetta salami tri-tip cupim sunt ut.  Buffalo ball tip dolor, ad shankle consectetur chicken pancetta laborum flank tempor excepteur commodo ut.  Pig eu turkey excepteur beef ribs porchetta irure picanha.  Aliquip pancetta beef, rump pork belly fugiat picanha bresaola ex hamburger.  T-bone beef ullamco ut mollit.  Kevin doner aute laborum sed turducken ex buffalo.  Biltong tenderloin pork chop, kielbasa burgdoggen capicola hamburger aliqua qui velit cupidatat chicken pork belly corned beef.",
  "Flank corned beef fugiat leberkas andouille ham hock cupidatat in.  Kevin hamburger ullamco ut, laboris corned beef andouille ball tip pancetta tempor in.  Rump shankle occaecat, ribeye kielbasa incididunt duis.  Est tongue pancetta lorem cupim, strip steak sunt turkey dolore consectetur swine corned beef."
]
        """.trimMargin()