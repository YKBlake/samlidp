### Tasarım
- SP uygulamasından yönlendirilen kullanıcı **/idp/login** URIì ile SamlServletè gelir. (Başka bir endpointe gelinmesi veya SAMLRequest gönderilmemesi durumunda hata dönülmektedir.)
- SamlServlet SamlResponseGenerator sınıfını çağırarak SAMLResponse üratir.
- SAMLRequest, IdpConfig ve PemKeyLoader sınıfındaki private ve public key bilgileri ile saml response oluşturulur. Kullanıcı bilgisi ortam bazlı setlenir.
- Oluşturulan SAMLResponse assertion URL`ine eklenerek kullanıcı SOM uygulamasına yönlendirilir.

---

### Ayarlar

**Tomcat**

   ````
   Tomcat server: local
   Deployment: war exploded
   Application Context: /idp
   On 'Update' action: update classes and resources
   JRE: java 8_381
   HTTP port: 8092
   JMX port: 1100
   ````

---

### Sertifika dosyaları nasıl yaratılır?

Aşağıdaki basamakları takip ediniz.

1. Intellij üzerinden projenin terminalini açınız.
2. Repo klonlanmadıysa aşağıdaki komut çalıştırılabilir.

    ```bash
   git clone https://github.com/YKBlake/samlidp.git
   
3. Verilen komut dizini ile sertifikalar yaratılabilir.

    ```bash
    openssl genpkey -algorithm RSA -out {private_key_pem_file_path} -pkeyopt rsa_keygen_bits:2048
    openssl rsa -in {private_key_pem_file_path} -pubout -out {public_key_pem_file_path}
    openssl req -x509 -new -key {private_key_pem_file_path} -out {certificate_pem_file_path} -days 365
    openssl x509 -outform der -in {certificate_pem_file_path} -out {certificate_der_file_path}

4. Oluşturulan dosyalar **resources/credentials/** altına eklenerek projede tutulur.
5. **certificate.der** dosyası Base64 formatına getirilerek SOM uygulamasında test ortamı için oluşturulan 
metadata.xml dosyasının X509Certificate elementine eklenmesi gerekmektedir. Aşağıdaki kod çalıştırılarak Base64
formatına getirilebilir.

    ```java
   package com.personal.workspace;

    import java.nio.file.Files;
    import java.nio.file.Paths;
    import java.util.Base64;
    
    public class Main {
        public static void main(String[] args) {
            try {
                byte[] derBytes = Files.readAllBytes(Paths.get(derFilePath));
                String base64Certificate = Base64.getEncoder().encodeToString(derBytes);
                System.out.println("Base64 Certificate:\n" + base64Certificate);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
