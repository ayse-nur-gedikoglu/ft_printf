## PRİNTF
Sadece kendi merak ettiklerimi araştırdım..

**printf** fonksiyonu, C programlama dilinde ekrana metin ve değişken değerlerini yazdırmak için kullanılan en temel ve yaygın fonksiyonlardan biridir. Bu fonksiyon sayesinde programınızın çalışması sırasında elde ettiğiniz sonuçları kullanıcıya sunabilir, hata ayıklama süreçlerinizi kolaylaştırabilir ve programınızın daha interaktif olmasını sağlayabilirsiniz.

### printf Fonksiyonunun Temel Yapısı

C

`#include <stdio.h>`

`int main() {
    printf("Merhaba, dünya!\n");
    return 0;
}`

Kodu [dikkatli](https://www.notion.so/faq#coding) kullanın.

- **#include <stdio.h>:** Bu satır, printf fonksiyonunun bulunduğu stdio.h kütüphanesini programa dahil eder.
- **printf("Merhaba, dünya!\n");:** Bu satır, ekrana "Merhaba, dünya!" metnini yazdırır. \n karakteri ise imleci bir satır aşağıya alır.

### Format Belirteçleri (%d, %f, %s vb.)

printf fonksiyonu, sadece sabit metinler değil, aynı zamanda değişkenlerin değerlerini de ekrana yazdırmamıza olanak tanır. Bunu, format belirteçleri (format specifiers) adı verilen özel karakterler sayesinde yaparız.

Gerekli dönüşümler hakkında kısa açıklamalar:
• %c tek bir karakter yazdırır.
• %s bir karakter dizisi yazdırır.
• %p Void * pointer argümanını hexadecimal biçiminde yazdırır.
• %d 10 tabanında decimal sayı yazdırır.
• %i 10 tabanında integer yazdırır.
• %u 10 tabanında işaretsiz decimal sayı yazdırır.
• %x hexadecimal sayıyı (16 tabanında) küçük harfler ile yazdırır.
• %X hexadecimal sayıyı (16 tabanında) büyük harfler ile yazdırır.
• %% yüzde işareti yazdırır.

*NEDEN YÜZDE İŞARETİ İÇİN ÖZEL BİR FLAG VAR*

`printf` fonksiyonunda, **`%%`** ifadesi, özel bir işlevi yerine getirir: **yüzde işareti** (`%`) yazdırmak.

Bunun nedeni, `%` karakterinin `printf` fonksiyonunun formatlama mekanizması için özel bir anlam taşımasıdır. Yani, `printf` fonksiyonu ile metin yazdırırken `%` işareti, bir format belirteci olarak kullanılır (örneğin, `%d` tam sayı, `%s` string, `%f` ondalıklı sayı vb.). Bu durumda, tek bir `%` karakteri doğrudan yazdırılmak istendiğinde, `printf` bunu format belirteci olarak anlamamalıdır, çünkü bu hata anlamına gelir.

### %% Neden Kullanılır?

`printf` fonksiyonunda `%` karakteri, format belirteçlerinin başıdır. Eğer bir `%` karakterini ekrana yazdırmak istiyorsak, `printf`'a bu karakterin format belirteci olmadığını belirtmek gerekir. İşte bu yüzden **`%%`** kullanılır.

### Örnek:

```c
c
Kodu kopyala
#include <stdio.h>int main() {
    printf("%%\n");  // Ekrana bir yüzde işareti yazdırır
    return 0;
}

```

### Diğer Önemli Noktalar

- **Kaçış Sekansları:** \n (yeni satır), \t (tab), \ (ters slash) gibi özel karakterler, metin içinde özel anlamlara sahiptir.
- **Field Width:** Belirli bir alan genişliği belirlemek için kullanılır. Örneğin, %10d, bir tam sayıyı en az 10 karakterlik bir alana yazdırır.
- **Precision:** Ondalıklı sayılarda virgül sonrası basamak sayısını belirtir. Örneğin, %.2f, bir sayıyı virgulden sonra 2 basamakla yazdırır.
- **Flags:** Çıktının nasıl biçimlendirileceğini belirler. Örneğin, - işareti sol hizalamayı, + işareti ise her zaman işaret göstermeyi sağlar.

## 1 - Buffer nedir?

Buffer (tampon saha), verilerin IO (girdi-çıktı) işlemlerinden sonra belleğe yazılmadan önce uğradıkları bir sahadır. Bufferlar IO işlemi sırasında kullanıcının beklemesini engellemek için kullanılırlar. Bellekten okumak ve belleğe yazmak maliyetli bir işlemdir. Sistemi yorar ve hız olarak yavaştır. IO aygıtlarından gelen veriler bu sebeple önce bir havuzda toplanır. Böylece bu havuz belirli miktarlarda dolduktan sonra toplu olarak belleğe yazılır. Bu sisteme performans kazandıran bir harekettir.

İkinci bir unsur ise tampon sahanın olmadığını düşündüğümüz zaman verilerin yazıldığı veya okunduğu anlarda sistem bununla meşgul olacağı için yeni veri girişiokunması yapılamayacaktır. Bu da kullanıcının beklemesine sebep olacaktır. Buffer bu derdin de dermanı olmuştur çünkü veri yazımı sırasında tampon saha yeni veriler almaya devam edebilecektir

### **Printf bufferı nasıl kullanır?**

`printf` fonksiyonu, çıktı işlemlerinde tampon (buffer) yönetimi kullanarak performansı artırır. Bu tamponlama, her karakterin veya dizinin doğrudan ekrana veya dosyaya yazılmasını önler. Bunun yerine, bir miktar veri toplandıktan sonra (örneğin tampon dolduğunda veya belirli bir işaret alındığında) topluca bir çıktı olarak yazılır. Bu sayede, I/O (giriş/çıkış) işlemleri daha az sayıda gerçekleşir ve işlemci ile bellek daha verimli kullanılır.

Tampon yönetiminin `printf` içinde nasıl çalıştığını şöyle açıklayabiliriz:

1. **Dahili Tamponlama:** `printf` çağrıldığında, veri doğrudan ekrana değil, bellekteki bir tampon bölgeye yazılır. Küçük veriler bu tamponda birikir.
2. **Tampon Boşaltma:** Tampon dolduğunda, yeni bir satır karakteri (`\\n`) görüldüğünde veya `fflush(stdout)` gibi bir işlev çağrıldığında tampon boşaltılır ve veriler ekrana (veya hedef çıktıya) yazılır.
3. **Tamponlama Modları:** C standart kütüphanesi, `stdout` akışı için 3 farklı tamponlama modu sunar:
    - **Satır Bazlı Tamponlama:** Standart çıktı (`stdout`) genellikle satır bazlı tamponlama kullanır. Yani, yeni satır karakteri (`\\n`) geldiğinde tampon otomatik olarak boşaltılır.
    - **Tam Tamponlama:** Dosya gibi hedeflerde tam tamponlama yapılır. Tampon dolana kadar veri bekletilir ve sonra toplu olarak yazılır.
    - **Tamponsuz Mod:** `stderr` gibi hataların hemen görülmesi gereken durumlarda veri doğrudan yazılır, tamponlama yapılmaz.

Bu tamponlama, özellikle sık sık çağrılan `printf` işlemlerinde, daha az I/O işlemi yapılmasını sağlayarak performansı artırır.

> Keyifli bir kahve arası yazısı🧋: https://tahtaciburak.medium.com/buffer-overflow-zaafiyeti-nedir-772103939bcb
> 

---

### `stdarg` (man 3 stdarg)

`stdarg`, C dilinde fonksiyonlara değişken sayıda parametre geçmek için kullanılan bir kütüphanedir. `stdarg.h` başlık dosyasında yer alan makrolar ile, fonksiyonlar sabit sayıda parametre yerine, parametre sayısı değişebilen bir şekilde tasarlanabilir.

**İlgili Başlık Dosyası:**

```c
c
Kodu kopyala
#include <stdarg.h>

```

## 2 - VARIADIK FONKSİYONLAR

Değişkenli fonksiyonlar, başlangıçta toplam eleman sayısı bilinmeyen fonksiyonlardır.

**Değişkenli** bir fonksiyon, **değişken sayıda argüman** kabul eden bir fonksiyondur . Fonksiyondaki **"..."** ile karakterize edilir . En az 1 adet değişkene sahip olmalıdır.

Değişken argümanlı fonksiyonlar yazmak için C dilinde aşağıdaki makrolar kullanılır:

1. **`va_list`**: Argüman listesini tanımlamak için kullanılır.
2. **`va_start`**: Argüman listesinin başlatılmasını sağlar.
3. **`va_arg`**: Argüman listesinden sıradaki argümanı alır.
4. **`va_end`**: Argüman listesinin temizlenmesini sağlar.

Örnek olarak, bir fonksiyon tanımlaması şöyle olabilir:

```c
#include <stdarg.h>
#include <stdio.h>

void topla(int adet, ...) {
    va_list args;
    va_start(args, adet);

    int toplam = 0;
    for (int i = 0; i < adet; i++) {
        toplam += va_arg(args, int); // sıradaki int argümanı alıyoruz
    }

    va_end(args);
    printf("Toplam: %d\\n", toplam);
}

int main() {
    topla(3, 10, 20, 30);  // 10 + 20 + 30 = 60
    topla(5, 1, 2, 3, 4, 5);  // 1 + 2 + 3 + 4 + 5 = 15
    return 0;
}

```

### Açıklama:

1. **`va_list args;`**: Argüman listesi için bir değişken tanımladık.
2. **`va_start(args, adet);`**: Argüman listemizi başlattık; burada `adet`, ilk parametredir.
3. **`va_arg(args, int);`**: Sıradaki argümanı `int` türünde alır.
4. **`va_end(args);`**: Argüman listesini sonlandırır.

Bu yöntemle, `va_arg` kullanarak argümanları sırayla alabiliriz ve farklı veri türleri için de kullanabiliriz.

### VA-ARG
---
**type va_arg(va_list ap, type);** (Makro)

**Açıklama**

Kendisine geçirilen ap parametre değerindeki listede yer alan bir sonraki parametreyi okur.

Bu makro kullanılmadan önce, ap değişken değerine va_start veya va_copy makrosu ile bir değer atanmış olmalıdır.

İlk parametre olan ap değerinde yer alan bir sonraki parametre veri türü, type ile tanımlı veri türü ile uyumsuz olursa veya va_arg makrosu ap değişkeninde daha fazla argüman olmadığında çağrılırsa, işlem beklenmedik şekilde sonuçlanabilir.

Ayrıca, va_arg makrosu okunan parametrenin ap listesinde yer alan son parametre olduğunu belirleyemez. Bu kontrol fonksiyon içinde ayrıca yapılmalıdır.

**Parametreler**

**ap:** va_list veri türünden bir değişken olup va_arg makrosu ile ek parametreleri almak için gerekli bilgiyi içerir.

**type:** Ap parametresindeki bir sonraki parametrenin veri türünü gösterir.

**Return değeri**

Bir sonraki parametrenin değeri geri döndürülür.

### VA-START
---
**void va_start(va_list ap, parlast);** (Makro)

**Açıklama**

Kendisine geçirilen ap parametre değerine bir ilk değer verir. Bu değer va_arg ve va_end makrolarıyla kullanıldığından bu makrolar kullanılmadan önce va_start makrosu çağrılarak ap değeri oluşturulmalıdır. Aynı zamanda, parlast parametresinden sonra yer alan parametre değişkenlerine erişimi sağlar.

**Parametreler**

**ap:** va_list veri türünden bir değişken olup va_arg makrosu ile ek parametreleri almak için gerekli bilgiyi içerir.

**parlast:** İlk değişken parametreden önce yer alan parametredir.

**Return değeri**

Yok.

### VA-END
---
**void va_end(va_list ap);** (Makro)

**Açıklama**

Va_start veya va_copy makrosu ile değer ataması yapılan bir ap değişkeni için temizleme yapar.

**Parametreler**

**ap:** va_list veri türünden bir değişken olup ek parametreleri almak için gerekli bilgiyi içerir.

**Return değeri**

Yok.

## 3 - HEXADECİMAL SİSTEM

## Onaltılık Sayı Sistemi: Daha Derinlemesine Bir Bakış

**Onaltılık sayı sistemi**, bilgisayar bilimleri ve programlamada yaygın olarak kullanılan, 16 tabanlı bir sayı sistemidir. 0'dan 9'a kadar olan rakamların yanı sıra A'dan F'ye kadar olan harflerle temsil edilir. Bu sistem, ikili sayı sistemi ile olan yakınlığı ve okunabilirliği sayesinde bilgisayar dünyasında önemli bir yer tutar.

### Neden Onaltılık Sayı Sistemi Kullanıyoruz?

- **İkili Sistemle İlişki:** Her bir onaltılık rakam, dört bitlik bir ikili sayıya karşılık gelir. Bu sayede, bilgisayarların doğrudan anladığı ikili sistemi daha insan okunaklı bir şekilde ifade edebiliriz. Örneğin, ikili sayı `1101` onaltılıda `D` olarak gösterilir.
- **Okunabilirlik:** Uzun ikili sayı dizileri yerine daha kısa ve anlaşılır bir gösterim sağlar. Özellikle büyük sayılar için bu avantaj daha belirgindir. Örneğin, `1111111111111111` ikili sayısı onaltılıda `FFFF` olarak yazılır.
- **Verimlilik:** Hafıza ve işlemci kaynaklarından daha verimli kullanım sağlar.
- **Standartlaşma:** Birçok yazılım ve donanım standardında onaltılık sayı sistemi kullanıldığı için sektörde yaygın bir kabul görmüştür.

### Kullanım Alanları

- **Bilgisayar Mimarisi:** Bellek adresleri, kayıt değerleri, makine kodu gibi düşük seviyeli bileşenlerde sıkça kullanılır.
- **Programlama:** Renk kodlaması (HTML, CSS), veri yapıları, algoritmalar, hata ayıklama ve düşük seviyeli optimizasyonlarda kullanılır.
- **Ağ İletişimi:** IP adresleri, MAC adresleri, veri paketleri gibi ağ ile ilgili verilerde kullanılır.
- **Kriptografi:** Şifreleme anahtarları, hash değerleri gibi güvenlik kritik uygulamalarda kullanılır.

### Avantajları ve Dezavantajları

- **Avantajlar:**
    - İkili sisteme yakınlık
    - Okunabilirlik
    - Verimlilik
    - Standartlaşma
- **Dezavantajlar:**
    - İnsanlar için doğal olmayan bir sistem
    - Diğer sayı sistemlerine göre dönüşüm işlemleri daha karmaşık olabilir

### Örnekler

- **Renk Kodlaması:** HTML ve CSS'de renkler, onaltılık sayılarla ifade edilir. Örneğin, `#FF0000` kırmızı rengi, `#FFFFFF` beyaz rengi temsil eder.
- **Bellek Adresleri:** Bilgisayarın belleğindeki her bir konum, onaltılık bir sayı ile ifade edilir. Bu sayede, programcılar ve sistem yöneticileri, bellek üzerindeki işlemleri daha kolay takip edebilirler.
- **Hex Editörler:** Hex editörler, dosyaları ikili formatta görüntülemek ve düzenlemek için kullanılır. Bu editörlerde, dosya içeriği onaltılık sayılarla gösterilir.

### Onaltılık Sayılarla Çalışmak

- **Dönüşümler:** Ondalık, ikili ve onaltılık sayılar arasında dönüştürme işlemleri yapmak için çeşitli yöntemler ve araçlar bulunmaktadır.
- **Programlama Dilleri:** Çoğu programlama dili, onaltılık sayıları temsil etmek için özel sözdizimi sunar. Örneğin, C programlama dilinde `0x` ön eki ile başlayan sayılar onaltılık olarak kabul edilir.

**Özetle,** onaltılık sayı sistemi, bilgisayar dünyasında önemli bir role sahiptir. İkili sistem ile olan yakınlığı, okunabilirliği ve standartlaşması sayesinde birçok alanda kullanılır. Programcılar, sistem yöneticileri ve bilgisayar mühendisleri, onaltılık sayı sistemi hakkında bilgi sahibi olarak daha etkin bir şekilde çalışabilirler.

## Pointer'ların Neden Onaltılık (Hexadecimal) Olarak Çıktısı Alınır?

Pointer (işaretçi) değerleri genellikle **hexadecimal (onaltılık)** formatında tutulur ve gösterilir. Bunun temel nedeni, bellek adreslerinin çok büyük olabilmesi ve onaltılık sayma sisteminin, bu tür büyük sayıları daha kısa ve okunabilir bir şekilde ifade edebilmesidir. Bunun arkasında birkaç teknik ve pratik neden bulunmaktadır:

### 1. **Bellek Adreslerinin Boyutu ve Okunabilirlik:**

- **Bellek adresleri genellikle büyük sayılardır.** Bilgisayarların belleği, gigabaytlar (GB) veya terabaytlar (TB) seviyelerine ulaşabilir ve her bir bellek adresi aslında bir sayıdır. Bu sayılar çok büyük olabilir.
- Örneğin, bir bellek adresi 4 baytlık (32 bit) bir işaretçi ile 4.294.967.295'e kadar (yaklaşık 4 milyar) bir sayıya karşılık gelebilir. 8 baytlık (64 bit) bir işaretçi ile bu sayı daha da büyür.
- **Onaltılık (hexadecimal) sayı sistemi**, bu tür büyük sayıları çok daha kısa ve okunabilir bir formatta ifade eder. Özellikle bilgisayarların donanım düzeyinde kullandığı ikili (binary) sayı sistemine çok daha yakın olduğu için, sayılar çok daha verimli bir şekilde temsil edilir.

Örneğin:

- **Decimal (onluk):** 4.294.967.295 (bu, 32 bitlik bir bellek adresinin en yüksek değeri olabilir)
- **Hexadecimal (onaltılık):** `0xFFFFFFF` (bu aynı sayının onaltılık karşılığıdır ve çok daha kısa görünür)

Onaltılık, 16'lık tabanda sayma yaptığı için, her iki haneli bir onaltılık sayı, tam olarak 8 bitlik bir veriyi (1 bayt) temsil eder. Yani, her iki haneli bir onaltılık sayı (0–FF) 1 byte'lık bir veriyi ifade eder.

### 2. **İkili (Binary) ve Onaltılık Arasındaki İlişki:**

Bilgisayarlar doğal olarak **ikili (binary)** sayıları kullanır, yani bellek adresleri, veriler ve işlemcinin tüm hesaplamaları ikili biçimde yapılır. Ancak, ikili sayı sistemi çok uzun ve karmaşık olur.

- **Onaltılık**, ikili sayıların her 4 bitlik grubunu (nibbles) tek bir sembol ile ifade eder. Bu nedenle, bir işaretçi değeri onaltılık olarak gösterildiğinde, ikili formattaki sayılara daha yakın ve daha kısa bir şekilde temsil edilir.
- Örneğin, 8 bitlik bir değer olan `11110101`'in onaltılık karşılığı `F5`'tir.

Bu nedenle, hexadecimal sayılar bilgisayar donanımıyla oldukça uyumludur ve ikili sayıların bir temsilcisi olarak daha pratik ve okunabilir bir formattır.

### 3. **Bellek Adreslerinin Temsil Edilmesi:**

Bellek adreslerini göstermek için kullanılan sayıların onaltılık formatta olması, **adresin her bir baytını daha kolay anlamamızı sağlar**. Her bir bayt için iki haneli bir onaltılık rakam (0-FF) kullanılır. Bu, 32 bitlik bir adresin 8 onaltılık rakamla temsil edilmesini sağlar.

- **Örneğin, 32 bit bir işaretçi:**
Adres `0x7ffeefbff4d0` gibi bir değeri alabilir.
    - Bu, 7 byte'lık bir işaretçi adresinin onaltılık gösterimidir ve toplamda 12 hanelidir.
    - Eğer aynı adresi **onluk (decimal)** biçimde ifade etmeye çalışırsak, çok uzun bir sayı oluşur: `1407374883556480`.

### 4. **Hata Ayıklama ve Diagnostik Araçlar:**

İşaretçilerin (pointer) onaltılık olarak yazdırılması, özellikle hata ayıklama (debugging) sırasında daha faydalıdır. Yazılım geliştiriciler, **bellek adreslerini takip etmek**, belirli bir adresin hangi verilere işaret ettiğini görmek ve bellekle ilgili sorunları (örneğin, bellek taşmaları veya hatalı adreslere işaretçiler) analiz etmek için bu formatı kullanırlar.

Hata ayıklayıcılar ve sistem izleyicileri (debugger ve profiler araçları) genellikle bellek adreslerini onaltılık olarak gösterir çünkü bu, adresin ne kadar uzun olduğu ve hangi bölgeyi işaret ettiği hakkında bilgi verir.

### 5. **Onaltılık Formatın Kısa ve Verimli Olması:**

Onaltılık format, çok büyük sayıların verimli bir şekilde kısa bir biçimde ifade edilmesini sağlar. Bu, bellek adresleri gibi büyük sayılar için oldukça uygundur. Onaltılık sayılar, her 4 bitten bir basamağa karşılık geldiği için, uzun sayı dizilerini daha kısa ve anlaşılır bir biçimde sunar.

### Özetle:

Pointer'lar **hexadecimal** formatında tutulur ve gösterilir çünkü:

- Hexadecimal (onaltılık) formatı, **ikili** sayılara yakın olup büyük sayıları daha kısa ve okunabilir bir şekilde ifade eder.
- **Bellek adresleri çok büyük sayılardır**, bu nedenle hexadecimal formatta gösterilmeleri daha pratik ve verimlidir.
- **Bellek ve donanım seviyesi** için hexadecimal daha uygun ve doğru bir temsil biçimidir, çünkü bilgisayarlar içsel olarak ikili veri kullanır ve hexadecimal, ikili verinin daha kısa bir versiyonudur.
- **Aygıt Adresleme:** Bazı aygıtlar (örneğin, ağ kartları) da onaltılık adreslere sahiptir.

---

!https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?ixlib=rb-4.0.3&q=85&fm=jpg&crop=entropy&cs=srgb

### **Binary (İkilik) – Decimal (Onluk) Sayı Sistemleri Dönüşümü:**

### Decimal’den Binary’e Dönüşüm:

Decimal sayıyı binary sayıya dönüştürürken, bölüm 2’den küçük oluncaya kadar bölünür ve her bölme işleminden kalan alınır ve en son bölümden itibaren kalanlar sırayla soldan sağa doğru yazılır.

Örneğin 10 tabanındaki 115 sayısının, 2 tabanındaki karşılığını bulalım;

!https://koddefteri.net/wp-content/uploads/2018/07/dec-bin.jpg

### Binary’den Decimal’e Dönüşüm:

Binary sayıyı decimale dönüştürürken sağdan sola doğru 2 üzeri sıfırdan başlayarak, basamak değerine kadar üstü bir artırarak sayı basamak değeri ile çarpılır. Çıkan sonuçlar toplanır ve decimal (10 tabanlı) sayımız bulunur.

Örneğin 110101 sayımızın decimal değerini bulalım;

!http://koddefteri.net/wp-content/uploads/2018/07/bin-dec.jpg

### Hexadecimal (On Altılık) – Decimal (Onluk) Sayı Sistemleri Dönüşümü:

### Decimal’den Hexadecimal’e Dönüşüm:

Decimal sayıyı Hexadecimal sayıya dönüştürürken, bölüm 16’dan küçük oluncaya kadar bölme işlemine devam edilir ve her bölme işleminden kalan alınır ve en son bölümden itibaren kalanlar sırayla soldan sağa doğru yazılır.

Örneğin 8090 decimal sayımızın, onaltı tabanına göre değerini bulalım;

!http://koddefteri.net/wp-content/uploads/2018/07/dec-hex-1.png

### Hexadecimal’den Decimal’e Dönüşüm:

Hexadecimal sayıyı Decimal’e dönüştürürken sağdan sola doğru 16 üzeri sıfırdan başlayarak, basamak değerine kadar üstü bir artırarak, sayı basamak değeri ile çarpılır. Çıkan sonuçlar toplanır ve decimal (10 tabanlı) sayımız bulunur.

Şimdi örnek olarak Hexadecimal tabanlı 36F sayısının Decimal karşılığını hesaplayalım.

!http://koddefteri.net/wp-content/uploads/2018/07/hex-dec-1.png

### Hexadecimal (On Altılık) – Binary (İkilik) Sayı Sistemleri Dönüşümü:

Bu iki sayı sistemi aslında önce 10 tabanlı sayı sistemine dönüştürülüp ardından hedef sayı sistemine dönüştürülür ancak bunun daha kolay bir yolu vardır. Öncelikle sayı sistemleri dersinde örnek olarak göstermiş olduğumuz tabloyu buraya ekleyelim ve ardından dönüştürme işleminin nasıl yapıldığına bakalım.

Tablomuz;

!http://koddefteri.net/wp-content/uploads/2018/07/sayi-tablo-1.jpg

### Hexadecimal’den Binary’e Dönüşüm:

Hexadecimal’den Binary sayıya dönüşüm yaparken her basamağın yukarıdaki tablodan binary karşılığını alıyoruz ve aynı sıra ile yan yana ekliyoruz.

Örnek olarak Hexadecimal 2A3C sayısının binary karşılığını bulalım.

!https://koddefteri.net/wp-content/uploads/2016/10/hex-bin.png

### Binary’den Hexadecimal’e Dönüşüm:

Binary sayıdan Hexadecimal sayıya dönüşüm yaparken basamakları sağdan sola doğru dörderli gruplar halinde ayırıyoruz ve her dörderli grubun yukarıdaki tablodan Hexadecimal değerini buluyoruz.Ardından aynı sıra ile yan yana yazıyoruz.

Örnek olarak 1100111010 sayısının Hexadecimal karşılığını bulalım. Sayımızı sağdan sola doğru dörderli gruplar halinde ayırdığımızda en solda 4 basamaktan az basamak kalmışsa son grubun önündeki basamaklar sıfır kabul edilir.

!http://koddefteri.net/wp-content/uploads/2018/07/bin-hex-1.png
