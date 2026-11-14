namespace Agamemnon.Core.Localization;

public static partial class Translations
{
    // Agamemnon 5.0: key → (English, Turkish). Keys that already existed (the welcome guide's
    // "what's new" lines) are replaced with their 5.0 text.
    private static readonly Dictionary<string, (string En, string Tr)> Table50 = new(StringComparer.Ordinal)
    {
        // Sidebar
        ["nav.recovery"] = ("Recovery", "Kurtarma"),

        // Dashboard: protection score
        ["score.title"] = ("Protection score {0}/100", "Koruma puanı {0}/100"),
        ["score.grade.strong"] = ("strong", "güçlü"),
        ["score.grade.fair"] = ("could be better", "daha iyi olabilir"),
        ["score.grade.weak"] = ("weak", "zayıf"),
        ["score.next"] = ("Next step: turn on “{0}” (+{1} points).", "Sonraki adım: “{0}” özelliğini açın (+{1} puan)."),
        ["score.allOn"] = ("Every layer of protection is on.", "Tüm koruma katmanları açık."),
        ["score.layer.engine"] = ("Virus scanner", "Virüs tarayıcı"),
        ["score.layer.database"] = ("Full threat database", "Tam tehdit veritabanı"),
        ["score.layer.downloads"] = ("Download protection", "İndirme koruması"),
        ["score.layer.onAccess"] = ("Real-time scanning", "Anlık tarama"),
        ["score.layer.ransomware"] = ("Ransomware shield", "Fidye yazılımı kalkanı"),
        ["score.layer.paste"] = ("Paste guard", "Yapıştırma koruması"),
        ["score.layer.smart"] = ("Smart analysis", "Akıllı analiz"),
        ["score.layer.web"] = ("Web protection", "Web koruması"),
        ["score.layer.dns"] = ("Encrypted DNS", "Şifreli DNS"),
        ["score.layer.recovery"] = ("Recent restore point", "Yakın tarihli geri yükleme noktası"),
        ["score.layer.scan"] = ("Scanned this week", "Bu hafta tarandı"),

        // Real-time protection page: smart analysis
        ["protection.smart"] = ("Smart analysis of unknown programs", "Bilinmeyen programların akıllı analizi"),
        ["protection.smart.detail"] = ("Catches new malware no list knows yet, from how the program is built: hidden or encrypted code, code that rewrites itself, no product name. Programs signed by a known publisher are never flagged.", "Henüz hiçbir listede olmayan yeni kötü amaçlı yazılımları, programın nasıl yapıldığına bakarak yakalar: gizlenmiş veya şifrelenmiş kod, kendini değiştiren kod, ürün adı olmaması. Bilinen bir yayıncının imzaladığı programlar asla işaretlenmez."),

        // Web protection
        ["web.title"] = ("Web protection", "Web koruması"),
        ["web.switch"] = ("Warn me about fake websites", "Sahte web siteleri için beni uyar"),
        ["web.switch.detail"] = ("Links you copy and the sites your downloads came from are checked for fake copies of banks, shops, e-Devlet and sign-in pages, and for known malware sites. Everything is checked on this PC.", "Kopyaladığınız bağlantılar ve indirdiğiniz dosyaların geldiği siteler; bankaların, alışveriş sitelerinin, e-Devlet'in ve giriş sayfalarının sahte kopyalarına ve bilinen kötü amaçlı sitelere karşı kontrol edilir. Her şey bu bilgisayarda kontrol edilir."),
        ["web.check.title"] = ("Check a link", "Bir bağlantıyı kontrol et"),
        ["web.check.detail"] = ("Got a text message or e-mail with a link? Paste it here before you open it.", "Bağlantı içeren bir SMS veya e-posta mı aldınız? Açmadan önce buraya yapıştırın."),
        ["web.check.button"] = ("Check", "Kontrol et"),
        ["web.result.safe"] = ("{0}: nothing suspicious found", "{0}: şüpheli bir şey bulunmadı"),
        ["web.result.caution"] = ("{0}: be careful", "{0}: dikkatli olun"),
        ["web.result.dangerous"] = ("{0}: don't open this link", "{0}: bu bağlantıyı açmayın"),
        ["web.reason.none"] = ("•  It isn't a known malware site and doesn't imitate a well-known site. Still only enter passwords on sites you opened yourself.", "•  Bilinen bir kötü amaçlı site değil ve tanınmış bir siteyi taklit etmiyor. Yine de parolanızı yalnızca kendiniz açtığınız sitelere girin."),
        ["web.reason.invalid"] = ("This isn't a web address.", "Bu bir web adresi değil."),
        ["web.reason.knownMalware"] = ("{0} is on the list of sites that spread malware.", "{0}, kötü amaçlı yazılım yayan siteler listesinde."),
        ["web.reason.lookalike"] = ("The address is made to look like {0}'s, but it isn't theirs.", "Adres {0} sitesine benzetilmiş ama ona ait değil."),
        ["web.reason.brandInName"] = ("It uses the name {0} but isn't {0}'s real site.", "{0} adını kullanıyor ama {0} kurumunun gerçek sitesi değil."),
        ["web.reason.brandInSubdomain"] = ("“{0}” only appears at the start; the site really belongs to someone else.", "“{0}” yalnızca başta görünüyor; site aslında başka birine ait."),
        ["web.reason.mixedScripts"] = ("The address mixes letters from different alphabets to imitate a real site ({0}).", "Adres, gerçek bir siteyi taklit etmek için farklı alfabelerden harfler karıştırıyor ({0})."),
        ["web.reason.internationalName"] = ("The address uses special letters ({0}); check that it is really the site you expect.", "Adres özel harfler kullanıyor ({0}); beklediğiniz site olduğundan emin olun."),
        ["web.reason.userInfo"] = ("The beginning of the link is a disguise: it really opens {0}.", "Bağlantının başı bir kılık: aslında {0} sitesini açıyor."),
        ["web.reason.ipAddress"] = ("The link goes to a bare number ({0}) instead of a name; real banks and shops don't do that.", "Bağlantı bir ad yerine çıplak bir numaraya ({0}) gidiyor; gerçek bankalar ve mağazalar bunu yapmaz."),
        ["web.reason.riskyEnding"] = ("Addresses ending in {0} are often used for scam sites.", "{0} ile biten adresler sıklıkla dolandırıcılık sitelerinde kullanılır."),
        ["web.reason.shortener"] = ("It is a shortened link ({0}): you can't see where it really goes.", "Bu kısaltılmış bir bağlantı ({0}): gerçekte nereye gittiğini göremezsiniz."),
        ["web.reason.insecureLogin"] = ("It asks for a sign-in or payment without encryption ({0}).", "Şifreleme olmadan giriş veya ödeme istiyor ({0})."),
        ["web.reason.manySubdomains"] = ("The address is unusually long and layered ({0}), a common trick to hide the real site.", "Adres alışılmadık derecede uzun ve katmanlı ({0}); gerçek siteyi gizlemek için sık kullanılan bir hile."),
        ["web.copied.title"] = ("Fake website: {0}", "Sahte web sitesi: {0}"),
        ["web.copied.text"] = ("Don't open the link you just copied, and never enter a password or card number there.", "Az önce kopyaladığınız bağlantıyı açmayın ve oraya asla parola ya da kart numarası girmeyin."),

        // Recovery page
        ["recovery.title"] = ("Recovery", "Kurtarma"),
        ["recovery.intro"] = ("Agamemnon has Windows take a restore point of your system drive every day. If ransomware or a mistake damages your files, you can get the earlier copies back from here. Restored files are put next to the originals; nothing is overwritten.", "Agamemnon, Windows'un sistem sürücünüzün her gün bir geri yükleme noktasını almasını sağlar. Fidye yazılımı veya bir hata dosyalarınıza zarar verirse önceki kopyaları buradan geri alabilirsiniz. Geri yüklenen dosyalar asıl dosyaların yanına konur; hiçbir şeyin üzerine yazılmaz."),
        ["recovery.incident.title"] = ("Get back the files the ransomware damaged", "Fidye yazılımının bozduğu dosyaları geri alın"),
        ["recovery.incident.text"] = ("On {0} the ransomware shield saw {1} file(s) being damaged. Agamemnon can bring back each one from the newest restore point taken before then.", "{0} tarihinde fidye yazılımı kalkanı {1} dosyanın bozulduğunu gördü. Agamemnon her birini o andan önce alınmış en yeni geri yükleme noktasından geri getirebilir."),
        ["recovery.incident.restore"] = ("Restore them all", "Hepsini geri yükle"),
        ["recovery.incident.dismiss"] = ("Not needed", "Gerek yok"),
        ["recovery.incident.progress"] = ("Restoring file {0} of {1}…", "{1} dosyadan {0}. geri yükleniyor…"),
        ["recovery.incident.done"] = ("{0} file(s) restored; {1} had no earlier copy.", "{0} dosya geri yüklendi; {1} dosyanın önceki kopyası yoktu."),
        ["recovery.incident.notification"] = ("Open Recovery to get the files back.", "Dosyaları geri almak için Kurtarma'yı açın."),
        ["recovery.file.title"] = ("Get back an earlier copy of a file", "Bir dosyanın önceki kopyasını geri alın"),
        ["recovery.file.detail"] = ("Choose the file, or type where it was if it's gone.", "Dosyayı seçin veya silindiyse nerede olduğunu yazın."),
        ["recovery.file.choose"] = ("Choose a file…", "Dosya seçin…"),
        ["recovery.file.find"] = ("Find copies", "Kopyaları bul"),
        ["recovery.file.invalid"] = ("Type the full path of a file on this PC, e.g. C:\\Users\\you\\Documents\\report.docx.", "Bu bilgisayardaki bir dosyanın tam yolunu yazın, örneğin C:\\Users\\siz\\Belgeler\\rapor.docx."),
        ["recovery.file.none"] = ("No restore point has an earlier copy of this file.", "Hiçbir geri yükleme noktasında bu dosyanın önceki bir kopyası yok."),
        ["recovery.file.found"] = ("{0} earlier copy(ies) found.", "{0} önceki kopya bulundu."),
        ["recovery.version.when"] = ("Copy from {0}", "{0} tarihli kopya"),
        ["recovery.version.detail"] = ("Last changed {0} · {1:N0} KB", "Son değişiklik {0} · {1:N0} KB"),
        ["recovery.version.restore"] = ("Restore", "Geri yükle"),
        ["recovery.restored"] = ("Restored as “{0}”.", "“{0}” olarak geri yüklendi."),
        ["recovery.restoreFailed"] = ("Couldn't restore the file: {0}", "Dosya geri yüklenemedi: {0}"),
        ["recovery.restoredWord"] = ("restored", "geri yüklendi"),
        ["recovery.points.title"] = ("Restore points", "Geri yükleme noktaları"),
        ["recovery.points.loading"] = ("Asking Windows…", "Windows'a soruluyor…"),
        ["recovery.points.summary"] = ("{0} restore point(s); the newest is from {1}.", "{0} geri yükleme noktası; en yenisi {1} tarihli."),
        ["recovery.points.none"] = ("No restore points yet. Agamemnon takes the first one a few minutes after Windows starts.", "Henüz geri yükleme noktası yok. Agamemnon ilkini Windows başladıktan birkaç dakika sonra alır."),
        ["recovery.points.error"] = ("Restore points aren't available: {0}", "Geri yükleme noktaları kullanılamıyor: {0}"),
        ["recovery.points.note"] = ("Agamemnon keeps its last 7 daily points; Windows decides how much disk space they may use. A restore point is not a backup: keep File History or OneDrive too.", "Agamemnon son 7 günlük noktasını saklar; ne kadar disk alanı kullanabileceklerine Windows karar verir. Geri yükleme noktası bir yedek değildir: Dosya Geçmişi veya OneDrive'ı da kullanın."),
        ["recovery.point.agamemnon"] = ("Drive {0}, taken by Agamemnon", "{0} sürücüsü, Agamemnon tarafından alındı"),
        ["recovery.point.windows"] = ("Drive {0}, taken by Windows", "{0} sürücüsü, Windows tarafından alındı"),
        ["recovery.create"] = ("Create one now", "Şimdi oluştur"),
        ["recovery.creating"] = ("Taking a restore point; this can take a minute…", "Geri yükleme noktası alınıyor; bu bir dakika sürebilir…"),
        ["recovery.created"] = ("Restore point taken.", "Geri yükleme noktası alındı."),

        // Welcome guide ("what's new" now describes 5.0)
        ["welcome.headline.upgrade"] = ("Agamemnon 5.0 is installed", "Agamemnon 5.0 kuruldu"),
        ["welcome.new.title"] = ("New in 5.0", "5.0'daki yenilikler"),
        ["welcome.new.1"] = ("•  Smart analysis: catches new malware from how it is built, before any list knows it.", "•  Akıllı analiz: yeni kötü amaçlı yazılımları, hiçbir liste tanımadan önce nasıl yapıldıklarından yakalar."),
        ["welcome.new.2"] = ("•  Web protection: warns about fake bank, shop and e-Devlet sites in links you copy and downloads.", "•  Web koruması: kopyaladığınız bağlantılardaki ve indirmelerdeki sahte banka, alışveriş ve e-Devlet siteleri için uyarır."),
        ["welcome.new.3"] = ("•  Check a link: paste a link from a text message to see if it is safe.", "•  Bağlantı kontrolü: SMS'ten gelen bir bağlantıyı yapıştırıp güvenli olup olmadığını görün."),
        ["welcome.new.4"] = ("•  Recovery: a restore point every day, and damaged files brought back after a ransomware attack.", "•  Kurtarma: her gün bir geri yükleme noktası ve fidye yazılımı saldırısından sonra bozulan dosyaların geri getirilmesi."),
        ["welcome.new.5"] = ("•  Protection score: one number on the dashboard, with the next step to make it stronger.", "•  Koruma puanı: ana sayfada tek bir sayı ve onu güçlendirmek için sonraki adım."),
        ["welcome.new.6"] = ("•  Everything from 4.0 stays: ransomware shield, paste guard, USB protection and the Security checkup.", "•  4.0'daki her şey yerinde: fidye yazılımı kalkanı, yapıştırma koruması, USB koruması ve Güvenlik kontrolü."),

        // Help
        ["help.q.recovery"] = ("Ransomware damaged my files. Can I get them back?", "Fidye yazılımı dosyalarımı bozdu. Geri alabilir miyim?"),
        ["help.a.recovery"] = ("Often, yes. Open Recovery: if the ransomware shield stepped in, press “Restore them all”. Otherwise choose a file and pick an earlier copy. Agamemnon takes a restore point every day, so files from yesterday can usually come back. Never pay the ransom.", "Çoğu zaman evet. Kurtarma'yı açın: fidye yazılımı kalkanı devreye girdiyse “Hepsini geri yükle”ye basın. Aksi halde bir dosya seçip önceki bir kopyasını seçin. Agamemnon her gün bir geri yükleme noktası alır, bu yüzden dünkü dosyalar genellikle geri gelebilir. Fidyeyi asla ödemeyin."),
        ["help.q.link"] = ("I got a text message with a link. Is it safe?", "Bağlantı içeren bir SMS aldım. Güvenli mi?"),
        ["help.a.link"] = ("Open Real-time protection, paste the link under “Check a link” and press Check. Agamemnon tells you if it imitates a bank, a shop, a delivery company or e-Devlet, or is a known malware site. When in doubt, open the bank's app or type its address yourself.", "Gerçek zamanlı koruma'yı açın, bağlantıyı “Bir bağlantıyı kontrol et” bölümüne yapıştırın ve Kontrol et'e basın. Agamemnon, bağlantının bir bankayı, mağazayı, kargo şirketini veya e-Devlet'i taklit edip etmediğini ya da bilinen kötü amaçlı bir site olup olmadığını söyler. Emin değilseniz bankanın uygulamasını açın veya adresini kendiniz yazın."),
        ["help.q.smart"] = ("A program was “built like malware”. What does that mean?", "Bir program “kötü amaçlı yazılım gibi yapılmış”. Bu ne demek?"),
        ["help.a.smart"] = ("The smart analysis found tricks malware uses to hide, such as encrypted code, and nobody vouches for the program with a signature. It may still be harmless (some small free tools are built this way). If you don't know where it came from, quarantine it.", "Akıllı analiz, kötü amaçlı yazılımların gizlenmek için kullandığı hileler (örneğin şifrelenmiş kod) buldu ve program için imzasıyla kefil olan kimse yok. Yine de zararsız olabilir (bazı küçük ücretsiz araçlar böyle yapılır). Nereden geldiğini bilmiyorsanız karantinaya alın."),
        ["help.q.score"] = ("What is the protection score?", "Koruma puanı nedir?"),
        ["help.a.score"] = ("A number from 0 to 100 for how many of Agamemnon's layers of protection are working, with points off for weak Windows settings. Below it the dashboard names the next thing to turn on. A threat that is still on the PC keeps the score at 40 or less until it is quarantined.", "Agamemnon'un koruma katmanlarından kaçının çalıştığını gösteren 0 ile 100 arasında bir sayı; zayıf Windows ayarları puan düşürür. Ana sayfa, altında açılacak sonraki özelliği gösterir. Bilgisayarda hâlâ bir tehdit varsa, karantinaya alınana kadar puan 40 veya altında kalır."),
    };
}
