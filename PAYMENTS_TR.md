# REDCELL — ödeme altyapısı ve şirket kurulumu (Türkiye)

_Hazırlayan: Direktör · 2026-08-21 · Kararlar araştırmayla doğrulandı, kaynaklar en altta._

---

## 0. Tek cümlelik cevap

**Stripe Türkiye'yi desteklemiyor.** Türkiye'den global SaaS satmanın en hızlı, en ucuz ve
en az bürokratik yolu bir **Merchant of Record (MoR)** kullanmak — yani satıcı hukuken
onlar olsun, KDV/sales-tax'i onlar toplasın, sana Türk banka hesabına havale yapsınlar.
Kodu buna göre yazdım ve canlıya aldım; senin yapman gereken tek şey hesabı açıp
3 anahtarı yapıştırmak.

---

## 1. Neden Stripe değil

Stripe'ın desteklediği ülke listesinde Türkiye **yok**. İşin merkezi desteklenen bir
ülkede olmak zorunda. Tek yolu yurtdışında şirket kurmak (UK Ltd / US LLC / Estonya OÜ)
— bu da kuruluş + muhasebe + banka + yıllık beyan demek. Şu aşamada gereksiz maliyet.

## 2. Seçenekler, dürüst karşılaştırma

| Yol | Komisyon | Türk şirketi şart mı | KDV/tax yükü | Kurulum |
|---|---|---|---|---|
| **Paddle (MoR)** ✅ önerim | ~5% + $0.50 | Hayır (şahıs yeterli) | **Onlarda** | 1–3 gün, KYC |
| Polar / Dodo / Creem (MoR) | ~4% + $0.40 | Hayır | Onlarda | 1 gün, daha yeni/riskli |
| Lemon Squeezy (MoR) | ~5% + $0.50 | Hayır | Onlarda | Stripe bünyesinde |
| **iyzico / PayTR** (yerel PSP) | ~2.5–3.5% | **Evet** | **Sende** | Şirket + KYC |
| UK Ltd + Stripe | ~2.9% + $0.30 | Yurtdışı şirket | Sende | Haftalar + masraf |

**Karar: Paddle ile başla.** Sebep: Türkiye'ye ödeme yapıyor (havale veya Payoneer,
min $100, aylık), 200+ ülkede KDV'yi o hallediyor, yurtdışı şirket gerekmiyor.
Global SaaS için komisyon farkı, tek başına global KDV uyumunu yönetmeye kıyasla ucuz.

**İkinci faz:** TL ile yerli müşteri gelmeye başlarsa iyzico/PayTR ekleriz. Kod
sağlayıcı-bağımsız yazıldı, ikinci sağlayıcı eklemek küçük iş.

---

## 3. Senin yapman gerekenler (ben yapamam — hesap açma ve kimlik/banka bilgisi)

> Bunlar bilinçli olarak bende değil: hesap açmak, KYC'ye kimlik yüklemek, banka/IBAN
> girmek ve sözleşme kabul etmek senin imzanı gerektiriyor.

**Adım 1 — Paddle hesabı** → https://paddle.com (Sign up / seller account)
- İş modeli: "SaaS / digital product", ürün: REDCELL, site: redcell.redcellv1.workers.dev
- KYC: kimlik + adres belgesi. Şahıs şirketi varsa vergi levhası.
- Payout: IBAN (TR) veya Payoneer.
- ⚠️ Paddle onay sürecinde canlı, çalışan bir ürün sayfası ister — **bizde var**, bu iyi.

**Adım 2 — Ürünü tanımla**
- Product: `REDCELL Team` · Price: `$499 / month` (sayfadaki fiyatla aynı)
- Checkout linkini kopyala.

**Adım 3 — 3 anahtarı bana ver, ben Worker'a basayım** (ya da kendin bas):
```bash
npx wrangler secret put PADDLE_CHECKOUT_TEAM
npx wrangler secret put PADDLE_WEBHOOK_SECRET
npx wrangler secret put ADMIN_EMAILS
```

**Adım 4 — Paddle webhook'u**
- URL: `https://redcell.redcellv1.workers.dev/billing/webhook/paddle`
- Events: `subscription.created/activated/updated/resumed/canceled/paused/past_due`
- Secret'i adım 3'teki `PADDLE_WEBHOOK_SECRET`'e koy.

Bu 4 adım bitince ödeme **çalışır durumda** olur. Kod hazır ve canlıda bekliyor.

---

## 4. Türkiye tarafı — şirket ve vergi

Paddle'a **şahıs şirketi** yeterli (hatta başlangıçta şahsi bile kabul edilebiliyor ama
düzgünü şirket). Şirket kurunca eline geçen üç avantaj var:

- **Genç girişimci kazanç istisnası:** 2026 için **400.000 TL**'ye kadar gelir vergisi
  istisnası. Şart: 29 yaşını doldurmamış + ilk kez mükellefiyet.
- **Hizmet/yazılım ihracatı kazanç indirimi:** yurtdışına verilen yazılım hizmetinde
  kazanç indirimi. **Kritik şart:** kazancın tamamı beyanname tarihine kadar döviz
  olarak Türkiye'ye getirilmeli. (Paddle → TR IBAN akışı bunu doğal olarak sağlıyor.)
- **KDV:** yurtdışındaki müşteriye verilip yurtdışında faydalanılan hizmet **KDV'den
  istisna**.

İki istisna **birlikte** uygulanabiliyor (önce genç girişimci, sonra ihracat indirimi).

> Oranları ve güncel şartları bir **mali müşavire** teyit ettir — bunlar her yıl değişiyor
> ve senin yaşın/mükellefiyet geçmişin sonucu doğrudan etkiliyor. Ben mali müşavir değilim.

**Pratik sıra:** Paddle hesabını aç (şahıs olarak başlayabilirsin) → ilk gelir gelmeye
başlayınca mali müşavirle şahıs şirketini kur → genç girişimci istisnasını kaydettir.

---

## 5. Ne kodladım (canlıda, çalışıyor)

| Yüzey | Yol | Durum |
|---|---|---|
| Kayıt | `/signup` | ✅ çalışıyor |
| Giriş | `/login` | ✅ çalışıyor |
| Hesap + API key | `/account` | ✅ çalışıyor |
| Admin paneli | `/admin` | ✅ çalışıyor (token veya admin e-posta) |
| Checkout | `/billing/checkout` | ⏸ Paddle linki girilince açılır |
| Webhook | `/billing/webhook/paddle` | ✅ imza doğrulaması hazır |

**Güvenlik notları:**
- Şifreler PBKDF2-SHA256, 210.000 tur, kullanıcıya özel salt. Düz şifre hiçbir yerde durmuyor.
- Oturum: httpOnly + Secure + SameSite=Lax cookie, 30 gün, opak token.
- Şifre karşılaştırması sabit zamanlı; yanlış e-postada bile aynı iş yapılıyor
  (timing ile kullanıcı var/yok ayrımı yapılamasın diye).
- Kayıt/giriş IP başına rate-limit'li (5/dk, 8/dk).
- Webhook: HMAC-SHA256 imza + 5 dakikalık replay penceresi. İmzasız istek 401.
- `/account` ve `/admin` `Cache-Control: no-store, private` — kişisel sayfa cache'e düşmez.
- API key'ler düz değil, **SHA-256 hash'i** saklanıyor; düz hali yalnızca üretildiği an gösteriliyor.

---

## Kaynaklar
- Stripe global availability — https://stripe.com/global
- Stripe supported countries 2026 — https://dodopayments.com/blogs/stripe-supported-countries-alternatives
- Paddle supported countries — https://www.paddle.com/help/start/intro-to-paddle/which-countries-are-supported-by-paddle
- Paddle payouts (wire / Payoneer, min $100) — https://www.paddle.com/help/manage/get-paid/when-and-how-do-i-get-paid
- MoR karşılaştırma 2026 — https://www.buildmvpfast.com/blog/lemon-squeezy-vs-polar-paddle-merchant-of-record-2026
- Genç girişimci istisnası 2026 (400.000 TL) — https://www.muhasebetr.com/yazarlarimiz/evrenozmen/0301/
- Yazılım ihracatı istisnası 2026 — https://vergimerkezi.com.tr/yazilim-ihracati-vergi-istisnasi-2026-hesaplama/
- Yurtdışına çalışan yazılımcıların vergilendirilmesi — https://baf.av.tr/yurt-disina-calisan-yazilimcilarin-vergilendirilmesi/
