# NEX VAULT — Fix Guide (Hindi/Hinglish)

Ye zip aapke project ki **saaf aur fixed** copy hai. Niche sab kuch step-by-step
samjhaaya hai — kaun si problem thi, kaise fix hui, aur aapko Render par kya karna hai.

---

## 📁 1. Folder structure (ab sahi hai)

Dockerfile aur package.json expect karte hain ki scripts ek `scripts/` folder me ho.
Pehle ye files root me padi thi, isliye `npm test / backup / restore` aur Docker build
galat ho sakta tha. Ab structure aisa hai:

```
nexvault-fixed/
├── .env                  (local reference ke liye — Render par ENV dashboard me set karo)
├── Dockerfile
├── docker-compose.yml
├── package.json
├── render.yaml           ← NAYA: Render blueprint (asli fix yahan hai)
├── server.js             ← health endpoint add kiya
├── public/               ← ⚠️ YE AAPKE PAAS HAI, zip me nahi (niche padho)
└── scripts/
    ├── backup.js
    ├── restore.js
    └── run-tests.js
```

---

## 🔴 2. ASLI PROBLEM — "visitor ko blank site dikhti hai"

**Kyun ho raha tha:**
Aapka saara data — products, images, videos, heroes, orders — `/data` folder ke andar
ek SQLite database aur uploads me store hota hai (`server.js` dekho: `DATA_DIR`,
`nexvault.db`, `uploads/`).

Render.com ka normal disk **EPHEMERAL** hota hai — matlab **har deploy ya restart par
`/data` poora mit jaata hai.** Free plan par to service thodi der inactive rehne par
"spin down" ho jaati hai, phir jab koi visitor link kholta hai to ek **fresh khaali
container** start hota hai — database khaali → catalogue khaali → **blank website**.

Aap khud ko data isliye dikhta tha kyunki aapne abhi-abhi upload kiya tha (purana
container abhi zinda tha). Thodi der baad / redeploy ke baad wo sab gayab.

Maine ye test karke confirm kiya: fresh data folder par `/api/catalogue` khaali
`{products:[]}` return karta hai — yahi blank page ki wajah hai.

**FIX — Persistent Disk:**
Maine `render.yaml` banaya hai jo `/data` par ek **permanent disk** mount karta hai.
Iske baad data restart/redeploy ke baad bhi safe rahega.

> ⚠️ **Zaroori:** Persistent disk Render ke **PAID plan** (Starter se upar) par hi
> milta hai. Free plan par disk nahi hota — isliye free plan par ye data-loss
> problem permanent fix nahi ho sakti. Agar free hi rakhna hai to database/uploads
> ko bahar le jaana padega (jaise Postgres + Cloudinary/S3) — wo bada change hai,
> bolo to woh bhi plan bana dunga.

---

## 🟠 3. Dockerfile healthcheck fix

`Dockerfile` line 9 me healthcheck `/api/health` ko call karta tha, par `server.js`
me aisa koi route tha hi nahi → container hamesha "unhealthy".

Maine `server.js` me ye naya route add kar diya hai:

```
GET /api/health  →  { ok, node, data_dir, uptime_s, time }
```

Ab healthcheck pass hoga. (Test karke confirm kiya — HTTP 200 aa raha hai.)

---

## 🟡 4. public/ folder (aapko dhyan dena hai)

`Dockerfile` ki line `COPY public ./public` — yani aapka storefront (index.html,
admin.html, order.html) `public/` folder me hona chahiye. **Ye folder aapne mujhe
upload nahi kiya tha**, isliye maine ise zip me shaamil nahi kiya (banaya hua / nakli
frontend daalna theek nahi hota — wo aapki real site se alag hota).

👉 Aapke Render repo me ye `public/` folder pehle se hona chahiye. Is zip ki files ko
apne repo me **merge** karo, aur `public/` ko waise hi rehne do. Agar public/ missing
hua to Docker build fail hoga ya site blank aayegi — us case me mujhe apna public/
folder bhejो, main check kar dunga.

---

## 🟢 5. Render par kya karna hai (steps)

1. Is zip ki files apne GitHub repo me daalo (public/ ko chhodkar — wo rehne do).
   `scripts/` folder zaroor banao.
2. Repo me `render.yaml` commit karo.
3. Render par: **Blueprint** se deploy karo (ya existing service me **Disk** add karke
   mountPath `/data` set karo), aur plan ko **Starter** (paid) karo taaki disk mile.
4. Render dashboard → **Environment** me ye secrets manually daalo:
   - `ADMIN_PASSWORD` = (strong password)
   - `BANK_WEBHOOK_SECRET` = (aapka secret)
   - `DATA_DIR` = `/data`  (disk mountPath ke saath same hona chahiye)
5. Deploy karo. Ab admin panel se products/images dobara upload karo (purana data to
   ja chuka hai). Ye naya data ab **permanent** rahega.
6. Check: `https://<aapki-site>.onrender.com/api/health` → `{"ok":true,...}` aana
   chahiye.

---

## ⚠️ 6. Ek aur baat — run-tests.js purane version ka hai

`scripts/run-tests.js` ek **alag/naye version** ke server ko test karta hai. Wo in
routes/fields ko expect karta hai jo aapke abhi wale `server.js` me **nahi** hain,
jaise:

- `/api/site`, `/api/admin/site`  (aapke paas: `/api/catalogue`, `/api/admin/catalogue`)
- `/api/webhooks/bank`            (aapke paas: `/api/webhook/bank`)
- `/api/admin/payments`, `/api/admin/sessions`, `/api/admin/me`, 2FA & password routes
- order me `access_key`, client-side `status`/`id`  (aapke paas: `access_hash`, server-side)

Iska matlab **`npm test` chalaoge to bahut saare test FAIL honge** — isliye nahi ki
server kharab hai, balki isliye ki test file kisi dusre (zyada bade) version ke liye
likhi gayi thi.

Maine ise **jaan-bujhkar waise hi chhoda** hai. Ise sahi karne ke 2 raaste hain, aur
mujhe aapse confirm karna hai ki **konsa version sahi/final hai**:

- **(A)** Aapka `server.js` hi final hai → main `run-tests.js` ko is server ke hisaab
  se dobara likh dunga.
- **(B)** `run-tests.js` wala bada version chahiye → tab `server.js` me bahut saare
  naye features (2FA, sessions, payments ledger, site versioning, access_key flow)
  add karne honge — ye bada kaam hai.

Bata do A ya B — main utna fix kar dunga. Maine khud se andaza lagakar aapka server
badalna theek nahi samjha.

---

**Summary:** Blank-site ka asli ilaaj = `render.yaml` ka persistent disk (paid plan).
Baaki structure + healthcheck fix ho chuke hain. public/ folder aur test-version ka
decision aap par hai.
