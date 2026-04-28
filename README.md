# 🛋️ Grand Furniture Backend
## Node.js + Express + SQLite — Webhook Receiver & Lead Scoring API

---

## ⚡ تشغيل سريع (5 دقايق)

### 1. تحميل الـ Dependencies
```bash
npm install
```

### 2. إعداد ملف البيئة
```bash
cp .env.example .env
# افتح .env وعدّل الإعدادات لو محتاج
```

### 3. تشغيل السيرفر
```bash
# للتطوير (بيعيد التشغيل تلقائياً)
npm run dev

# للإنتاج
npm start
```

### 4. تأكد إن السيرفر شغال
```bash
curl http://localhost:3000/health
# المفروض يرجع: {"status":"ok","timestamp":"..."}
```

---

## 📡 API Endpoints

| Method | Endpoint | الوصف |
|---|---|---|
| `POST` | `/api/events` | استقبال webhook من ManyChat |
| `GET` | `/api/dashboard` | كل إحصائيات الداشبورد |
| `GET` | `/api/leads` | قائمة الـ leads مع فلترة |
| `GET` | `/api/leads/:user_id` | بروفايل مستخدم + تاريخ أحداثه |
| `GET` | `/health` | حالة السيرفر |

---

## 🧪 اختبار الـ Webhook يدوياً

```bash
# اختبار event عادي
curl -X POST http://localhost:3000/api/events \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "test_user_001",
    "first_name": "أحمد",
    "event_type": "product_details",
    "event_value": "bedroom_01",
    "session_count": 1,
    "current_score": 0
  }'

# اختبار location request (أعلى intent)
curl -X POST http://localhost:3000/api/events \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "test_user_001",
    "first_name": "أحمد",
    "event_type": "location_request",
    "event_value": "bedroom_01",
    "session_count": 1,
    "current_score": 20
  }'

# عرض الداشبورد
curl http://localhost:3000/api/dashboard

# عرض بروفايل المستخدم
curl http://localhost:3000/api/leads/test_user_001

# عرض كل الـ hot leads
curl "http://localhost:3000/api/leads?class=hot"
```

---

## 🚀 النشر على الإنترنت (مجاناً)

### خيار 1: Railway.app (الأسهل)
```bash
# 1. اعمل حساب على railway.app
# 2. ارفع المشروع من GitHub
# 3. Railway هيعمل deploy تلقائياً
# 4. هتاخد URL زي: https://grand-furniture.railway.app
```

### خيار 2: Render.com
```bash
# 1. اعمل حساب على render.com
# 2. New Web Service → Connect GitHub repo
# 3. Build Command: npm install
# 4. Start Command: npm start
# 5. هتاخد URL تاني تحطه في ManyChat
```

---

## 🔗 ربط ManyChat بالـ Backend

في كل زر في ManyChat:
1. اضغط **Add Action**
2. اختار **Send to External URL (Webhook)**
3. Method: **POST**
4. URL: `https://YOUR-URL.com/api/events`
5. Body Type: **JSON**
6. الـ Body:
```json
{
  "user_id": "{{user_id}}",
  "first_name": "{{first name}}",
  "event_type": "REPLACE_WITH_EVENT_TYPE",
  "event_value": "REPLACE_WITH_EVENT_VALUE",
  "session_count": "{{session_count}}",
  "current_score": "{{lead_score}}"
}
```

---

## 📊 هيكل قاعدة البيانات

```
grand_furniture.db
├── events          — كل حدث من كل مستخدم
└── lead_profiles   — بروفايل مجمّع لكل مستخدم
```

---

## 🎯 نظام التسجيل

| Event | نقاط |
|---|---|
| دخل فلو الكتالوج | +5 |
| دخل فلو العرض | +5 |
| دخل فلو الفروع | +10 |
| شاف تفاصيل منتج | +20 |
| طلب location | +40 |
| طلب تواصل | +15 |
| اختار فرع محدد | +30 |
| ضغط خريطة Google | +25 (bonus) |
| شاف نفس المنتج مرتين | +10 (bonus) |
| أكد الزيارة | +100 |

| التصنيف | النقاط |
|---|---|
| 🔵 Cold | 0–30 |
| 🟡 Warm | 31–74 |
| 🔴 Hot | 75–149 أو طلب location |
| ✅ Converted | 150+ أو أكد الزيارة |
