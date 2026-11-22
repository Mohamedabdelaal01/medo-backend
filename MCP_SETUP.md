# ربط Claude Desktop بـ CRM عبر MCP (قراءة + كتابة)

السيرفر `mcp-server.js` بيوصّل Claude Desktop بقاعدة بيانات الـ CRM في وضع
**قراءة وكتابة** — Claude يقدر يحلّل البيانات **و** ينفّذ تعديلات جماعية
(إصلاح سجلات قديمة، تحديثات، إلخ).

> ⚠️ **تحذير مهم:** الوضع ده بيدّي الذكاء الاصطناعي صلاحية تعديل/حذف بيانات
> الإنتاج فعلياً. **اعمل نسخة احتياطية من `grand_furniture.db` قبل أي عملية
> تعديل جماعية** — وراجع جملة `WHERE` في أي استعلام كتابة قبل تنفيذه.

## خطوات الربط

1. تأكد إن الباكدچ متثبّتة (مرة واحدة):

   ```bash
   cd "/Users/mohamed/Documents/last project/backend"
   npm install
   ```

2. افتح ملف إعدادات Claude Desktop:

   - **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

3. الصق المقطع ده جوّه الملف (لو فيه `mcpServers` بالفعل ضيف بس المفتاح
   `grand-furniture-crm` جواه):

   ```json
   {
     "mcpServers": {
       "grand-furniture-crm": {
         "command": "node",
         "args": ["/Users/mohamed/Documents/last project/backend/mcp-server.js"]
       }
     }
   }
   ```

   > لو نقلت المشروع، عدّل المسار في `args`.
   > اختياري: حدّد قاعدة بيانات معيّنة عبر `"env": { "DB_PATH": "/full/path/grand_furniture.db" }`.

4. اقفل Claude Desktop وافتحه تاني — هتلاقي السيرفر `grand-furniture-crm`
   ظهر في قائمة الأدوات (🔌).

## الأدوات المتاحة لـ Claude

| الأداة | الوضع | الوظيفة |
|---|---|---|
| `get_branch_kpis`    | قراءة  | مبيعات الفرع + عدد الزيارات + المستهدف لشهر معيّن. |
| `get_leads_by_status`| قراءة  | قائمة العملاء (id/name/phone/class) للفلترة بالمندوب أو التصنيف. |
| `run_select_sql`     | قراءة  | استعلام `SELECT` واحد، على اتصال للقراءة بس. |
| `execute_write_sql`  | **مقفولة** | من المرحلة 0 (2026-11-22) الأداة لسه موجودة بالاسم بس **مش بتكتب أي حاجة**: أي طلب بيرجع رسالة «أداة الكتابة مقفولة» ومفيش صف بيتغيّر. أي تعديل في البيانات يتعمل من السيستم نفسه. |

## الأمان والحدود

- **الكتابة مقفولة**: `execute_write_sql` مقفولة في الاتنين — `mcp-server.js`
  (على الجهاز) وسيرفر MCP جوه `server.js` (`/api/mcp/sse`). مفيش طريقة من MCP
  تعمل `INSERT / UPDATE / DELETE`.
- `run_select_sql` بتشتغل على اتصال مفتوح للقراءة بس (`readonly` + `query_only`)،
  وبترفض جدول `settings` (المفاتيح)، و`password_hash`، وسجل التدقيق، وجداول
  هيكل قاعدة البيانات، وأي أمر غير `SELECT` (`services/sqlGuard.js`).
- السيرفر طبقة منفصلة تماماً — مايلمسش `server.js` ولا `db.js` ولا أي كود قائم.
