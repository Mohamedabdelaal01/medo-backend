# ربط Claude Desktop بـ CRM عبر MCP

السيرفر `mcp-server.js` بيوصّل Claude Desktop بقاعدة بيانات الـ CRM **للقراءة فقط**
(read-only) — Claude يقدر يحلّل ويسأل البيانات، لكن **مايقدرش يعدّل أو يمسح أي حاجة**.

## خطوات الربط

1. تأكد إن الباكدچ متثبّتة (مرة واحدة):

   ```bash
   cd "/Users/mohamed/Documents/last project/backend"
   npm install
   ```

2. افتح ملف إعدادات Claude Desktop:

   - **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

3. الصق المقطع ده جوّه الملف (لو الملف فاضي ابدأ به؛ لو فيه `mcpServers` بالفعل
   ضيف بس المفتاح `grand-furniture-crm` جواه):

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

   > لو نقلت المشروع لمكان تاني، عدّل المسار في `args`.
   > اختياري: تقدر تحدّد قاعدة بيانات معيّنة عبر `"env": { "DB_PATH": "/full/path/grand_furniture.db" }`.

4. اقفل Claude Desktop وافتحه تاني — هتلاقي السيرفر `grand-furniture-crm` ظهر
   في قائمة الأدوات (🔌).

## الأدوات المتاحة لـ Claude

| الأداة | الوظيفة |
|---|---|
| `get_branch_kpis` | مبيعات الفرع + عدد الزيارات + نسبة تحقيق المستهدف لشهر معيّن. |
| `get_lost_leads` | العملاء الباردين/المغلقين، مع فلترة بمصدر الحملة أو الفئة. |
| `run_readonly_sql` | تنفيذ أي استعلام `SELECT` حر على القاعدة (قراءة فقط). |

## الأمان

- الاتصال بقاعدة البيانات **read-only** بالكامل — أي محاولة كتابة بيرفضها SQLite نفسه.
- أداة `run_readonly_sql` بترفض أي استعلام لا يبدأ بـ `SELECT`، وبتحجب أي
  كلمة تعديل (`INSERT/UPDATE/DELETE/DROP/ALTER/REPLACE/...`).
- السيرفر طبقة منفصلة تماماً — مايلمسش `server.js` ولا `db.js` ولا أي كود قائم.
