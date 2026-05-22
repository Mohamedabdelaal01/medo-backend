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
| `run_select_sql`     | قراءة  | تنفيذ أي استعلام `SELECT`. |
| `execute_write_sql`  | **كتابة** | تنفيذ `INSERT / UPDATE / DELETE` لإصلاح أو تعديل البيانات. |

## الأمان والحدود

- `execute_write_sql` بتقبل عمليات `INSERT / UPDATE / DELETE / REPLACE` فقط،
  وبتحجب أوامر تعديل الهيكل (`DROP / ALTER / TRUNCATE / ATTACH`) لحماية
  بنية قاعدة البيانات.
- كل عملية كتابة بتتسجّل في الـ stderr مع عدد الصفوف المتأثّرة (سجل تدقيق).
- السيرفر طبقة منفصلة تماماً — مايلمسش `server.js` ولا `db.js` ولا أي كود قائم.
