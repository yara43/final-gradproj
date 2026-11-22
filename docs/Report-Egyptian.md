# تقرير تعديل Brand Impersonation في PhishGuard
## ١. بنحاول نعرف إيه؟
تخيّلي إنك فتحتي مقال اسمه “How to use Facebook”. تحت المقال فيه تسجيل دخول للمشتركين في الجريدة. الصفحة ذكرت Facebook، لكن مين اللي طلب الباسورد؟ الجريدة. لو نفس الفورم مكتوب جواه “Sign in to Facebook”، والدومين بتاع الجريدة، هنا ظهر تعارض يستاهل تنبيه. ده اسمه brand mismatch: اختلاف بين الهوية اللي الصفحة بتدّعيها وصاحب عنوان الموقع. هو دليل خطر، مش إثبات إن باسورد اتسرق.
## ٢. المعلومة بتمشي إزاي؟
Chrome بيشغّل extension/content/contentScript.js جوّه الصفحة. السكريبت بيحدد كل form لوحده، وهل فيه password أو OTP (كود تحقق)، وبياخد عينة محدودة من العناوين والأزرار والـlabels جوّاه، من غير قراءة القيمة اللي المستخدم كتبها. extension/background/serviceWorker.js بيستلم الرسالة ويمرر البيانات لمحرك القرار. src/core/engine/brandIdentity.ts هو مصدر منطق الهوية، وextension/engine/brandIdentity.js هو الملف اللي Chrome بيشغله. riskScoring بيجمع نتيجة الهوية مع أدلة مستقلة زي بيانات الدفع ووجهة الفورم.
## ٣. التغييرات وأثر كل واحد
1. المقال وفورم المشتركين: قبل كده عنوان الصفحة وخانة الباسورد كانوا ممكن يتفهموا كأنهم مرتبطين. دلوقتي اسم Facebook في مقال مش كفاية، لكن طلب الدخول باسم Facebook داخل نفس الفورم الحساس دليل أقوى. عشان كده تعديل المحرك لوحده ماكانش كفاية: لو السكريبت بعت “فيه باسورد” بس، المحرك مش هيعرف مين اللي طلبه.
2. وسائل الدفع: عنوان فرعي PayPal تحت Payment methods ممكن يكون مجرد اختيار دفع. دلوقتي العناوين الفرعية تسجل ذكر البراند؛ مش دليل انتحال بمفردها. عنوان صفحة مطابق لاسم براند معروف يفضل دليل مستقل، فمش معنى التغيير إن كل ذكر للبراند بيتجاهله الكود.
3. صاحب الدومين غير البراند المذكور. بوست على facebook.com عنوانه PayPal: صاحب الدومين Meta، والبراند المذكور PayPal. بنحدد الاتنين بصورة منفصلة. لو الفورم نفسه بيطلب دخول باسم جهة تانية، المحرك يقدر يحتفظ بصاحب الدومين ويرجع ادعاء الجهة التانية؛ مش بيختار أول اسم قابله في الليست.
4. جهة مجهولة: Student Services وصف للصفحة، مش إثبات إن فيه شركة اسمها كده تملك دومين .com. شلنا تخمين الدومين. null معناها «ما عنديش هوية موثقة أقارن بيها»؛ مش معناها الموقع آمن. في اختبار المتجر، طلب الكارت لسه طلع FINANCIAL_DATA_COLLECTION. الدرجة نزلت لـ25 بعد اختفاء ادعاء الانتحال؛ حدّثنا النتيجة المتوقعة واختبرنا وجود دليل الدفع وغياب دليل البراند مع بعض.
5. X / Twitter: ضفنا x.com وtwitter.com كسجلات رسمية. X لوحدها على صفحة غير معروفة مش دليل كفاية لأنها حرف شائع. لكن Sign in to X داخل فورم باسورد له سياق مختلف.
6. Static hosting: معناها المنصة بتستضيف صفحات؛ مش معناها إن المنصة كتبت كل صفحة عليها. في demo.github.io، GitHub Pages هي المضيف وdemo اسم المساحة المستضافة. الفصل ده يمنع اعتبار الصفحة رسمية لمجرد اسم GitHub، ويمنع اعتبار github في اسم المنصة محاولة تقليد. نفس القاعدة بتشتغل مع المنصات المسجلة زي Netlify وVercel. وجود استضافة مشتركة لوحده مش تهمة؛ صفحة شخصية عادية ينفع تعدّي، وصفحة بتدّعي براند معروف تتقيّم.
## ٤. إيه اللي اضطرينا نعدله مع القرار؟
src/core/types.ts وengine/formAnalysis.ts بقوا يوصفوا معلومات كل فورم، وevents/pageEvents.ts بقى يستقبلها. الـservice worker اتظبط عشان يبعت objects بالشكل اللي دوال الأحداث متوقعاه، يستخدم recordEvent، ويرجّع analysis للـcontent script. riskScoring مبقاش يقلّل درجة ادعاء مخالف لمجرد إن صاحب الدومين معروف. عدّلنا typosquatting كمان عشان ما يرجعش الثقة للمنصة من طريق تاني.
## ٥. الاختبار وحدوده
شغّلنا node scripts/test-brand-review.mjs من فولدر المشروع باستخدام Node 24. نجحت 10 مجموعات جديدة و18/18 من سيناريوهات المشروع بعد تحديث توقع المتجر الموضح فوق. جرّبنا المقال وفورم المشتركين، فورم باسم براند، وسيلة دفع، قلب ترتيب الليست، جامعة مجهولة، X، واستضافة مشتركة. اختبار الربط بعت رسالة للـworker باستخدام Chrome APIs بديلة محليًا؛ ده مش اختبار يدوي على Chrome ولا قياس latency. المحرك بيعتمد على نصوص وقائمة جهات ومنصات معروفة؛ مش بيحلل اللوجو بصريًا، وسياقات أو لغات تانية ممكن تفوته. ومسار الـallowlist الحالي ممكن يرجع SAFE قبل فحص البراند.

## ٦. الكود الحقيقي: قبل وبعد (مقتطفات من ملفات القرار)
**Before — upstream 348f3be:**
~~~ts
const isCanonical = brand.canonicalDomains.some(d => cleanHostname === d || cleanHostname.endsWith('.' + d));
if (pageTitle && (pageTitle.toLowerCase().includes(brand.name.toLowerCase()) || brand.keywords.some(k => pageTitle.toLowerCase().includes(k)))) {
if (visibleTokens.some(t => t.toLowerCase() === brand.name.toLowerCase() || brand.keywords.includes(t.toLowerCase()))) {
if (pageTitle && pageTitle.trim().length > 2) {
const inferredCanonical = `${inferredClean}.com`;
~~~
**After — local implementation:**
~~~ts
const tenant = provider ? host.slice(0, -(provider.length + 1)) : host;
const labels = (formMeta?.suspiciousForms || []).filter(f => f.hasPasswordField || f.has2FAField).flatMap(f => f.identityLabels || []).map(norm);
const formClaim = labels.some(t => names.some(n => login(t,n) || (n.length > 1 && t === n)));
const titleClaim = names.some(n => login(title,n) || (n.length > 1 && title === n));
const official = !provider && brand.canonicalDomains.some(d => host === d || host.endsWith('.'+d));
const owner = rows.find(r => r.official);
const row = rows.find(r => r.formClaim && r !== owner) || owner || rows.find(r => r.formClaim) || rows.find(r => r.titleClaim) || rows.find(r => r.hostMatch);
if (!row) return null; // Unknown identity: no verified domain to compare against.
~~~
اقريها بالترتيب: tenant يفصل المستأجر عن المضيف؛ labels يجمع كلام كل فورم حساس؛ formClaim وtitleClaim يختبروا ادّعاء الهوية؛ official وowner يحددوا صاحب الدومين؛ row يختار الدليل الأقوى؛ null يمتنع عن الحكم. [كل التغييرات سطر بسطر](before-after.diff): علامة − للكود القديم و+ للجديد.
