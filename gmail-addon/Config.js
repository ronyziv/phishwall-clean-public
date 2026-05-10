// ---------------------------------------------------------------------------
// PhishWall add-on configuration.
// API_URL must point at your deployed FastAPI /scan endpoint. The placeholder
// below is intentional — see README.md / docs/getting-started.md.
// ---------------------------------------------------------------------------

const API_URL = "https://YOUR_PUBLIC_HOST_HERE/scan";

const APP_NAME = "PhishWall";
const APP_SUBTITLE = "Email safety scan";
const APP_LOGO_URL = "https://drive.google.com/uc?export=view&id=1B0pLLT7MDD8mK_n7crhnHrV3pLD0JuKz";

// Three-way language toggle. Stored per-user via PropertiesService (see UiService).
const LANG_HE = "he";
const LANG_EN = "en";
const LANG_ES = "es";
const DEFAULT_LANG = LANG_EN;

// Random rotation of safety tips shown on the home card and after each scan.
const TIPS = {
  en: [
    "Do not open unexpected attachments, especially .zip, .exe, .js, or Office files asking to enable macros.",
    "Check the sender carefully. A familiar display name does not guarantee a safe email address.",
    "Hover over links before clicking. A trusted-looking message can still lead to a suspicious website.",
    "Be careful with urgent messages asking you to act immediately, reset a password, or send payment.",
    "If something feels off, open the service manually in your browser instead of using the email link."
  ],
  he: [
    "קבצים מצורפים לא צפויים — במיוחד .zip, .exe, .js ומסמכי Office עם מאקרו — אל תפתחו.",
    "שם תצוגה מוכר לא מבטיח שהכתובת באמת שייכת למי שכתוב.",
    "לפני לחיצה — בדקו לאן הקישור מוביל. גם מייל שנראה תקין עלול לכוון לאתר חשוד.",
    "הודעות דוחקות (איפוס סיסמה, תשלום, פעולה מיידית) — רגע של בדיקה לפני המשך.",
    "אם משהו מרגיש לא נכון, היכנסו לשירות בכתובת הרגילה דרך הדפדפן, לא דרך הקישור במייל."
  ],
  es: [
    "No abras adjuntos inesperados — especialmente .zip, .exe, .js o documentos de Office con macros.",
    "Un nombre conocido no garantiza que la dirección sea legítima.",
    "Antes de hacer clic, revisa a dónde lleva el enlace. Un correo de aspecto confiable puede llevar a un sitio sospechoso.",
    "Cuidado con mensajes urgentes (restablecer contraseña, pago, acción inmediata) — verifica antes.",
    "Si algo no parece bien, entra al servicio por el navegador en la dirección habitual, no por el enlace del correo."
  ]
};