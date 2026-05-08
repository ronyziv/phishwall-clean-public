const API_URL = "https://dispense-why-glamour.ngrok-free.dev/scan";

const APP_NAME = "PhishWall";
const APP_SUBTITLE = "Malicious Email Analysis";
const APP_LOGO_URL = "https://drive.google.com/uc?export=view&id=1B0pLLT7MDD8mK_n7crhnHrV3pLD0JuKz";

const LANG_HE = "he";
const LANG_EN = "en";
const LANG_ES = "es";
const DEFAULT_LANG = LANG_EN;

const TIPS = {
  en: [
    "Do not open unexpected attachments, especially .zip, .exe, .js, or Office files asking to enable macros.",
    "Check the sender carefully. A familiar display name does not guarantee a safe email address.",
    "Hover over links before clicking. A trusted-looking message can still lead to a suspicious website.",
    "Be careful with urgent messages asking you to act immediately, reset a password, or send payment.",
    "If something feels off, open the service manually in your browser instead of using the email link."
  ],
  he: [
    "אל תפתחי קבצים מצורפים לא צפויים, במיוחד קבצי ‎.zip‎, ‎.exe‎, ‎.js‎ או מסמכי Office שמבקשים להפעיל מאקרו.",
    "בדקי היטב את השולח. שם מוכר לא אומר שכתובת המייל באמת בטוחה.",
    "לפני לחיצה על קישור, בדקי לאן הוא מוביל. גם מייל שנראה אמין יכול להפנות לאתר חשוד.",
    "היזהרי מהודעות לחוצות שמבקשות לפעול מיד, לאפס סיסמה או לבצע תשלום.",
    "אם משהו מרגיש לא תקין, היכנסי לשירות ידנית דרך הדפדפן במקום דרך הקישור שבמייל."
  ],
  es: [
    "No abras archivos adjuntos inesperados, especialmente .zip, .exe, .js o documentos de Office que pidan habilitar macros.",
    "Verifica bien al remitente. Un nombre conocido no garantiza que la dirección de correo sea segura.",
    "Antes de hacer clic en un enlace, revisa a dónde dirige. Un correo que parece confiable puede llevar a un sitio sospechoso.",
    "Ten cuidado con mensajes urgentes que te piden actuar de inmediato, restablecer una contraseña o enviar un pago.",
    "Si algo parece extraño, abre el servicio manualmente en el navegador en lugar de usar el enlace del correo."
  ]
};