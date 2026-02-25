import json, os, base64, secrets, threading, string, pyperclip
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import customtkinter as ctk
from tkinter import messagebox

VAULT_FILE      = "vault.json"
SALT_FILE       = "salt.bin"
SETTINGS_FILE   = "settings.json"
PBKDF2_ITERS    = 480_000
CLIPBOARD_CLEAR = 30

BG, SURFACE, SURFACE2 = "#0f1117", "#1a1d27", "#22263a"
ACCENT, ACCENT2       = "#4f8ef7", "#6c63ff"
DANGER, SUCCESS       = "#e05c5c", "#3ec98a"
TEXT, MUTED, BORDER   = "#e8eaf0", "#6b7280", "#2d3148"

TRANSLATIONS = {
    "en": {
        "app_title": "🔐  Password Manager", "app_window": "🔐  Local Password Manager",
        "new_vault": "Create a new vault", "unlock_vault": "Unlock your vault",
        "master_pwd": "Master Password", "confirm_pwd": "Confirm Password",
        "ph_master": "Enter master password...", "ph_confirm": "Repeat master password...",
        "btn_create": "Create Vault 🔑", "btn_unlock": "Unlock 🔓",
        "hint": "🛡  Your password is never stored — only an encrypted key",
        "err_empty": "⚠  Field cannot be empty.", "err_short": "⚠  Minimum 8 characters.",
        "err_mismatch": "⚠  Passwords do not match!", "err_wrong_pwd": "⚠  Incorrect master password!",
        "dashboard_title": "  🔐  Password Manager", "total": "Total: {}",
        "new_entry": "➕  New Password", "lbl_site": "Site / App Name",
        "lbl_user": "Username / Email", "lbl_pwd": "Password",
        "ph_site": "e.g. GitHub", "ph_user": "user@email.com", "ph_pwd": "••••••••",
        "btn_generate": "🎲  Generate Password", "btn_add": "✚  Add Password",
        "add_ok": "✔  Password added!", "err_fields": "⚠  All fields are required!",
        "generated": "🎲  Password generated!", "search_ph": "Search vault...",
        "empty_vault": "🗄  Vault is empty.", "no_results": "🗄  No passwords found.",
        "show": "👁 Show", "hide": "🙈 Hide", "copy": "📋 Copy", "delete": "🗑 Delete",
        "copy_title": "Copied!", "copy_msg": "Password for '{}' copied.\nAuto-cleared in {}s.",
        "del_title": "Confirm Delete", "del_msg": "Delete entry for '{}'?",
    },
    "sr": {
        "app_title": "🔐  Menadžer Lozinki", "app_window": "🔐  Lokalni Menadžer Lozinki",
        "new_vault": "Kreiranje novog trezora", "unlock_vault": "Otključaj trezor",
        "master_pwd": "Master Lozinka", "confirm_pwd": "Potvrdi Lozinku",
        "ph_master": "Unesi master lozinku...", "ph_confirm": "Ponovi master lozinku...",
        "btn_create": "Kreiraj Trezor 🔑", "btn_unlock": "Otključaj 🔓",
        "hint": "🛡  Lozinka se nikad ne čuva — samo enkriptovani ključ",
        "err_empty": "⚠  Polje je prazno.", "err_short": "⚠  Minimum 8 znakova.",
        "err_mismatch": "⚠  Lozinke se ne poklapaju!", "err_wrong_pwd": "⚠  Pogrešna master lozinka!",
        "dashboard_title": "  🔐  Menadžer Lozinki", "total": "Ukupno: {}",
        "new_entry": "➕  Nova Lozinka", "lbl_site": "Naziv sajta / aplikacije",
        "lbl_user": "Username / Email", "lbl_pwd": "Lozinka",
        "ph_site": "npr. GitHub", "ph_user": "korisnik@email.com", "ph_pwd": "••••••••",
        "btn_generate": "🎲  Generiši lozinku", "btn_add": "✚  Dodaj lozinku",
        "add_ok": "✔  Dodano!", "err_fields": "⚠  Sva polja su obavezna!",
        "generated": "🎲  Lozinka generisana!", "search_ph": "Pretraži trezor...",
        "empty_vault": "🗄  Trezor je prazan.", "no_results": "🗄  Nema lozinki.",
        "show": "👁 Prikaži", "hide": "🙈 Sakrij", "copy": "📋 Kopiraj", "delete": "🗑 Obriši",
        "copy_title": "Kopirano!", "copy_msg": "Lozinka za '{}' kopirana.\nBriše se posle {}s.",
        "del_title": "Potvrdi brisanje", "del_msg": "Obrisati '{}'?",
    },
    "es": {
        "app_title": "🔐  Gestor de Contraseñas", "app_window": "🔐  Gestor de Contraseñas Local",
        "new_vault": "Crear nueva bóveda", "unlock_vault": "Desbloquear bóveda",
        "master_pwd": "Contraseña Maestra", "confirm_pwd": "Confirmar Contraseña",
        "ph_master": "Introduce contraseña maestra...", "ph_confirm": "Repite la contraseña maestra...",
        "btn_create": "Crear Bóveda 🔑", "btn_unlock": "Desbloquear 🔓",
        "hint": "🛡  Tu contraseña nunca se guarda — solo una clave cifrada",
        "err_empty": "⚠  El campo está vacío.", "err_short": "⚠  Mínimo 8 caracteres.",
        "err_mismatch": "⚠  Las contraseñas no coinciden!", "err_wrong_pwd": "⚠  Contraseña maestra incorrecta!",
        "dashboard_title": "  🔐  Gestor de Contraseñas", "total": "Total: {}",
        "new_entry": "➕  Nueva Contraseña", "lbl_site": "Sitio / App",
        "lbl_user": "Usuario / Email", "lbl_pwd": "Contraseña",
        "ph_site": "ej. GitHub", "ph_user": "usuario@email.com", "ph_pwd": "••••••••",
        "btn_generate": "🎲  Generar Contraseña", "btn_add": "✚  Agregar Contraseña",
        "add_ok": "✔  ¡Agregado!", "err_fields": "⚠  Todos los campos son obligatorios!",
        "generated": "🎲  ¡Contraseña generada!", "search_ph": "Buscar en la bóveda...",
        "empty_vault": "🗄  La bóveda está vacía.", "no_results": "🗄  No se encontraron contraseñas.",
        "show": "👁 Mostrar", "hide": "🙈 Ocultar", "copy": "📋 Copiar", "delete": "🗑 Borrar",
        "copy_title": "¡Copiado!", "copy_msg": "Contraseña de '{}' copiada.\nSe borra en {}s.",
        "del_title": "Confirmar borrado", "del_msg": "¿Borrar entrada de '{}'?",
    },
    "de": {
        "app_title": "🔐  Passwort-Manager", "app_window": "🔐  Lokaler Passwort-Manager",
        "new_vault": "Neuen Tresor erstellen", "unlock_vault": "Tresor entsperren",
        "master_pwd": "Master-Passwort", "confirm_pwd": "Passwort bestätigen",
        "ph_master": "Master-Passwort eingeben...", "ph_confirm": "Master-Passwort wiederholen...",
        "btn_create": "Tresor erstellen 🔑", "btn_unlock": "Entsperren 🔓",
        "hint": "🛡  Dein Passwort wird nie gespeichert — nur ein verschlüsselter Schlüssel",
        "err_empty": "⚠  Feld darf nicht leer sein.", "err_short": "⚠  Mindestens 8 Zeichen.",
        "err_mismatch": "⚠  Passwörter stimmen nicht überein!", "err_wrong_pwd": "⚠  Falsches Master-Passwort!",
        "dashboard_title": "  🔐  Passwort-Manager", "total": "Gesamt: {}",
        "new_entry": "➕  Neues Passwort", "lbl_site": "Website / App",
        "lbl_user": "Benutzername / E-Mail", "lbl_pwd": "Passwort",
        "ph_site": "z.B. GitHub", "ph_user": "benutzer@email.com", "ph_pwd": "••••••••",
        "btn_generate": "🎲  Passwort generieren", "btn_add": "✚  Passwort hinzufügen",
        "add_ok": "✔  Hinzugefügt!", "err_fields": "⚠  Alle Felder sind erforderlich!",
        "generated": "🎲  Passwort generiert!", "search_ph": "Tresor durchsuchen...",
        "empty_vault": "🗄  Tresor ist leer.", "no_results": "🗄  Keine Passwörter gefunden.",
        "show": "👁 Anzeigen", "hide": "🙈 Verbergen", "copy": "📋 Kopieren", "delete": "🗑 Löschen",
        "copy_title": "Kopiert!", "copy_msg": "Passwort für '{}' kopiert.\nWird in {}s gelöscht.",
        "del_title": "Löschen bestätigen", "del_msg": "Eintrag für '{}' löschen?",
    },
    "fr": {
        "app_title": "🔐  Gestionnaire de Mots de Passe", "app_window": "🔐  Gestionnaire Local de Mots de Passe",
        "new_vault": "Créer un nouveau coffre", "unlock_vault": "Déverrouiller le coffre",
        "master_pwd": "Mot de passe principal", "confirm_pwd": "Confirmer le mot de passe",
        "ph_master": "Entrez le mot de passe principal...", "ph_confirm": "Répétez le mot de passe principal...",
        "btn_create": "Créer le coffre 🔑", "btn_unlock": "Déverrouiller 🔓",
        "hint": "🛡  Votre mot de passe n'est jamais stocké — uniquement une clé chiffrée",
        "err_empty": "⚠  Le champ est vide.", "err_short": "⚠  Minimum 8 caractères.",
        "err_mismatch": "⚠  Les mots de passe ne correspondent pas!", "err_wrong_pwd": "⚠  Mot de passe principal incorrect!",
        "dashboard_title": "  🔐  Gestionnaire de Mots de Passe", "total": "Total : {}",
        "new_entry": "➕  Nouveau Mot de Passe", "lbl_site": "Site / Application",
        "lbl_user": "Nom d'utilisateur / Email", "lbl_pwd": "Mot de passe",
        "ph_site": "ex. GitHub", "ph_user": "utilisateur@email.com", "ph_pwd": "••••••••",
        "btn_generate": "🎲  Générer un mot de passe", "btn_add": "✚  Ajouter",
        "add_ok": "✔  Ajouté !", "err_fields": "⚠  Tous les champs sont obligatoires !",
        "generated": "🎲  Mot de passe généré !", "search_ph": "Rechercher dans le coffre...",
        "empty_vault": "🗄  Le coffre est vide.", "no_results": "🗄  Aucun mot de passe trouvé.",
        "show": "👁 Afficher", "hide": "🙈 Masquer", "copy": "📋 Copier", "delete": "🗑 Supprimer",
        "copy_title": "Copié !", "copy_msg": "Mot de passe de '{}' copié.\nEffacé dans {}s.",
        "del_title": "Confirmer la suppression", "del_msg": "Supprimer l'entrée de '{}' ?",
    },
}

LANG_OPTIONS = {"English": "en", "Srpski": "sr", "Español": "es", "Deutsch": "de", "Français": "fr"}
LANG_REVERSE = {v: k for k, v in LANG_OPTIONS.items()}


class Settings:
    _d = {"lang": "en"}

    @classmethod
    def load(cls):
        if os.path.exists(SETTINGS_FILE):
            try: cls._d = json.load(open(SETTINGS_FILE))
            except Exception: pass

    @classmethod
    def save(cls): json.dump(cls._d, open(SETTINGS_FILE, "w"))
    @classmethod
    def get_lang(cls) -> str: return cls._d.get("lang", "en")
    @classmethod
    def set_lang(cls, code: str): cls._d["lang"] = code; cls.save()


def t(key: str, *args) -> str:
    val = TRANSLATIONS.get(Settings.get_lang(), TRANSLATIONS["en"]).get(key, key)
    return val.format(*args) if args else val


class CryptoManager:
    def __init__(self, master: str, salt: bytes):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERS)
        self._f = Fernet(base64.urlsafe_b64encode(kdf.derive(master.encode())))

    def encrypt(self, data: str) -> str: return self._f.encrypt(data.encode()).decode()
    def decrypt(self, data: str) -> str: return self._f.decrypt(data.encode()).decode()
    def try_decrypt(self, data: str) -> str | None:
        try: return self.decrypt(data)
        except InvalidToken: return None


class VaultManager:
    def __init__(self, crypto: CryptoManager):
        self._c, self._e = crypto, []

    def load(self) -> bool:
        if not os.path.exists(VAULT_FILE): return True
        dec = self._c.try_decrypt(open(VAULT_FILE).read())
        if dec is None: return False
        self._e = json.loads(dec).get("entries", [])
        return True

    def save(self):
        open(VAULT_FILE, "w").write(self._c.encrypt(json.dumps({"entries": self._e})))

    def add(self, site: str, user: str, pwd: str):
        self._e.append({"id": secrets.token_hex(8), "site": self._c.encrypt(site),
                        "username": self._c.encrypt(user), "password": self._c.encrypt(pwd)})
        self.save()

    def delete(self, eid: str):
        self._e = [e for e in self._e if e["id"] != eid]; self.save()

    def all(self) -> list[dict]:
        return [{"id": e["id"], "site": self._c.decrypt(e["site"]),
                 "username": self._c.decrypt(e["username"]),
                 "password": self._c.decrypt(e["password"])} for e in self._e]


def load_salt() -> bytes:
    if os.path.exists(SALT_FILE): return open(SALT_FILE, "rb").read()
    salt = secrets.token_bytes(32); open(SALT_FILE, "wb").write(salt); return salt

def vault_exists() -> bool: return os.path.exists(VAULT_FILE) and os.path.exists(SALT_FILE)

def gen_password(n=20) -> str:
    pool = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    pwd  = [secrets.choice(c) for c in (string.ascii_uppercase, string.ascii_lowercase,
                                         string.digits, "!@#$%^&*-_=+")] + \
           [secrets.choice(pool) for _ in range(n - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

def _lang_menu(parent, cmd) -> ctk.CTkOptionMenu:
    m = ctk.CTkOptionMenu(parent, values=list(LANG_OPTIONS.keys()), command=cmd,
                          fg_color=SURFACE2, button_color=ACCENT, button_hover_color="#3a7de0",
                          text_color=TEXT, dropdown_fg_color=SURFACE,
                          dropdown_hover_color=SURFACE2, width=130, height=32,
                          font=ctk.CTkFont(size=12))
    m.set(LANG_REVERSE.get(Settings.get_lang(), "English"))
    return m

def _entry(parent, ph, row, show="") -> ctk.CTkEntry:
    e = ctk.CTkEntry(parent, placeholder_text=ph, show=show, height=40, corner_radius=8,
                     fg_color=SURFACE2, border_color=BORDER, text_color=TEXT,
                     font=ctk.CTkFont(size=13))
    e.grid(row=row, column=0, sticky="ew", padx=20, pady=(4, 14))
    return e


class PasswordRow(ctk.CTkFrame):
    def __init__(self, parent, entry: dict, on_delete, index: int, **kw):
        super().__init__(parent, **kw)
        self._e, self._on_delete, self._shown = entry, on_delete, False
        self.configure(fg_color=SURFACE if index % 2 == 0 else SURFACE2, corner_radius=10)
        self._build()

    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(self, text=self._e["site"][:2].upper(), width=40, height=40,
                     fg_color=ACCENT2, corner_radius=8,
                     font=ctk.CTkFont(size=15, weight="bold"),
                     text_color=TEXT).grid(row=0, column=0, rowspan=2, padx=10, pady=8)
        ctk.CTkLabel(self, text=self._e["site"],
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=TEXT, anchor="w").grid(row=0, column=1, sticky="ew", padx=(0, 10), pady=(8, 0))
        ctk.CTkLabel(self, text=f"👤  {self._e['username']}",
                     font=ctk.CTkFont(size=12), text_color=MUTED,
                     anchor="w").grid(row=1, column=1, sticky="ew", padx=(0, 10), pady=(0, 8))
        self._pv = ctk.StringVar(value="••••••••••••")
        ctk.CTkLabel(self, textvariable=self._pv, font=ctk.CTkFont(size=13, family="Courier"),
                     text_color=ACCENT, anchor="w").grid(row=0, column=2, rowspan=2, padx=10)
        bf = ctk.CTkFrame(self, fg_color="transparent")
        bf.grid(row=0, column=3, rowspan=2, padx=(0, 8))

        def btn(text, color, hover, cmd):
            b = ctk.CTkButton(bf, text=text, width=90, height=30, fg_color=color,
                              hover_color=hover, text_color="white" if color != SURFACE2 else TEXT,
                              corner_radius=6, font=ctk.CTkFont(size=12), command=cmd)
            b.pack(pady=3)
            return b

        self._eye = btn(t("show"), SURFACE2, BORDER, self._toggle)
        btn(t("copy"),   ACCENT,  "#3a7de0", self._copy)
        btn(t("delete"), DANGER,  "#c04040", self._delete)

    def _toggle(self):
        self._shown = not self._shown
        self._pv.set(self._e["password"] if self._shown else "••••••••••••")
        self._eye.configure(text=t("hide") if self._shown else t("show"))

    def _copy(self):
        pyperclip.copy(self._e["password"])
        tmr = threading.Timer(CLIPBOARD_CLEAR, lambda: pyperclip.copy(""))
        tmr.daemon = True; tmr.start()
        messagebox.showinfo(t("copy_title"), t("copy_msg", self._e["site"], CLIPBOARD_CLEAR))

    def _delete(self):
        if messagebox.askyesno(t("del_title"), t("del_msg", self._e["site"])):
            self._on_delete(self._e["id"])


class LoginScreen(ctk.CTkFrame):
    def __init__(self, parent, on_success, on_lang_change):
        super().__init__(parent, fg_color=BG)
        self._ok, self._lc, self._new = on_success, on_lang_change, not vault_exists()
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.place(relx=1.0, rely=0.0, anchor="ne", x=-20, y=16)
        ctk.CTkLabel(bar, text="🌐", font=ctk.CTkFont(size=16), text_color=MUTED).pack(side="left", padx=(0, 6))
        _lang_menu(bar, self._change_lang).pack(side="left")

        card = ctk.CTkFrame(self, fg_color=SURFACE, corner_radius=20, width=440)
        card.grid(row=0, column=0, padx=40, pady=40, ipadx=30, ipady=30)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card, text="🔐", font=ctk.CTkFont(size=64)).grid(row=0, column=0, pady=(30, 10))
        ctk.CTkLabel(card, text=t("app_title"), font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=TEXT).grid(row=1, column=0, pady=(0, 4))
        ctk.CTkLabel(card, text=t("new_vault" if self._new else "unlock_vault"),
                     font=ctk.CTkFont(size=14), text_color=MUTED).grid(row=2, column=0, pady=(0, 30))
        ctk.CTkFrame(card, height=1, fg_color=BORDER).grid(row=3, column=0, sticky="ew", padx=30, pady=(0, 20))

        def lbl_field(row, lbl_key, ph_key):
            ctk.CTkLabel(card, text=t(lbl_key), font=ctk.CTkFont(size=13),
                         text_color=MUTED, anchor="w").grid(row=row, column=0, sticky="ew", padx=30)
            e = ctk.CTkEntry(card, placeholder_text=t(ph_key), show="●", height=44, corner_radius=10,
                             fg_color=SURFACE2, border_color=BORDER, text_color=TEXT,
                             font=ctk.CTkFont(size=14))
            e.grid(row=row + 1, column=0, sticky="ew", padx=30, pady=(4, 14))
            return e

        self._pwd = lbl_field(4, "master_pwd", "ph_master")
        self._pwd.bind("<Return>", lambda _: self._submit())
        self._confirm = None
        if self._new:
            self._confirm = lbl_field(6, "confirm_pwd", "ph_confirm")
            self._confirm.bind("<Return>", lambda _: self._submit())

        self._err = ctk.CTkLabel(card, text="", font=ctk.CTkFont(size=12), text_color=DANGER)
        self._err.grid(row=8, column=0, pady=(0, 6))
        ctk.CTkButton(card, text=t("btn_create" if self._new else "btn_unlock"),
                      height=46, corner_radius=12, fg_color=ACCENT, hover_color="#3a7de0",
                      font=ctk.CTkFont(size=15, weight="bold"),
                      command=self._submit).grid(row=9, column=0, sticky="ew", padx=30, pady=(4, 30))
        ctk.CTkLabel(card, text=t("hint"), font=ctk.CTkFont(size=11),
                     text_color=MUTED).grid(row=10, column=0, pady=(0, 20))
        self._pwd.focus()

    def _change_lang(self, name: str):
        Settings.set_lang(LANG_OPTIONS.get(name, "en")); self._lc()

    def _submit(self):
        pwd = self._pwd.get().strip()
        if not pwd: return self._err.configure(text=t("err_empty"))
        if len(pwd) < 8: return self._err.configure(text=t("err_short"))
        if self._new and pwd != self._confirm.get().strip():
            return self._err.configure(text=t("err_mismatch"))
        crypto = CryptoManager(pwd, load_salt())
        vault  = VaultManager(crypto)
        if vault.load(): self._ok(vault)
        else: self._err.configure(text=t("err_wrong_pwd"))


class Dashboard(ctk.CTkFrame):
    def __init__(self, parent, vault: VaultManager, on_lang_change):
        super().__init__(parent, fg_color=BG)
        self._vault, self._lc = vault, on_lang_change
        self._build(); self._refresh()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(self, fg_color=SURFACE, height=64, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew"); hdr.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(hdr, text=t("dashboard_title"),
                     font=ctk.CTkFont(size=20, weight="bold"),
                     text_color=TEXT).grid(row=0, column=0, padx=20, pady=16, sticky="w")
        self._count = ctk.CTkLabel(hdr, text="", font=ctk.CTkFont(size=13), text_color=MUTED)
        self._count.grid(row=0, column=1, padx=20, sticky="e")
        lf = ctk.CTkFrame(hdr, fg_color="transparent")
        lf.grid(row=0, column=2, padx=(0, 16), pady=10)
        ctk.CTkLabel(lf, text="🌐", font=ctk.CTkFont(size=15), text_color=MUTED).pack(side="left", padx=(0, 6))
        _lang_menu(lf, self._change_lang).pack(side="left")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        body.grid_columnconfigure(1, weight=1); body.grid_rowconfigure(0, weight=1)
        self._build_form(body); self._build_list(body)

    def _build_form(self, parent):
        form = ctk.CTkFrame(parent, fg_color=SURFACE, corner_radius=16, width=320)
        form.grid(row=0, column=0, sticky="ns", padx=(0, 20))
        form.grid_columnconfigure(0, weight=1); form.grid_propagate(False)

        ctk.CTkLabel(form, text=t("new_entry"), font=ctk.CTkFont(size=16, weight="bold"),
                     text_color=TEXT).grid(row=0, column=0, pady=(24, 20), padx=20)
        ctk.CTkFrame(form, height=1, fg_color=BORDER).grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))

        def lf(row, lkey, phkey, show=""):
            ctk.CTkLabel(form, text=t(lkey), font=ctk.CTkFont(size=12),
                         text_color=MUTED, anchor="w").grid(row=row, column=0, sticky="ew", padx=20)
            return _entry(form, t(phkey), row + 1, show)

        self._fs = lf(2, "lbl_site", "ph_site")
        self._fu = lf(4, "lbl_user", "ph_user")
        self._fp = lf(6, "lbl_pwd",  "ph_pwd", show="●")

        ctk.CTkButton(form, text=t("btn_generate"), height=36, corner_radius=8,
                      fg_color=SURFACE2, hover_color=BORDER, text_color=MUTED,
                      font=ctk.CTkFont(size=12), command=self._gen).grid(
            row=8, column=0, sticky="ew", padx=20, pady=(0, 16))
        self._msg = ctk.CTkLabel(form, text="", font=ctk.CTkFont(size=12), text_color=DANGER)
        self._msg.grid(row=9, column=0, pady=(0, 4))
        ctk.CTkButton(form, text=t("btn_add"), height=44, corner_radius=10,
                      fg_color=ACCENT, hover_color="#3a7de0",
                      font=ctk.CTkFont(size=14, weight="bold"), command=self._add).grid(
            row=10, column=0, sticky="ew", padx=20, pady=(0, 24))

    def _build_list(self, parent):
        right = ctk.CTkFrame(parent, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_columnconfigure(0, weight=1); right.grid_rowconfigure(1, weight=1)

        sf = ctk.CTkFrame(right, fg_color=SURFACE, corner_radius=12, height=52)
        sf.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        sf.grid_columnconfigure(1, weight=1); sf.grid_propagate(False)
        ctk.CTkLabel(sf, text="🔍", font=ctk.CTkFont(size=16)).grid(row=0, column=0, padx=(16, 4), pady=10)
        self._q = ctk.StringVar()
        self._q.trace_add("write", lambda *_: self._refresh())
        ctk.CTkEntry(sf, textvariable=self._q, placeholder_text=t("search_ph"),
                     border_width=0, fg_color="transparent", text_color=TEXT,
                     font=ctk.CTkFont(size=14)).grid(row=0, column=1, sticky="ew", padx=(0, 16))
        self._scroll = ctk.CTkScrollableFrame(right, fg_color="transparent",
                                               scrollbar_button_color=BORDER,
                                               scrollbar_button_hover_color=ACCENT)
        self._scroll.grid(row=1, column=0, sticky="nsew")
        self._scroll.grid_columnconfigure(0, weight=1)

    def _refresh(self):
        for w in self._scroll.winfo_children(): w.destroy()
        entries = self._vault.all()
        q = self._q.get().lower() if hasattr(self, "_q") else ""
        if q: entries = [e for e in entries if q in e["site"].lower() or q in e["username"].lower()]
        self._count.configure(text=t("total", len(entries)))
        if not entries:
            ctk.CTkLabel(self._scroll, text=t("no_results" if q else "empty_vault"),
                         font=ctk.CTkFont(size=15), text_color=MUTED).grid(row=0, column=0, pady=60)
            return
        for i, e in enumerate(entries):
            PasswordRow(self._scroll, entry=e, on_delete=self._delete,
                        index=i, fg_color=SURFACE, corner_radius=10).grid(
                row=i, column=0, sticky="ew", pady=(0, 8))

    def _add(self):
        s, u, p = self._fs.get().strip(), self._fu.get().strip(), self._fp.get().strip()
        if not all([s, u, p]): return self._msg.configure(text=t("err_fields"), text_color=DANGER)
        self._vault.add(s, u, p)
        for e in (self._fs, self._fu, self._fp): e.delete(0, "end")
        self._msg.configure(text=t("add_ok"), text_color=SUCCESS)
        self.after(2500, lambda: self._msg.configure(text=""))
        self._refresh()

    def _delete(self, eid: str): self._vault.delete(eid); self._refresh()

    def _gen(self):
        self._fp.delete(0, "end"); self._fp.insert(0, gen_password())
        self._msg.configure(text=t("generated"), text_color=SUCCESS)
        self.after(3000, lambda: self._msg.configure(text=""))

    def _change_lang(self, name: str):
        Settings.set_lang(LANG_OPTIONS.get(name, "en")); self._lc()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        Settings.load()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.geometry("1140x720")
        self.minsize(960, 600)
        self.configure(fg_color=BG)
        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"1140x720+{(sw - 1140) // 2}+{(sh - 720) // 2}")
        self._vault = None
        self._show_login()

    def _clear(self):
        for w in self.winfo_children(): w.destroy()
        self.title(t("app_window"))

    def _show_login(self):
        self._clear()
        LoginScreen(self, on_success=self._show_dashboard,
                    on_lang_change=self._show_login).pack(fill="both", expand=True)

    def _show_dashboard(self, vault: VaultManager):
        self._vault = vault; self._clear()
        Dashboard(self, vault=vault,
                  on_lang_change=self._reload_dash).pack(fill="both", expand=True)

    def _reload_dash(self):
        self._clear()
        Dashboard(self, vault=self._vault,
                  on_lang_change=self._reload_dash).pack(fill="both", expand=True)


if __name__ == "__main__":
    App().mainloop()