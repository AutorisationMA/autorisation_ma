import streamlit as st
import pandas as pd
import hashlib
from datetime import datetime
from supabase import create_client, Client
import io

# --------------------------
# Configuration Supabase
# --------------------------
SUPABASE_URL = st.secrets.get("SUPABASE_URL")
SUPABASE_KEY = st.secrets.get("SUPABASE_KEY")
if not SUPABASE_URL or not SUPABASE_KEY:
    st.error("Les secrets SUPABASE_URL et SUPABASE_KEY doivent être définis dans `st.secrets`.")
    st.stop()

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --------------------------
# Utilitaires
# --------------------------
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def safe_str_upper(series: pd.Series) -> pd.Series:
    return series.astype(str).fillna("").str.strip().str.upper()

# --------------------------
# Initialisation des tables
# --------------------------
# NOTE: Supabase ne permet pas d'exécuter du SQL arbitraire depuis le client
# sans une fonction RPC côté serveur. Nous essayons d'appeler une RPC nommée
# `exec_sql` (si vous l'avez créée) pour créer les tables automatiquement.
# Sinon, l'app affichera les commandes SQL à exécuter manuellement dans SQL Editor.

SQL_CREATE_USERS = '''
CREATE TABLE IF NOT EXISTS users (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','agent','consult'))
);
'''

SQL_CREATE_MA = '''
CREATE TABLE IF NOT EXISTS autorisations_ma (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  Matricule TEXT,
  Declarant TEXT,
  Reference_MA TEXT,
  Pays TEXT,
  Date_ajout TIMESTAMP DEFAULT now(),
  Type TEXT,
  Exporte TEXT DEFAULT 'Non',
  Cree_par TEXT,
  Observation TEXT,
  Cloture_par TEXT,
  Date_cloture TIMESTAMP,
  Vide_plein TEXT
);
'''


def try_init_tables():
    """Tente d'appeler la RPC `exec_sql`. Si elle existe, crée les tables.
    Sinon retourne False et on demandera à l'utilisateur d'exécuter le SQL manuellement.
    """
    try:
        # Appel d'une RPC hypothétique `exec_sql(sql text)` qui exécute SQL brut
        supabase.rpc("exec_sql", {"sql": SQL_CREATE_USERS}).execute()
        supabase.rpc("exec_sql", {"sql": SQL_CREATE_MA}).execute()
        return True
    except Exception:
        return False

# --------------------------
# Fonctions utilisateur (Supabase)
# --------------------------

def load_users_df() -> pd.DataFrame:
    res = supabase.table("users").select("*").execute()
    return pd.DataFrame(res.data) if res.data else pd.DataFrame(columns=["username","password_hash","role"])


def create_user(username: str, password: str, role: str):
    supabase.table("users").insert({
        "username": username,
        "password_hash": hash_password(password),
        "role": role
    }).execute()


def check_login(username: str, password: str):
    res = supabase.table("users").select("*").eq("username", username).execute()
    if res.data:
        user = res.data[0]
        if user.get("password_hash") == hash_password(password):
            return True, user.get("role")
    return False, None


def update_password(username: str, new_password: str) -> bool:
    supabase.table("users").update({"password_hash": hash_password(new_password)}).eq("username", username).execute()
    return True

# --------------------------
# Fonctions autorisations MA
# --------------------------

def load_ma_df() -> pd.DataFrame:
    res = supabase.table("autorisations_ma").select("*").execute()
    return pd.DataFrame(res.data) if res.data else pd.DataFrame(columns=["id","Matricule","Reference_MA","Pays","Date_ajout","Type","Exporte","Cree_par","Observation","Cloture_par","Date_cloture","Vide_plein","Declarant"])


def insert_ma(doc: dict):
    supabase.table("autorisations_ma").insert(doc).execute()


def close_ma(ma_id: int, username: str):
    supabase.table("autorisations_ma").update({
        "Exporte": "Oui",
        "Cloture_par": username,
        "Date_cloture": datetime.now().isoformat()
    }).eq("id", ma_id).execute()

# --------------------------
# App Streamlit
# --------------------------

st.set_page_config(page_title="Gestion des autorisations MA (Supabase)", layout="centered")
st.title("📄 Gestion de MA & Suivi — Supabase")

# Tenter initialisation tables
inited = try_init_tables()
if not inited:
    with st.expander("Initialisation des tables (si nécessaire)"):
        st.warning("Impossible d'exécuter automatiquement les commandes SQL via RPC. Si vous n'avez pas créé les tables, copiez-collez le SQL ci-dessous dans SQL Editor de Supabase et exécutez-le une fois.")
        st.code(SQL_CREATE_USERS + "\n" + SQL_CREATE_MA, language="sql")
        st.info("Option alternative : créer une fonction RPC `exec_sql(sql text)` dans Supabase pour permettre l'exécution automatique du SQL depuis l'app.")

# -- Session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None

# --- Authentification
if not st.session_state.logged_in:
    st.subheader("Connexion")
    username = st.text_input("Nom d'utilisateur")
    password = st.text_input("Mot de passe", type="password")
    if st.button("Se connecter"):
        valid, role = check_login(username, password)
        if valid:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = role
            st.experimental_rerun()
        else:
            st.error("Nom d'utilisateur ou mot de passe incorrect.")
    st.stop()

st.sidebar.write(f"✅ Connecté : {st.session_state.username} ({st.session_state.role})")
if st.sidebar.button("Déconnexion"):
    st.session_state.logged_in = False
    st.session_state.username = None
    st.experimental_rerun()

menu_options = [
    "🔐 Modifier mot de passe",
    "📥 MA Import",
    "📤 MA Export",
    "📊 Consulter MA"
]
if st.session_state.role == "admin":
    menu_options.insert(1, "👤 Créer un utilisateur")

menu = st.sidebar.radio("Menu", menu_options)

# Chargement dataframe depuis Supabase
try:
    df = load_ma_df()
except Exception as e:
    st.error(f"Erreur lors du chargement des MA depuis Supabase: {e}")
    df = pd.DataFrame()

# --- Modifier mot de passe ---
if menu == "🔐 Modifier mot de passe":
    st.header("Modifier mon mot de passe")
    current_pwd = st.text_input("Mot de passe actuel", type="password")
    new_pwd = st.text_input("Nouveau mot de passe", type="password")
    new_pwd_confirm = st.text_input("Confirmer nouveau mot de passe", type="password")
    if st.button("Changer mon mot de passe"):
        users_df = load_users_df()
        user_row = users_df[users_df["username"] == st.session_state.username]
        if not user_row.empty and hash_password(current_pwd) == user_row.iloc[0]["password_hash"]:
            if new_pwd and new_pwd == new_pwd_confirm:
                update_password(st.session_state.username, new_pwd)
                st.success("✅ Mot de passe modifié avec succès.")
            else:
                st.error("❌ Les nouveaux mots de passe ne correspondent pas ou sont vides.")
        else:
            st.error("❌ Mot de passe actuel incorrect.")

# --- Création utilisateur ---
elif menu == "👤 Créer un utilisateur" and st.session_state.role == "admin":
    st.header("Créer un nouvel utilisateur")
    new_username = st.text_input("Nom d'utilisateur du nouvel utilisateur").strip()
    new_password = st.text_input("Mot de passe", type="password")
    confirm_password = st.text_input("Confirmer le mot de passe", type="password")
    new_role = st.selectbox("Rôle", ["agent", "admin", "consult"])
    if st.button("Créer l'utilisateur"):
        if not new_username or not new_password:
            st.warning("❗ Veuillez remplir tous les champs.")
        elif new_password != confirm_password:
            st.error("❌ Les mots de passe ne correspondent pas.")
        else:
            users_df = load_users_df()
            if new_username in users_df["username"].values:
                st.error("❌ Ce nom d'utilisateur existe déjà.")
            else:
                create_user(new_username, new_password, new_role)
                st.success(f"✅ Utilisateur '{new_username}' ({new_role}) créé avec succès.")

# --- Import MA ---
elif menu == "📥 MA Import" and st.session_state.role != "consult":
    st.subheader("Ajouter une nouvelle autorisation")

    matricule = st.text_input("Matricule").strip().upper()
    declarant = st.text_input("Déclarant").strip().upper()
    type_doc = st.selectbox("Type MA", ["", "AU VOYAGE", "A TEMPS", "A VIDE", "FOURGON", "SUBSAHARIEN", "T6BIS"]).upper()
    ref = st.text_input("Référence_MA").strip()

    if type_doc not in ["FOURGON", "T6BIS", "SUBSAHARIEN"]:
        if ref and not ref.isdigit():
            st.warning("Veuillez entrer uniquement des chiffres pour la Référence MA.")
        else:
            ref = ref.upper()
    else:
        ref = ref.upper() if ref else ""

    europe_countries = ["", "ALBANIE", "ANDORRE", "AUTRICHE", "BELGIQUE", "BOSNIE-HERZÉGOVINE", "BULGARIE", "CROATIE", "DANEMARK", "ESPAGNE", "ESTONIE", "FINLANDE", "FRANCE", "GRÈCE", "HONGRIE", "IRLANDE", "ISLANDE", "ITALIE", "LETTONIE", "LIECHTENSTEIN", "LITUANIE", "LUXEMBOURG", "MACÉDOINE", "MALTE", "MOLDAVIE", "MONACO", "MONTÉNÉGRO", "NORVÈGE", "PAYS-BAS", "POLOGNE", "PORTUGAL", "RÉPUBLIQUE TCHÈQUE", "ROUMANIE", "ROYAUME-UNI", "SAINT-MARIN", "SERBIE", "SLOVAQUIE", "SLOVÉNIE", "SUÈDE", "SUISSE", "UKRAINE", "VATICAN"]
    pays = st.selectbox("Pays", options=europe_countries).upper()
    vide_plein = st.selectbox("Vide / Plein", ["", "VIDE", "PLEIN"])
    observation = st.text_area("Observation (facultatif)").strip().upper()

    if st.button("📥 Ajouter"):
        if not matricule or not pays:
            st.warning("❗ Veuillez remplir tous les champs obligatoires.")
        elif type_doc not in ["FOURGON", "T6BIS", "SUBSAHARIEN"] and not ref:
            st.warning("❗ La Référence MA est obligatoire pour ce type.")
        else:
            # Vérifier doublon
            df_local = load_ma_df()
            df_local["Reference_MA_clean"] = safe_str_upper(df_local.get("Reference_MA", pd.Series()))
            df_local["Pays_clean"] = safe_str_upper(df_local.get("Pays", pd.Series()))
            df_local["Type_clean"] = safe_str_upper(df_local.get("Type", pd.Series()))

            is_duplicate = df_local[(df_local["Reference_MA_clean"] == ref) & (df_local["Pays_clean"] == pays) & (df_local["Type_clean"] == type_doc) & ~((df_local["Type_clean"] == "A TEMPS") & (df_local.get("Exporte", "").str.upper() == "OUI"))]

            if not is_duplicate.empty:
                st.error("❌ Cette autorisation MA existe déjà (Réf + Type + Pays).")
            else:
                ma_doc = {
                    "Matricule": matricule,
                    "Declarant": declarant,
                    "Reference_MA": ref,
                    "Pays": pays,
                    "Date_ajout": datetime.now().isoformat(),
                    "Type": type_doc,
                    "Exporte": "Non",
                    "Cree_par": st.session_state.username,
                    "Observation": observation,
                    "Cloture_par": None,
                    "Date_cloture": None,
                    "Vide_plein": vide_plein
                }
                insert_ma(ma_doc)
                st.success("✅ Réf MA ajouté avec succès.")

    st.subheader("📋 10 dernières opérations")
    last_imports = load_ma_df().sort_values(by="Date_ajout", ascending=False).head(10)
    st.dataframe(last_imports)

# --- MA Export ---
elif menu == "📤 MA Export" and st.session_state.role != "consult":
    st.subheader("Rechercher une autorisation MA à clôturer")
    df_temp = load_ma_df()
    df_temp = df_temp[df_temp.get("Exporte", "").str.upper() != "OUI"] if not df_temp.empty else df_temp

    search_term = st.text_input("🔍 Recherche (matricule ou référence_MA ou Pays)").strip().upper()

    if search_term:
        df_filtered = df_temp[df_temp.apply(lambda r: search_term in str(r.get("Matricule","")).upper() or search_term in str(r.get("Reference_MA","")) or search_term in str(r.get("Pays","")), axis=1)]
        if not df_filtered.empty:
            st.dataframe(df_filtered[[c for c in ["id","Matricule","Reference_MA","Type","Date_ajout"] if c in df_filtered.columns]])

            # mapping id
            options = {row.get("Reference_MA") or f"id:{row.get('id')}": row.get("id") for _, row in df_filtered.iterrows()}
            selected_label = st.selectbox("Sélectionner une autorisation à clôturer", list(options.keys()))

            if st.button("📤 Clôturer la sélection"):
                idx = options[selected_label]
                row = df_filtered[df_filtered["id"] == idx].iloc[0]
                type_selected = (row.get("Type") or "").upper()

                if type_selected in ["T6BIS", "FOURGON", "SUBSAHARIEN"]:
                    st.warning(f"⚠️ Attention : vous êtes en train de clôturer une opération de type {type_selected}.")
                    if st.button(f"✅ Confirmer la clôture {type_selected}"):
                        close_ma(idx, st.session_state.username)
                        st.success("✅ Autorisation clôturée.")
                else:
                    close_ma(idx, st.session_state.username)
                    st.success("✅ Autorisation clôturée.")
        else:
            st.info("Aucun résultat trouvé pour cette recherche.")
    else:
        st.info("👉 Veuillez saisir un critère de recherche pour afficher les résultats.")

    st.subheader("📋 10 dernières opérations")
    last_imports = load_ma_df().sort_values(by="Date_ajout", ascending=False).head(10)
    st.dataframe(last_imports)

# --- Consultation ---
elif menu == "📊 Consulter MA":
    st.subheader("Filtrer les autorisations MA")

    df_full = load_ma_df()
    matricule_search = st.text_input("🔍 Recherche par Matricule").strip()
    pays_sel = st.multiselect("Pays", options=sorted(df_full["Pays"].dropna().unique()) if not df_full.empty else [])
    type_sel = st.multiselect("Type MA", options=sorted(df_full["Type"].dropna().unique()) if not df_full.empty else [])
    date_start = st.date_input("Date début", value=None)
    date_end = st.date_input("Date fin", value=None)

    df_filtered = df_full.copy()
    if "Date_ajout" in df_filtered.columns and not pd.api.types.is_datetime64_any_dtype(df_filtered["Date_ajout"]):
        df_filtered["Date_ajout"] = pd.to_datetime(df_filtered["Date_ajout"], errors='coerce')

    if matricule_search:
        df_filtered = df_filtered[df_filtered["Matricule"].astype(str).str.upper().str.contains(matricule_search.upper())]
    if pays_sel:
        df_filtered = df_filtered[df_filtered["Pays"].isin(pays_sel)]
    if type_sel:
        df_filtered = df_filtered[df_filtered["Type"].isin(type_sel)]
    if date_start:
        df_filtered = df_filtered[df_filtered["Date_ajout"] >= pd.Timestamp(date_start)]
    if date_end:
        df_filtered = df_filtered[df_filtered["Date_ajout"] <= pd.Timestamp(date_end)]

    df_filtered = df_filtered.sort_values(by="Date_ajout", ascending=False)
    st.dataframe(df_filtered)

    # Export Excel
    if not df_filtered.empty:
        buffer = io.BytesIO()
        with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
            df_filtered.to_excel(writer, index=False, sheet_name="Autorisations_MA")
        st.download_button(
            label="📥 Télécharger en Excel",
            data=buffer.getvalue(),
            file_name="autorisations_filtrees.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    else:
        st.info("Aucune donnée à exporter.")
