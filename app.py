import streamlit as st
import pandas as pd
import hashlib
from datetime import datetime
from supabase import create_client, Client

# ==========================
# --- Connexion Supabase ---
# ==========================
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


# ==========================
# --- Utils / Hashing ---
# ==========================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def safe_str_upper(series):
    return series.astype(str).fillna('').str.strip().str.upper()


# ==========================
# --- Gestion utilisateurs ---
# ==========================
def load_users() -> pd.DataFrame:
    resp = supabase.table("users").select("*").execute()
    return pd.DataFrame(resp.data) if resp.data else pd.DataFrame()


def save_user(user: dict):
    supabase.table("users").insert(user).execute()


def check_login(username: str, password: str):
    users = load_users()
    user = users[users["username"] == username]
    if not user.empty:
        is_valid = hash_password(password) == user.iloc[0]["password_hash"]
        role = user.iloc[0]["role"]
        return is_valid, role
    return False, None


def update_password(username: str, new_password: str) -> bool:
    users = load_users()
    user = users[users["username"] == username]
    if not user.empty:
        supabase.table("users").update({"password_hash": hash_password(new_password)}).eq("username", username).execute()
        return True
    return False


# ==========================
# --- Authentification ---
# ==========================
st.set_page_config(page_title="Gestion des autorisations MA", layout="centered")
st.title("📄 Gestion de MA & Suivi")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None

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
            st.rerun()
        else:
            st.error("Nom d'utilisateur ou mot de passe incorrect.")
    st.stop()

st.sidebar.write(f"✅ Connecté : {st.session_state.username} ({st.session_state.role})")
if st.sidebar.button("Déconnexion"):
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.rerun()


# ==========================
# --- Menu ---
# ==========================
menu_options = [
    "🔐 Modifier mot de passe",
    "📥 MA Import",
    "📤 MA Export",
    "📊 Consulter MA"
]

if st.session_state.role == "admin":
    menu_options.insert(1, "👤 Créer un utilisateur")

menu = st.sidebar.radio("Menu", menu_options)


# ==========================
# --- Fonctions MA ---
# ==========================
def insert_ma(new_doc: dict):
    """Insère une nouvelle MA dans Supabase avec vérification des doublons"""
    resp = supabase.table("autorisations_ma").select("*").execute()
    df = pd.DataFrame(resp.data) if resp.data else pd.DataFrame()

    if not df.empty:
        df["Reference_MA_clean"] = safe_str_upper(df["Reference_MA"])
        df["Pays_clean"] = safe_str_upper(df["Pays"])
        df["Type_clean"] = safe_str_upper(df["Type"])

        ref = str(new_doc.get("Reference_MA", "")).upper().strip()
        pays = str(new_doc.get("Pays", "")).upper().strip()
        typ = str(new_doc.get("Type", "")).upper().strip()

        doublon = df[
            (df["Reference_MA_clean"] == ref) &
            (df["Pays_clean"] == pays) &
            (df["Type_clean"] == typ)
        ]
        if not doublon.empty:
            st.warning(f"⚠️ Cette autorisation MA existe déjà ({ref} - {typ} - {pays})")
            return False

    clean_doc = {k: v for k, v in new_doc.items() if not k.endswith("_clean")}
    try:
        supabase.table("autorisations_ma").insert(clean_doc).execute()
        st.success(f"✅ MA {new_doc.get('Reference_MA')} ajoutée")
        return True
    except Exception as e:
        st.error(f"Erreur insertion : {e}")
        return False


# ==========================
# --- Modifier mot de passe ---
# ==========================
if menu == "🔐 Modifier mot de passe":
    st.header("Modifier mon mot de passe")
    current_pwd = st.text_input("Mot de passe actuel", type="password")
    new_pwd = st.text_input("Nouveau mot de passe", type="password")
    new_pwd_confirm = st.text_input("Confirmer nouveau mot de passe", type="password")
    if st.button("Changer mon mot de passe"):
        user_hash = load_users().set_index("username").loc[st.session_state.username]["password_hash"]
        if hash_password(current_pwd) == user_hash:
            if new_pwd == new_pwd_confirm and new_pwd:
                update_password(st.session_state.username, new_pwd)
                st.success("✅ Mot de passe modifié avec succès.")
            else:
                st.error("❌ Les nouveaux mots de passe ne correspondent pas ou sont vides.")
        else:
            st.error("❌ Mot de passe actuel incorrect.")


# ==========================
# --- Création utilisateur ---
# ==========================
elif menu == "👤 Créer un utilisateur" and st.session_state.role == "admin":
    st.header("Créer un nouvel utilisateur")
    new_username = st.text_input("Nom d'utilisateur").strip()
    new_password = st.text_input("Mot de passe", type="password")
    confirm_password = st.text_input("Confirmer le mot de passe", type="password")
    new_role = st.selectbox("Rôle", ["agent", "admin", "consult"])
    if st.button("Créer l'utilisateur"):
        if not new_username or not new_password:
            st.warning("❗ Veuillez remplir tous les champs.")
        elif new_password != confirm_password:
            st.error("❌ Les mots de passe ne correspondent pas.")
        else:
            users = load_users()
            if new_username in users["username"].values:
                st.error("❌ Ce nom d'utilisateur existe déjà.")
            else:
                save_user({
                    "username": new_username,
                    "password_hash": hash_password(new_password),
                    "role": new_role
                })
                st.success(f"✅ Utilisateur '{new_username}' ({new_role}) créé")


# ==========================
# --- MA Import Formulaire ---
# ==========================
elif menu == "📥 MA Import" and st.session_state.role != "consult":
    st.subheader("Ajouter une nouvelle autorisation")
    matricule = st.text_input("Matricule").strip().upper()
    declarant = st.text_input("Déclarant").strip().upper()
    type_doc = st.selectbox("Type MA", ["AU VOYAGE", "A TEMPS", "A VIDE", "FOURGON", "SUBSAHARIEN", "T6BIS"]).upper()
    ref = st.text_input("Référence MA").strip()
    pays = st.text_input("Pays").strip().upper()
    vide_plein = st.selectbox("Vide / Plein", ["", "VIDE", "PLEIN"])
    observation = st.text_area("Observation").strip().upper()

    if st.button("📥 Ajouter"):
        if not matricule or not pays or (type_doc not in ["FOURGON", "T6BIS", "SUBSAHARIEN"] and not ref):
            st.warning("❗ Veuillez remplir tous les champs obligatoires")
        else:
            ma_doc = {
                "Matricule": matricule,
                "Declarant": declarant,
                "Reference_MA": ref,
                "Pays": pays,
                "Type": type_doc,
                "Cree_par": st.session_state.username,
                "Observation": observation,
                "Vide_plein": vide_plein,
                "Date_ajout": datetime.now().isoformat()
            }
            insert_ma(ma_doc)


# ==========================
# --- MA Export / Clôture ---
# ==========================
elif menu == "📤 MA Export" and st.session_state.role != "consult":
    st.subheader("Clôturer une autorisation MA")
    resp = supabase.table("autorisations_ma").select("*").execute()
    df = pd.DataFrame(resp.data) if resp.data else pd.DataFrame()
    df_active = df[df["Exporte"].str.upper() != "OUI"] if not df.empty else pd.DataFrame()

    search_term = st.text_input("🔍 Recherche (matricule ou référence_MA ou Pays)").strip().upper()
    if search_term and not df_active.empty:
        df_filtered = df_active[
            safe_str_upper(df_active["Matricule"]).str.contains(search_term, na=False) |
            safe_str_upper(df_active["Reference_MA"]).str.contains(search_term, na=False) |
            safe_str_upper(df_active["Pays"]).str.contains(search_term, na=False)
        ]
        if not df_filtered.empty:
            options = {row["Reference_MA"]: idx for idx, row in df_filtered.iterrows()}
            selected_label = st.selectbox("Sélectionner une autorisation à clôturer", list(options.keys()))
            if st.button("📤 Clôturer la sélection"):
                idx = options[selected_label]
                type_selected = df_filtered.at[idx, "Type"].upper()
                supabase.table("autorisations_ma").update({
                    "Exporte": "Oui",
                    "Cloture_par": st.session_state.username,
                    "Date_cloture": datetime.now().isoformat()
                }).eq("id", df_filtered.at[idx, "id"]).execute()
                st.success(f"✅ L'autorisation {selected_label} ({type_selected}) a été clôturée")


# ==========================
# --- Consultation MA ---
# ==========================
elif menu == "📊 Consulter MA":
    st.subheader("Filtrer les autorisations MA")
    resp = supabase.table("autorisations_ma").select("*").execute()
    df = pd.DataFrame(resp.data) if resp.data else pd.DataFrame()
    if df.empty:
        st.info("Aucune donnée")
    else:
        matricule_search = st.text_input("🔍 Recherche par Matricule").strip().upper()
        pays_sel = st.multiselect("Pays", options=df["Pays"].dropna().unique())
        type_sel = st.multiselect("Type MA", options=df["Type"].dropna().unique())
        date_start = st.date_input("Date début")
        date_end = st.date_input("Date fin")
        df_filtered = df.copy()
        df_filtered["Date_ajout"] = pd.to_datetime(df_filtered["Date_ajout"], errors='coerce')

        if matricule_search:
            df_filtered = df_filtered[safe_str_upper(df_filtered["Matricule"]).str.contains(matricule_search)]
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
        import io
        if not df_filtered.empty:
            buffer = io.BytesIO()
            df_filtered.to_excel(buffer, index=False)
            st.download_button("📥 Télécharger en Excel", buffer.getvalue(),
                               file_name="autorisations_filtrees.xlsx",
                               mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
