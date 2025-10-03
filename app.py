import streamlit as st
import pandas as pd
import hashlib
from datetime import datetime
from supabase import create_client, Client
import io

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

menu_options = [
    "📥 MA Import",
    "📤 MA Export",
    "📊 Consulter MA",
    "🔐 Modifier mot de passe"  # par défaut
]

# Si admin, insérer "Créer un utilisateur" juste avant "Modifier mot de passe"
if st.session_state.role == "admin":
    menu_options.insert(-1, "👤 Créer un utilisateur")

menu = st.sidebar.radio("Menu", menu_options)

# ==========================
# --- Liste des pays ---
# ==========================
europe_countries = [
    "", "ALBANIE", "ANDORRE", "AUTRICHE", "BELGIQUE", "BOSNIE-HERZÉGOVINE",
    "BULGARIE", "CROATIE", "DANEMARK", "ESPAGNE", "ESTONIE", "FINLANDE",
    "FRANCE", "GRÈCE", "HONGRIE", "IRLANDE", "ISLANDE", "ITALIE",
    "LETTONIE", "LIECHTENSTEIN", "LITUANIE", "LUXEMBOURG", "MACÉDOINE",
    "MALTE", "MOLDAVIE", "MONACO", "MONTÉNÉGRO", "NORVÈGE", "PAYS-BAS",
    "POLOGNE", "PORTUGAL", "RÉPUBLIQUE TCHÈQUE", "ROUMANIE", "ROYAUME-UNI",
    "SAINT-MARIN", "SERBIE", "SLOVAQUIE", "SLOVÉNIE", "SUÈDE", "SUISSE",
    "UKRAINE", "VATICAN"
]

# ==========================
# --- Fonctions MA ---
# ==========================
def insert_ma(new_doc: dict):
    """Insertion MA avec vérification des doublons et colonnes existantes"""
    resp2 = supabase.table("autorisations_ma").select("*").execute()
    df = pd.DataFrame(resp2.data) if resp2.data else pd.DataFrame()
    # Vérification doublon
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
            st.warning(f"⚠️ Cette MA existe déjà ({ref} - {typ} - {pays})")
            return False
    try:
        supabase.table("autorisations_ma").insert(new_doc).execute()
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
            save_user({
                "username": new_username,
                "password_hash": hash_password(new_password),
                "role": new_role
            })
            st.success(f"✅ Utilisateur '{new_username}' ({new_role}) créé")

# ==========================
# --- MA Import ---
# ==========================
# ==========================
# --- MA Import / Ajout ---
# ==========================
elif menu == "📥 MA Import" and st.session_state.role != "consult":
    st.subheader("Ajouter une nouvelle autorisation")

    # --- Champs formulaire ---
    matricule = st.text_input("Matricule", value="").strip().upper()
    declarant = st.text_input("Déclarant", value="").strip().upper()
    
    type_doc = st.selectbox(
        "Type MA",
        ["", "AU VOYAGE", "A TEMPS", "A VIDE", "FOURGON", "SUBSAHARIEN", "T6BIS"]
    ).upper()

    ref = st.text_input("Référence MA (chiffres uniquement si requis)", value="").strip().upper()

    europe_countries = [
        "", "ALBANIE", "ANDORRE", "AUTRICHE", "BELGIQUE", "BOSNIE-HERZÉGOVINE",
        "BULGARIE", "CROATIE", "DANEMARK", "ESPAGNE", "ESTONIE", "FINLANDE",
        "FRANCE", "GRÈCE", "HONGRIE", "IRLANDE", "ISLANDE", "ITALIE",
        "LETTONIE", "LIECHTENSTEIN", "LITUANIE", "LUXEMBOURG", "MACÉDOINE",
        "MALTE", "MOLDAVIE", "MONACO", "MONTÉNÉGRO", "NORVÈGE", "PAYS-BAS",
        "POLOGNE", "PORTUGAL", "RÉPUBLIQUE TCHÈQUE", "ROUMANIE", "ROYAUME-UNI",
        "SAINT-MARIN", "SERBIE", "SLOVAQUIE", "SLOVÉNIE", "SUÈDE", "SUISSE",
        "UKRAINE", "VATICAN"
    ]
    pays = st.selectbox("Pays", options=europe_countries, index=0).upper()
    vide_plein = st.selectbox("Vide / Plein", ["", "VIDE", "PLEIN"])
    observation = st.text_area("Observation (facultatif)", value="").strip().upper()

    # --- Bouton ajout ---
    if st.button("📥 Ajouter"):
        # Vérification champs obligatoires
        if not matricule or not pays:
            st.warning("❗ Veuillez remplir tous les champs obligatoires (Matricule et Pays).")
        elif type_doc not in ["FOURGON", "SUBSAHARIEN", "T6BIS"] and (not ref or not ref.isdigit()):
            st.error("❌ Référence MA obligatoire et uniquement chiffres pour ce type de MA.")
        else:
            # --- Vérifier doublons et MA non exportées ---
            resp_existing = supabase.table("autorisations_ma").select("*").execute()
            df_existing = pd.DataFrame(resp_existing.data) if resp_existing.data else pd.DataFrame()

            if not df_existing.empty:
                # Doublons exacts
                dup = df_existing[
                    (safe_str_upper(df_existing["Reference_MA"]) == ref) &
                    (safe_str_upper(df_existing["Pays"]) == pays) &
                    (safe_str_upper(df_existing["Type"]) == type_doc)
                ]
                if not dup.empty:
                    st.error("❌ Cette autorisation MA existe déjà (Réf + Type + Pays).")
                    st.stop()

                # Vérifier si ce camion a déjà une MA non exportée
                active_ma = df_existing[
                    (safe_str_upper(df_existing["Matricule"]) == matricule) &
                    (safe_str_upper(df_existing["Exporte"]) != "OUI")
                ]
                if not active_ma.empty:
                    st.error(f"❌ Le camion {matricule} possède déjà {len(active_ma)} MA actives non exportées. Impossible d'ajouter une nouvelle MA.")
                    st.stop()

            # --- Préparer le document à insérer ---
            new_doc = {
                "Matricule": matricule,
                "Declarant": declarant,
                "Reference_MA": ref,
                "Pays": pays,
                "Date_ajout": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Type": type_doc,
                "Exporte": "Non",
                "Cree_par": st.session_state.username,
                "Observation": observation,
                "Cloture_par": "",
                "Date_cloture": None,
                "Vide_plein": vide_plein if vide_plein else ""
            }

            # --- Insertion dans Supabase ---
            supabase.table("autorisations_ma").insert(new_doc).execute()
            st.success("✅ Référence MA ajoutée avec succès.")

        # --- Affichage des 5 derniers ajouts ---
        resp_last = supabase.table("autorisations_ma").select("*").order("Date_ajout", desc=True).limit(5).execute()
        df_last = pd.DataFrame(resp_last.data) if resp_last.data else pd.DataFrame()
        if not df_last.empty:
            df_last_display = df_last[["id", "Reference_MA", "Matricule", "Pays", "Date_ajout"]].copy()
            df_last_display = df_last_display.rename(columns={
                "id": "ID",
                "Reference_MA": "MA",
                "Matricule": "N",
                "Date_ajout": "Date"
            })
            st.subheader("📋 5 derniers ajouts")
            st.dataframe(df_last_display)

# ==========================
# --- MA Export / Clôture ---
# ==========================
# ==========================
# --- MA Export / Clôture ---
# ==========================
elif menu == "📤 MA Export" and st.session_state.role != "consult":
    st.subheader("Clôturer une autorisation MA")

    # Récupérer MA non exportées
    resp = supabase.table("autorisations_ma").select("*").neq("Exporte", "Oui").execute()
    df_ma = pd.DataFrame(resp.data) if resp.data else pd.DataFrame()

    if df_ma.empty:
        st.info("Aucune MA non exportée disponible")
    else:
        # Champs de recherche initialement vides
        search_term = st.text_input("🔍 Recherche (matricule, MA, pays)", value="").strip().upper()

        df_filtered = df_ma.copy()
        if search_term:
            df_filtered = df_filtered[
                safe_str_upper(df_filtered["Matricule"]).str.contains(search_term) |
                safe_str_upper(df_filtered["Reference_MA"]).str.contains(search_term) |
                safe_str_upper(df_filtered["Pays"]).str.contains(search_term)
            ]

        if df_filtered.empty:
            st.info("Aucun résultat ne correspond à votre recherche")
        else:
            # --- Affichage colonnes essentielles ---
            df_display = df_filtered[["id", "Reference_MA", "Matricule", "Pays", "Date_ajout"]].copy()
            df_display = df_display.rename(columns={
                "id": "ID",
                "Reference_MA": "MA",
                "Matricule": "N",
                "Date_ajout": "Date"
            })
            st.dataframe(df_display)

            # --- Selectbox améliorée avec ID | N | MA | Pays | Date ---
            select_options = [
                f"{row['ID']} | {row['N']} | {row['MA']} | {row['Pays']} | {row['Date']}"
                for _, row in df_display.iterrows()
            ]
            selected_label = st.selectbox("Sélectionner une MA à clôturer", select_options)

            # Récupérer la MA correspondant au label sélectionné
            selected_id = int(selected_label.split(" | ")[0])
            type_selected = df_filtered[df_filtered["id"] == selected_id]["Type"].iloc[0].upper()

            if st.button("📤 Clôturer la sélection"):
                if type_selected in ["FOURGON", "SUBSAHARIEN", "T6BIS"]:
                    st.warning(f"⚠️ Attention : vous clôturez une MA de type {type_selected}. Confirmez ci-dessous.")
                    if st.button(f"✅ Confirmer clôture {type_selected}"):
                        supabase.table("autorisations_ma").update({
                            "Exporte": "Oui",
                            "Cloture_par": st.session_state.username,
                            "Date_cloture": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }).eq("id", selected_id).execute()
                        st.success(f"✅ MA {selected_label} clôturée")
                else:
                    # Clôture normale
                    supabase.table("autorisations_ma").update({
                        "Exporte": "Oui",
                        "Cloture_par": st.session_state.username,
                        "Date_cloture": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }).eq("id", selected_id).execute()
                    st.success(f"✅ MA {selected_label} clôturée")

        # --- 10 dernières clôtures ---
        resp_closed = supabase.table("autorisations_ma").select("*").eq("Exporte", "Oui").order("Date_cloture", desc=True).limit(10).execute()
        df_closed = pd.DataFrame(resp_closed.data) if resp_closed.data else pd.DataFrame()

        if not df_closed.empty:
            df_closed_display = df_closed[["id", "Reference_MA", "Matricule", "Pays", "Date_cloture"]].copy()
            df_closed_display = df_closed_display.rename(columns={
                "id": "ID",
                "Reference_MA": "MA",
                "Matricule": "N",
                "Date_cloture": "Date"
            })
            st.subheader("📋 10 dernières clôtures")
            st.dataframe(df_closed_display)


# ==========================
# --- Consultation / Export ---
# ==========================
elif menu == "📊 Consulter MA":
    st.subheader("Filtrer les autorisations MA")

    # Récupération des données depuis Supabase
    resp = supabase.table("autorisations_ma").select("*").execute()
    df = pd.DataFrame(resp.data) if resp.data else pd.DataFrame()

    if df.empty:
        st.info("Aucune donnée disponible")
    else:
        # --- Champs de recherche initialement vides ---
        matricule_search = st.text_input("🔍 Recherche par matricule", value="")
        pays_sel = st.multiselect("Pays", options=sorted(df["Pays"].dropna().unique()), default=[])
        type_sel = st.multiselect("Type MA", options=sorted(df["Type"].dropna().unique()), default=[])
        date_start = st.date_input("Date début", value=None)
        date_end = st.date_input("Date fin", value=None)

        # Assure que Date_ajout est datetime
        df["Date_ajout"] = pd.to_datetime(df["Date_ajout"], errors='coerce')

        # --- Filtrage dynamique ---
        df_filtered = df.copy()
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

        # --- Messages et affichage ---
        if df_filtered.empty:
            st.info("Aucun résultat ne correspond à votre recherche")
        else:
            st.dataframe(df_filtered)

            # 10 dernières opérations
            st.subheader("📋 10 dernières opérations")
            st.dataframe(df_filtered.head(10))

            # Export Excel
            buffer = io.BytesIO()
            df_filtered.to_excel(buffer, index=False)
            st.download_button(
                label="📥 Télécharger en Excel",
                data=buffer.getvalue(),
                file_name="autorisations_filtrees.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )









