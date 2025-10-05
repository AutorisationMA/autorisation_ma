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

    # --- Recherche dynamique de déclarant ---
    st.markdown("### 🔍 Déclarant")
    search_decl = st.text_input("Rechercher un déclarant (tapez quelques lettres)").strip().upper()

    declarants = []
    if search_decl:
        resp_decl = supabase.table("declarants").select("nom").ilike("nom", f"%{search_decl}%").limit(20).execute()
        declarants = [d["nom"] for d in resp_decl.data]

    if declarants:
        declarant = st.selectbox("Sélectionnez un déclarant", options=declarants)
    else:
        declarant = st.text_input("Ajouter un nouveau déclarant si non trouvé").strip().upper()
        # Si l'utilisateur a saisi un nouveau déclarant
        if declarant:
            if st.button("➕ Ajouter ce déclarant dans la base"):
                # Vérifier s’il existe déjà
                check_decl = supabase.table("declarants").select("*").eq("nom", declarant).execute()
                if check_decl.data:
                    st.warning("⚠️ Ce déclarant existe déjà.")
                else:
                    supabase.table("declarants").insert({"nom": declarant}).execute()
                    st.success("✅ Nouveau déclarant ajouté avec succès.")

    # --- Autres champs du formulaire ---
    matricule = st.text_input("Matricule", value="").strip().upper()
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
        if not matricule or not pays:
            st.warning("❗ Veuillez remplir tous les champs obligatoires (Matricule et Pays).")
        elif type_doc not in ["FOURGON", "SUBSAHARIEN", "T6BIS"] and (not ref or not ref.isdigit()):
            st.error("❌ Référence MA obligatoire et uniquement chiffres pour ce type de MA.")
        else:
            # Vérifier doublons et MA actives
            resp_existing = supabase.table("autorisations_ma").select("*").execute()
            df_existing = pd.DataFrame(resp_existing.data) if resp_existing.data else pd.DataFrame()

            if not df_existing.empty:
                dup = df_existing[
                    (safe_str_upper(df_existing["Reference_MA"]) == ref) &
                    (safe_str_upper(df_existing["Pays"]) == pays) &
                    (safe_str_upper(df_existing["Type"]) == type_doc)
                ]
                if not dup.empty:
                    st.error("❌ Cette autorisation MA existe déjà (Réf + Type + Pays).")
                    st.stop()

                active_ma = df_existing[
                    (safe_str_upper(df_existing["Matricule"]) == matricule) &
                    (safe_str_upper(df_existing["Exporte"]) != "OUI")
                ]
                if not active_ma.empty:
                    st.error(f"❌ Le camion {matricule} possède déjà {len(active_ma)} MA actives non exportées.")
                    st.stop()

            # Insérer la nouvelle MA
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

            supabase.table("autorisations_ma").insert(new_doc).execute()
            st.success("✅ Référence MA ajoutée avec succès.")
            st.rerun()

    # --- 5 derniers ajouts ---
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
        st.dataframe(df_last_display, use_container_width=True)



# ==========================
# --- MA Export / Clôture ---
# ==========================
elif menu == "📤 MA Export" and st.session_state.role != "consult":
    st.subheader("Clôturer une autorisation MA")

    resp = supabase.table("autorisations_ma").select("*").neq("Exporte", "Oui").execute()
    df_ma = pd.DataFrame(resp.data) if resp.data else pd.DataFrame()

    if df_ma.empty:
        st.info("Aucune MA non exportée disponible")
    else:
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
            df_display = df_filtered[["Reference_MA", "Matricule", "Pays", "Date_ajout"]].copy()
            df_display.rename(columns={"Reference_MA": "MA", "Matricule": "N", "Date_ajout": "Date"}, inplace=True)
            st.dataframe(df_display)

            selected_ref = st.selectbox("Sélectionner une MA à clôturer", df_filtered["Reference_MA"])

            if st.button("📤 Clôturer la sélection"):
                supabase.table("autorisations_ma").update({
                    "Exporte": "Oui",
                    "Cloture_par": st.session_state.username,
                    "Date_cloture": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }).eq("Reference_MA", selected_ref).execute()
                st.success(f"✅ MA {selected_ref} clôturée")

        # Affichage 10 dernières clôtures
        resp_closed = supabase.table("autorisations_ma").select("*").eq("Exporte", "Oui").order("Date_cloture", desc=True).limit(10).execute()
        df_closed = pd.DataFrame(resp_closed.data) if resp_closed.data else pd.DataFrame()
        if not df_closed.empty:
            df_closed_display = df_closed[["Reference_MA", "Matricule", "Pays", "Date_cloture"]].copy()
            df_closed_display.rename(columns={"Reference_MA": "MA", "Matricule": "N", "Date_cloture": "Date"}, inplace=True)
            st.subheader("📋 10 dernières clôtures")
            st.dataframe(df_closed_display)



# ==========================
# --- Consultation / Export ---
# ==========================
elif menu == "📊 Consulter MA":
    st.subheader("Filtrer les autorisations MA")

    # Charger toutes les données depuis Supabase
    resp = supabase.table("autorisations_ma").select("*").order("Date_ajout", desc=True).execute()
    df = pd.DataFrame(resp.data) if resp.data else pd.DataFrame()

    if df.empty:
        st.info("Aucune donnée disponible dans la base.")
    else:
        # --- Initialisation des variables de session ---
        if "matricule_search" not in st.session_state:
            st.session_state.matricule_search = ""
        if "pays_sel" not in st.session_state:
            st.session_state.pays_sel = []
        if "type_sel" not in st.session_state:
            st.session_state.type_sel = []
        if "date_start" not in st.session_state:
            st.session_state.date_start = None
        if "date_end" not in st.session_state:
            st.session_state.date_end = None

        # --- Options disponibles ---
        pays_options = sorted(df["Pays"].dropna().unique())
        type_options = sorted(df["Type"].dropna().unique())

        # Corriger les defaults invalides
        st.session_state.pays_sel = [p for p in st.session_state.pays_sel if p in pays_options]
        st.session_state.type_sel = [t for t in st.session_state.type_sel if t in type_options]

        # --- Formulaire de recherche ---
        with st.form("search_form"):
            col1, col2 = st.columns(2)
            with col1:
                matricule_search = st.text_input(
                    "🔍 Recherche par matricule",
                    st.session_state.matricule_search
                ).strip().upper()
                pays_sel = st.multiselect(
                    "🌍 Pays",
                    options=pays_options,
                    default=st.session_state.pays_sel
                )
            with col2:
                type_sel = st.multiselect(
                    "📦 Type MA",
                    options=type_options,
                    default=st.session_state.type_sel
                )
                date_start = st.date_input("📅 Date début", value=st.session_state.date_start)
                date_end = st.date_input("📅 Date fin", value=st.session_state.date_end)

            col_btn1, col_btn2 = st.columns([1, 1])
            with col_btn1:
                submit_search = st.form_submit_button("🔎 Rechercher")
            with col_btn2:
                reset_filters = st.form_submit_button("♻️ Réinitialiser les filtres")

        # --- Réinitialiser les filtres ---
        if reset_filters:
            st.session_state.matricule_search = ""
            st.session_state.pays_sel = []
            st.session_state.type_sel = []
            st.session_state.date_start = None
            st.session_state.date_end = None
            st.rerun()  # 🔹 relance l'app pour vider les champs

        # --- Si pas encore de recherche ---
        if not submit_search:
            st.info("Veuillez saisir vos critères et cliquer sur **Rechercher** pour afficher les résultats.")
        else:
            df["Date_ajout"] = pd.to_datetime(df["Date_ajout"], errors="coerce")
            df_filtered = df.copy()

            # --- Application des filtres ---
            if matricule_search:
                df_filtered = df_filtered[df_filtered["Matricule"].str.contains(matricule_search, case=False, na=False)]
                st.session_state.matricule_search = matricule_search
            if pays_sel:
                df_filtered = df_filtered[df_filtered["Pays"].isin(pays_sel)]
                st.session_state.pays_sel = pays_sel
            if type_sel:
                df_filtered = df_filtered[df_filtered["Type"].isin(type_sel)]
                st.session_state.type_sel = type_sel
            if date_start:
                df_filtered = df_filtered[df_filtered["Date_ajout"] >= pd.Timestamp(date_start)]
                st.session_state.date_start = date_start
            if date_end:
                df_filtered = df_filtered[df_filtered["Date_ajout"] <= pd.Timestamp(date_end)]
                st.session_state.date_end = date_end

            # --- Affichage résultat ---
            if df_filtered.empty:
                st.warning("⚠️ Aucun résultat trouvé pour ces critères.")
            else:
                df_affiche = df_filtered[["Matricule", "Reference_MA", "Pays", "Date_ajout", "Exporte"]].copy()
                df_affiche.columns = ["N°", "Réf. MA", "Pays", "Date", "Statut"]
                st.success(f"✅ {len(df_affiche)} résultat(s) trouvé(s)")
                st.dataframe(df_affiche, use_container_width=True)

                # --- Export Excel ---
                buffer = io.BytesIO()
                df_affiche.to_excel(buffer, index=False, engine="openpyxl")
                st.download_button(
                    "📥 Télécharger en Excel",
                    buffer.getvalue(),
                    file_name="resultats_filtrés.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

        # --- 10 dernières opérations (toujours visibles) ---
        st.subheader("📋 10 dernières opérations")
        df_recent = df.head(10)[["id", "Matricule", "Reference_MA", "Pays", "Date_ajout", "Exporte"]].copy()
        df_recent.columns = ["ID", "N°", "Réf. MA", "Pays", "Date", "Statut"]
        st.dataframe(df_recent, use_container_width=True)











