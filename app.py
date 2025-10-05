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
    st.subheader("Clôturer / Exporter des autorisations MA")

    # --- Helper : trouver le nom réel d'une colonne (tolérant casse/variantes) ---
    def get_col_name(df, *candidates):
        # retourne le nom exact de la colonne dans df si trouvé, sinon None
        cols_map = {c.lower(): c for c in df.columns}
        for cand in candidates:
            if cand and cand.lower() in cols_map:
                return cols_map[cand.lower()]
        return None

    # --- Récupérer toutes les données ---
    try:
        resp = supabase.table("autorisations_ma").select("*").execute()
        raw = resp.data
    except Exception as e:
        st.error(f"Erreur lors du chargement des MA depuis Supabase : {e}")
        raw = None

    df = pd.DataFrame(raw) if raw else pd.DataFrame()

    # Si pas de données
    if df.empty:
        st.info("Aucune MA disponible dans la base.")
        # On affiche quand même les 10 dernières clôtures (vide ici)
        st.subheader("📋 10 dernières clôtures")
        st.info("Aucune opération disponible.")
    else:
        # --- Préparer noms de colonnes utiles ---
        col_id = get_col_name(df, "id", "ID")
        col_mat = get_col_name(df, "Matricule", "matricule")
        col_ref = get_col_name(df, "Reference_MA", "Référence_MA", "reference_ma", "reference")
        col_pays = get_col_name(df, "Pays", "pays")
        col_date_add = get_col_name(df, "Date_ajout", "date_ajout", "Date", "date")
        col_exporte = get_col_name(df, "Exporte", "exporte", "Statut", "statut")
        col_type = get_col_name(df, "Type", "type")
        col_date_clot = get_col_name(df, "Date_cloture", "date_cloture", "Date_closure", "date_closure")

        # --- FORMULAIRE DE RECHERCHE (vide avant recherche) ---
        with st.form("export_search_form"):
            c1, c2, c3 = st.columns([2, 2, 1])
            with c1:
                matricule_in = st.text_input("🔍 Matricule", st.session_state.get("export_matricule", "")).strip().upper()
            with c2:
                ref_in = st.text_input("🔍 Référence MA", st.session_state.get("export_ref", "")).strip().upper()
            with c3:
                # boutons du form (chacun renvoie True quand cliqué)
                search_btn = st.form_submit_button("🔎 Rechercher")
                reset_btn = st.form_submit_button("♻️ Réinitialiser")

        # action Reset : vider le session_state et recharger
        if reset_btn:
            st.session_state.export_matricule = ""
            st.session_state.export_ref = ""
            st.rerun()

        # si clique Rechercher, on enregistre la recherche
        if search_btn:
            st.session_state.export_matricule = matricule_in
            st.session_state.export_ref = ref_in

        # --- CONDITION D'AFFICHAGE : rien si aucune recherche (champs vides) ---
        export_m = st.session_state.get("export_matricule", "")
        export_r = st.session_state.get("export_ref", "")
        performed_search = bool(export_m or export_r)

        if not performed_search:
            st.info("🔎 Entrez Matricule ou Référence MA puis cliquez sur 'Rechercher' pour afficher les résultats.")
        else:
            # Appliquer filtres sur le dataframe
            df_filtered = df.copy()
            if export_m and col_mat in df_filtered.columns:
                df_filtered = df_filtered[df_filtered[col_mat].astype(str).str.contains(export_m, case=False, na=False)]
            if export_r and col_ref in df_filtered.columns:
                df_filtered = df_filtered[df_filtered[col_ref].astype(str).str.contains(export_r, case=False, na=False)]

            if df_filtered.empty:
                st.warning("⚠️ Aucun résultat trouvé pour cette recherche.")
            else:
                # Créer affichage propre : ID | N | MA | Pays | Date
                # S'assurer que les colonnes existent sinon remplacer par vide
                def safe_col(dfrow, col):
                    return dfrow[col] if (col and col in dfrow.index and pd.notna(dfrow[col])) else ""

                # Construire df_display
                display_rows = []
                for _, row in df_filtered.iterrows():
                    id_val = row.get(col_id) if col_id in row.index else ""
                    n_val = row.get(col_mat) if col_mat in row.index else ""
                    ma_val = row.get(col_ref) if col_ref in row.index else ""
                    pays_val = row.get(col_pays) if col_pays in row.index else ""
                    date_val = row.get(col_date_add) if col_date_add in row.index else ""
                    # format date si possible
                    try:
                        if pd.notna(date_val):
                            date_val = pd.to_datetime(date_val).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        pass
                    display_rows.append({
                        "ID": id_val,
                        "N": n_val,
                        "MA": ma_val,
                        "Pays": pays_val,
                        "Date": date_val
                    })
                df_display = pd.DataFrame(display_rows)

                st.success(f"✅ {len(df_display)} autorisation(s) trouvée(s).")
                st.dataframe(df_display, use_container_width=True)

                # Export Excel des résultats filtrés
                try:
                    buffer = io.BytesIO()
                    df_display.to_excel(buffer, index=False, engine="openpyxl")
                    st.download_button(
                        "📥 Télécharger les résultats (Excel)",
                        buffer.getvalue(),
                        file_name="export_resultats.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
                except Exception as e:
                    st.error(f"Erreur lors de l'export Excel : {e}")

                # --- Sélection et clôture ---
                # Préparer selectbox avec label "ID | N | MA | Pays | Date"
                select_opts = [
                    f"{int(r['ID'])} | {r['N']} | {r['MA']} | {r['Pays']} | {r['Date']}"
                    for _, r in df_display.iterrows()
                ]
                selected_label = st.selectbox("Sélectionner une MA à clôturer", select_opts)

                # Extraire id sélectionné
                try:
                    selected_id = int(str(selected_label).split(" | ")[0])
                except Exception:
                    st.error("Impossible de lire l'ID sélectionné.")
                    selected_id = None

                if selected_id is not None:
                    # Récupérer la ligne complète de df_filtered correspondant à l'id
                    row_sel = df_filtered[df_filtered[col_id] == selected_id] if col_id in df_filtered.columns else pd.DataFrame()
                    if row_sel.empty:
                        # essayer cast string/int mismatch
                        row_sel = df_filtered[df_filtered[col_id].astype(str) == str(selected_id)] if col_id in df_filtered.columns else pd.DataFrame()

                    if row_sel.empty:
                        st.error("La MA sélectionnée n'a pas été trouvée (données incohérentes).")
                    else:
                        row_sel = row_sel.iloc[0]
                        type_selected = row_sel.get(col_type, "") if col_type in row_sel.index else ""
                        type_selected = str(type_selected).upper()

                        # Bouton initial pour demander clôture (créé ici)
                        if st.button("📤 Clôturer la sélection"):
                            specials = ["FOURGON", "SUBSAHARIEN", "T6BIS"]
                            if type_selected in specials:
                                st.warning(f"⚠️ Attention : vous êtes sur une MA de type {type_selected}. Confirmez la clôture ci-dessous.")
                                st.session_state["pending_close_id"] = selected_id
                            else:
                                # clôture immédiate
                                try:
                                    supabase.table("autorisations_ma").update({
                                        "Exporte": "Oui",
                                        "Cloture_par": st.session_state.get("username"),
                                        "Date_cloture": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    }).eq("id", selected_id).execute()
                                    st.success(f"✅ MA (ID {selected_id}) clôturée avec succès.")
                                    # refresh pour afficher changements
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Erreur lors de la clôture : {e}")

                        # Si on a mis en session pending_close_id, afficher bouton de confirmation
                        if st.session_state.get("pending_close_id") == selected_id:
                            if st.button(f"✅ Confirmer clôture {type_selected}"):
                                try:
                                    supabase.table("autorisations_ma").update({
                                        "Exporte": "Oui",
                                        "Cloture_par": st.session_state.get("username"),
                                        "Date_cloture": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    }).eq("id", selected_id).execute()
                                    st.success(f"✅ MA (ID {selected_id}) clôturée (confirmé).")
                                    # nettoie l'état pending et recharge
                                    del st.session_state["pending_close_id"]
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Erreur lors de la clôture confirmée : {e}")

        # --- 10 dernières clôtures (toujours visibles en bas) ---
st.subheader("📋 10 dernières clôtures")
try:
    # Filtrer Exporte == Oui (tolérance casse)
    if col_exporte and col_exporte in df.columns:
        df_closed = df[df[col_exporte].astype(str).str.upper() == "OUI"].copy()
    else:
        # fallback : si pas de colonne Exporte on cherche par Date_cloture non null
        df_closed = df[df[col_date_clot].notna()] if col_date_clot and col_date_clot in df.columns else pd.DataFrame()

    if not df_closed.empty:
        # trier par date_cloture si possible, sinon par id
        if col_date_clot and col_date_clot in df_closed.columns:
            df_closed[col_date_clot] = pd.to_datetime(df_closed[col_date_clot], errors="coerce")
            df_closed = df_closed.sort_values(by=col_date_clot, ascending=False)
        elif col_id and col_id in df_closed.columns:
            df_closed = df_closed.sort_values(by=col_id, ascending=False)

        # garder colonnes clefs si elles existent
        cols_keep = []
        for cand in [col_id, col_mat, col_ref, col_pays, col_date_clot]:
            if cand and cand in df_closed.columns:
                cols_keep.append(cand)

        df_closed_display = df_closed[cols_keep].head(10).copy()
        # renommer pour affichage
        rename_map = {}
        if col_id in df_closed_display.columns:
            rename_map[col_id] = "ID"
        if col_mat in df_closed_display.columns:
            rename_map[col_mat] = "N"
        if col_ref in df_closed_display.columns:
            rename_map[col_ref] = "MA"
        if col_pays in df_closed_display.columns:
            rename_map[col_pays] = "Pays"
        if col_date_clot in df_closed_display.columns:
            rename_map[col_date_clot] = "Date_cloture"
        df_closed_display = df_closed_display.rename(columns=rename_map)
        # formater date si presente
        if "Date_cloture" in df_closed_display.columns:
            df_closed_display["Date_cloture"] = pd.to_datetime(df_closed_display["Date_cloture"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")

        st.dataframe(df_closed_display, use_container_width=True)

        # --- Bouton Export Excel pour 10 dernières clôtures ---
        try:
            buffer_closed = io.BytesIO()
            df_closed_display.to_excel(buffer_closed, index=False, engine="openpyxl")
            st.download_button(
                "📥 Télécharger les 10 dernières clôtures (Excel)",
                buffer_closed.getvalue(),
                file_name="10_dernières_clotures.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        except Exception as e:
            st.error(f"Erreur lors de l'export Excel des dernières clôtures : {e}")

    else:
        st.info("Aucune MA clôturée trouvée.")
except Exception as e:
    st.error(f"Erreur lors du calcul des dernières clôtures : {e}")






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

        # Corriger les defaults invalides (évite StreamlitAPIException)
        st.session_state.pays_sel = [p for p in st.session_state.pays_sel if p in pays_options]
        st.session_state.type_sel = [t for t in st.session_state.type_sel if t in type_options]

        # --- Zone de recherche ---
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
            st.rerun()

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



