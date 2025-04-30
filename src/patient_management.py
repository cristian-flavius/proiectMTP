import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import xml.etree.ElementTree as ET
import os
import re
from datetime import datetime


class PatientManagementSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistem de Gestiune a Pacienților pentru Clinică")
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        # Variabile pentru autentificare
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.logged_in = False

        # Fișier XML pentru utilizatori și pacienți
        self.users_file = "users.xml"
        self.patients_file = "patients.xml"

        # Verifică dacă fișierele XML există, dacă nu, le creează
        self.check_xml_files()

        # Afișează ecranul de autentificare
        self.show_login_screen()

    def check_xml_files(self):
        # Verifică și creează fișierul de utilizatori dacă nu există
        if not os.path.exists(self.users_file):
            root = ET.Element("users")

            # Adaugă un utilizator implicit (admin/admin)
            user = ET.SubElement(root, "user")
            ET.SubElement(user, "username").text = "admin"
            ET.SubElement(user, "password").text = "admin"
            ET.SubElement(user, "role").text = "administrator"

            # Adaugă un utilizator normal (user/user)
            user = ET.SubElement(root, "user")
            ET.SubElement(user, "username").text = "user"
            ET.SubElement(user, "password").text = "user"
            ET.SubElement(user, "role").text = "operator"

            tree = ET.ElementTree(root)
            tree.write(self.users_file, encoding="utf-8", xml_declaration=True)

        # Verifică și creează fișierul de pacienți dacă nu există
        if not os.path.exists(self.patients_file):
            root = ET.Element("patients")

            # Adaugă câțiva pacienți de exemplu
            for i in range(1, 6):
                patient = ET.SubElement(root, "patient")
                ET.SubElement(patient, "id").text = str(i)
                ET.SubElement(patient, "cnp").text = f"1{'0' * 11}"[0:12 - len(str(i))] + str(i)
                ET.SubElement(patient, "nume").text = f"Nume{i}"
                ET.SubElement(patient, "prenume").text = f"Prenume{i}"
                ET.SubElement(patient, "varsta").text = str(20 + i)
                ET.SubElement(patient, "telefon").text = f"07{i * 10}123456"
                ET.SubElement(patient, "diagnostic").text = f"Diagnostic{i}"
                ET.SubElement(patient, "data_internare").text = f"2023-12-{i:02d}"

            tree = ET.ElementTree(root)
            tree.write(self.patients_file, encoding="utf-8", xml_declaration=True)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        self.clear_window()

        # Creează frame-ul pentru autentificare
        login_frame = ttk.Frame(self.root, padding=20)
        login_frame.pack(expand=True)

        # Titlu
        ttk.Label(login_frame, text="Autentificare", font=("Arial", 16, "bold")).grid(row=0, column=0, columnspan=2,
                                                                                      pady=20)

        # Utilizator
        ttk.Label(login_frame, text="Utilizator:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(login_frame, textvariable=self.username_var).grid(row=1, column=1, pady=5, padx=5)

        # Parolă
        ttk.Label(login_frame, text="Parolă:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Entry(login_frame, textvariable=self.password_var, show="*").grid(row=2, column=1, pady=5, padx=5)

        # Buton autentificare
        ttk.Button(login_frame, text="Autentificare", command=self.authenticate).grid(row=3, column=0, columnspan=2,
                                                                                      pady=20)

    def authenticate(self):
        username = self.username_var.get()
        password = self.password_var.get()

        # Validare câmpuri obligatorii
        if not username or not password:
            messagebox.showerror("Eroare", "Utilizatorul și parola sunt obligatorii!")
            return

        # Verificare autentificare din XML
        try:
            tree = ET.parse(self.users_file)
            root = tree.getroot()

            for user in root.findall("user"):
                user_name = user.find("username").text
                user_pass = user.find("password").text
                user_role = user.find("role").text

                if username == user_name and password == user_pass:
                    self.logged_in = True
                    self.current_user = {'username': username, 'role': user_role}
                    messagebox.showinfo("Succes", f"Bine ați venit, {username}!")
                    self.show_main_screen()
                    return

            messagebox.showerror("Eroare", "Utilizator sau parolă incorecte!")

        except Exception as e:
            messagebox.showerror("Eroare", f"A apărut o eroare la autentificare: {str(e)}")

    def show_main_screen(self):
        if not self.logged_in:
            self.show_login_screen()
            return

        self.clear_window()

        # Creează meniul principal
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # Meniu Fișier
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Fișier", menu=file_menu)
        file_menu.add_command(label="Ieșire", command=self.root.quit)

        # Meniu Pacienți
        patients_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Pacienți", menu=patients_menu)
        patients_menu.add_command(label="Adaugă Pacient", command=self.add_patient)
        patients_menu.add_command(label="Caută Pacient", command=self.search_patient)

        # Meniu Utilizatori (doar pentru admin)
        if self.current_user['role'] == 'administrator':
            users_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="Utilizatori", menu=users_menu)
            users_menu.add_command(label="Adaugă Utilizator", command=self.add_user)

        # Frame pentru tabel pacienți
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Label informativ
        ttk.Label(main_frame,
                  text=f"Utilizator autentificat: {self.current_user['username']} ({self.current_user['role']})",
                  font=("Arial", 10)).pack(anchor=tk.W, pady=5)

        # Titlu tabel
        ttk.Label(main_frame, text="Listă Pacienți", font=("Arial", 14, "bold")).pack(pady=10)

        # Frame pentru tabel și scrollbar
        table_frame = ttk.Frame(main_frame)
        table_frame.pack(fill=tk.BOTH, expand=True)

        # Scrollbar
        scrollbar = ttk.Scrollbar(table_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Treeview pentru afișarea pacienților
        self.patients_tree = ttk.Treeview(table_frame, yscrollcommand=scrollbar.set)
        self.patients_tree["columns"] = ("ID", "CNP", "Nume", "Prenume", "Vârstă", "Telefon", "Diagnostic",
                                         "Data Internare")

        # Configurare coloane
        self.patients_tree.column("#0", width=0, stretch=tk.NO)
        self.patients_tree.column("ID", width=50, anchor=tk.W)
        self.patients_tree.column("CNP", width=120, anchor=tk.W)
        self.patients_tree.column("Nume", width=100, anchor=tk.W)
        self.patients_tree.column("Prenume", width=100, anchor=tk.W)
        self.patients_tree.column("Vârstă", width=50, anchor=tk.W)
        self.patients_tree.column("Telefon", width=100, anchor=tk.W)
        self.patients_tree.column("Diagnostic", width=150, anchor=tk.W)
        self.patients_tree.column("Data Internare", width=100, anchor=tk.W)

        # Configurare heading-uri
        self.patients_tree.heading("#0", text="")
        self.patients_tree.heading("ID", text="ID")
        self.patients_tree.heading("CNP", text="CNP")
        self.patients_tree.heading("Nume", text="Nume")
        self.patients_tree.heading("Prenume", text="Prenume")
        self.patients_tree.heading("Vârstă", text="Vârstă")
        self.patients_tree.heading("Telefon", text="Telefon")
        self.patients_tree.heading("Diagnostic", text="Diagnostic")
        self.patients_tree.heading("Data Internare", text="Data Internare")

        # Asocierea scrollbar-ului cu treeview
        scrollbar.config(command=self.patients_tree.yview)

        # Poziționare treeview
        self.patients_tree.pack(fill=tk.BOTH, expand=True)

        # Încarcă datele în tabel
        self.load_patients_data()

        # Adaugă meniu context la click dreapta pe tabel
        self.create_context_menu()

        # Frame pentru butoane
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10, fill=tk.X)

        def logout(self) -> None:
            """Log the user out and return to the login screen."""
            self.logged_in = False
            self.show_login_screen()

        # Butoane pentru acțiuni
        ttk.Button(button_frame, text="Adaugă Pacient", command=self.add_patient).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Editează Pacient", command=self.edit_patient).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Șterge Pacient", command=self.delete_patient).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reîmprospătează", command=self.load_patients_data).pack(side=tk.LEFT, padx=5)
        tk.Button( button_frame, text="Ieșire",command=self.logout).pack(side=tk.RIGHT, padx=5)

    def create_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Editează", command=self.edit_patient)
        self.context_menu.add_command(label="Șterge", command=self.delete_patient)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Vizualizare detalii", command=self.view_patient_details)

        self.patients_tree.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        try:
            item = self.patients_tree.identify_row(event.y)
            if item:
                self.patients_tree.selection_set(item)
                self.context_menu.post(event.x_root, event.y_root)
        except Exception as e:
            print(f"Eroare la afișarea meniului contextual: {str(e)}")

    def load_patients_data(self):
        # Șterge datele existente
        for item in self.patients_tree.get_children():
            self.patients_tree.delete(item)

        try:
            # Încarcă datele din fișierul XML
            tree = ET.parse(self.patients_file)
            root = tree.getroot()

            for patient in root.findall("patient"):
                patient_id = patient.find("id").text
                cnp = patient.find("cnp").text
                nume = patient.find("nume").text
                prenume = patient.find("prenume").text
                varsta = patient.find("varsta").text
                telefon = patient.find("telefon").text
                diagnostic = patient.find("diagnostic").text
                data_internare = patient.find("data_internare").text

                self.patients_tree.insert("", tk.END,
                                          values=(patient_id, cnp, nume, prenume, varsta, telefon, diagnostic,
                                                  data_internare))

        except Exception as e:
            messagebox.showerror("Eroare", f"Eroare la încărcarea datelor: {str(e)}")

    def add_patient(self):
        # Deschide o fereastră pentru adăugarea unui nou pacient
        add_window = tk.Toplevel(self.root)
        add_window.title("Adaugă Pacient Nou")
        add_window.geometry("500x450")
        add_window.grab_set()  # Blochează fereastra principală

        # Frame pentru câmpuri
        frame = ttk.Frame(add_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # Variabile pentru câmpuri
        var_cnp = tk.StringVar()
        var_nume = tk.StringVar()
        var_prenume = tk.StringVar()
        var_varsta = tk.StringVar()
        var_telefon = tk.StringVar()
        var_diagnostic = tk.StringVar()
        var_data = tk.StringVar()

        # Setăm data curentă ca default
        var_data.set(datetime.now().strftime("%Y-%m-%d"))

        # Funcție pentru validare numerică
        def validate_numeric(P):
            return P.isdigit() or P == ""

        # Funcție pentru validarea CNP (13 cifre)
        def validate_cnp(P):
            if len(P) <= 13 and (P.isdigit() or P == ""):
                return True
            return False

        # Funcție pentru validarea telefonului (10 cifre)
        def validate_phone(P):
            if len(P) <= 10 and (P.isdigit() or P == ""):
                return True
            return False

        # Funcție pentru validarea datei (format YYYY-MM-DD)
        def validate_date(P):
            if P == "":
                return True
            pattern = re.compile(r'^\d{4}-\d{2}-\d{2}$')
            if pattern.match(P):
                try:
                    datetime.strptime(P, "%Y-%m-%d")
                    return True
                except ValueError:
                    return False
            return False

        # Înregistrare validatori
        vcmd_numeric = (add_window.register(validate_numeric), '%P')
        vcmd_cnp = (add_window.register(validate_cnp), '%P')
        vcmd_phone = (add_window.register(validate_phone), '%P')
        vcmd_date = (add_window.register(validate_date), '%P')

        # Etichete și câmpuri
        ttk.Label(frame, text="CNP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, textvariable=var_cnp, validate="key", validatecommand=vcmd_cnp).grid(row=0, column=1,
                                                                                              sticky=(tk.W, tk.E),
                                                                                              pady=5, padx=5)

        ttk.Label(frame, text="Nume:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, textvariable=var_nume).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        ttk.Label(frame, text="Prenume:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, textvariable=var_prenume).grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        ttk.Label(frame, text="Vârstă:").grid(row=3, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, textvariable=var_varsta, validate="key", validatecommand=vcmd_numeric).grid(row=3, column=1,
                                                                                                     sticky=(tk.W,
                                                                                                             tk.E),
                                                                                                     pady=5, padx=5)

        ttk.Label(frame, text="Telefon:").grid(row=4, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, textvariable=var_telefon, validate="key", validatecommand=vcmd_phone).grid(row=4, column=1,
                                                                                                    sticky=(tk.W, tk.E),
                                                                                                    pady=5, padx=5)

        ttk.Label(frame, text="Diagnostic:").grid(row=5, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, textvariable=var_diagnostic).grid(row=5, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        ttk.Label(frame, text="Data Internare (YYYY-MM-DD):").grid(row=6, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, textvariable=var_data, validate="key", validatecommand=vcmd_date).grid(row=6, column=1,
                                                                                                sticky=(tk.W, tk.E),
                                                                                                pady=5, padx=5)

        # Informații validare
        ttk.Label(frame, text="* CNP trebuie să aibă 13 cifre", font=("Arial", 8)).grid(row=7, column=0, columnspan=2,
                                                                                        sticky=tk.W, pady=2)
        ttk.Label(frame, text="* Telefon trebuie să aibă 10 cifre", font=("Arial", 8)).grid(row=8, column=0,
                                                                                            columnspan=2, sticky=tk.W,
                                                                                            pady=2)
        ttk.Label(frame, text="* Data trebuie să fie în formatul YYYY-MM-DD", font=("Arial", 8)).grid(row=9, column=0,
                                                                                                      columnspan=2,
                                                                                                      sticky=tk.W,
                                                                                                      pady=2)

        # Funcția pentru salvare
        def save_patient():
            # Validare câmpuri obligatorii
            if not var_cnp.get() or not var_nume.get() or not var_prenume.get():
                messagebox.showerror("Eroare", "CNP, Nume și Prenume sunt câmpuri obligatorii!")
                return

            # Validare CNP - exact 13 cifre
            if len(var_cnp.get()) != 13:
                messagebox.showerror("Eroare", "CNP-ul trebuie să aibă exact 13 cifre!")
                return

            # Validare telefon - exact 10 cifre
            if var_telefon.get() and len(var_telefon.get()) != 10:
                messagebox.showerror("Eroare", "Numărul de telefon trebuie să aibă exact 10 cifre!")
                return

            # Validare dată
            if var_data.get():
                try:
                    datetime.strptime(var_data.get(), "%Y-%m-%d")
                except ValueError:
                    messagebox.showerror("Eroare", "Data trebuie să fie în formatul YYYY-MM-DD!")
                    return

            try:
                # Încărcăm fișierul XML
                tree = ET.parse(self.patients_file)
                root = tree.getroot()

                # Generăm un ID nou
                max_id = 0
                for patient in root.findall("patient"):
                    patient_id = int(patient.find("id").text)
                    if patient_id > max_id:
                        max_id = patient_id

                # Creăm un nou element patient
                new_patient = ET.SubElement(root, "patient")
                ET.SubElement(new_patient, "id").text = str(max_id + 1)
                ET.SubElement(new_patient, "cnp").text = var_cnp.get()
                ET.SubElement(new_patient, "nume").text = var_nume.get()
                ET.SubElement(new_patient, "prenume").text = var_prenume.get()
                ET.SubElement(new_patient, "varsta").text = var_varsta.get() if var_varsta.get() else ""
                ET.SubElement(new_patient, "telefon").text = var_telefon.get() if var_telefon.get() else ""
                ET.SubElement(new_patient, "diagnostic").text = var_diagnostic.get() if var_diagnostic.get() else ""
                ET.SubElement(new_patient, "data_internare").text = var_data.get() if var_data.get() else ""

                # Salvăm fișierul
                tree.write(self.patients_file, encoding="utf-8", xml_declaration=True)

                messagebox.showinfo("Succes", "Pacient adăugat cu succes!")
                add_window.destroy()

                # Reîncărcăm datele în tabel
                self.load_patients_data()

            except Exception as e:
                messagebox.showerror("Eroare", f"Eroare la salvarea datelor: {str(e)}")

        # Butoane
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=10, column=0, columnspan=2, pady=20)

        ttk.Button(button_frame, text="Salvează", command=save_patient).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Anulează", command=add_window.destroy).pack(side=tk.LEFT, padx=5)

    def edit_patient(self):
        # Verifică dacă este selectat un pacient
        selected_items = self.patients_tree.selection()
        if not selected_items:
            messagebox.showwarning("Avertisment", "Vă rugăm să selectați un pacient pentru editare!")
            return

        # Obține ID-ul pacientului selectat
        patient_id = self.patients_tree.item(selected_items[0], "values")[0]

        try:
            # Încarcă datele pacientului din XML
            tree = ET.parse(self.patients_file)
            root = tree.getroot()

            patient_elem = None
            for patient in root.findall("patient"):
                if patient.find("id").text == patient_id:
                    patient_elem = patient
                    break

            if not patient_elem:
                messagebox.showerror("Eroare", "Pacientul nu a fost găsit în baza de date!")
                return

            # Deschide o fereastră pentru editarea pacientului
            edit_window = tk.Toplevel(self.root)
            edit_window.title(f"Editează Pacient - ID: {patient_id}")
            edit_window.geometry("500x450")
            edit_window.grab_set()  # Blochează fereastra principală

            # Frame pentru câmpuri
            frame = ttk.Frame(edit_window, padding=20)
            frame.pack(fill=tk.BOTH, expand=True)

            # Variabile pentru câmpuri
            var_cnp = tk.StringVar(value=patient_elem.find("cnp").text)
            var_nume = tk.StringVar(value=patient_elem.find("nume").text)
            var_prenume = tk.StringVar(value=patient_elem.find("prenume").text)
            var_varsta = tk.StringVar(
                value=patient_elem.find("varsta").text if patient_elem.find("varsta") is not None and patient_elem.find(
                    "varsta").text else "")
            var_telefon = tk.StringVar(value=patient_elem.find("telefon").text if patient_elem.find(
                "telefon") is not None and patient_elem.find("telefon").text else "")
            var_diagnostic = tk.StringVar(value=patient_elem.find("diagnostic").text if patient_elem.find(
                "diagnostic") is not None and patient_elem.find("diagnostic").text else "")
            var_data = tk.StringVar(value=patient_elem.find("data_internare").text if patient_elem.find(
                "data_internare") is not None and patient_elem.find("data_internare").text else "")

            # Funcții de validare (la fel ca la add_patient)
            def validate_numeric(P):
                return P.isdigit() or P == ""

            def validate_cnp(P):
                if len(P) <= 13 and (P.isdigit() or P == ""):
                    return True
                return False

            def validate_phone(P):
                if len(P) <= 10 and (P.isdigit() or P == ""):
                    return True
                return False

            def validate_date(P):
                if P == "":
                    return True
                pattern = re.compile(r'^\d{4}-\d{2}-\d{2}$')
                if pattern.match(P):
                    try:
                        datetime.strptime(P, "%Y-%m-%d")
                        return True
                    except ValueError:
                        return False
                return False

            # Înregistrare validatori
            vcmd_numeric = (edit_window.register(validate_numeric), '%P')
            vcmd_cnp = (edit_window.register(validate_cnp), '%P')
            vcmd_phone = (edit_window.register(validate_phone), '%P')
            vcmd_date = (edit_window.register(validate_date), '%P')

            # Etichete și câmpuri
            ttk.Label(frame, text="CNP:").grid(row=0, column=0, sticky=tk.W, pady=5)
            ttk.Entry(frame, textvariable=var_cnp, validate="key", validatecommand=vcmd_cnp).grid(row=0, column=1,
                                                                                                  sticky=(tk.W, tk.E),
                                                                                                  pady=5, padx=5)

            ttk.Label(frame, text="Nume:").grid(row=1, column=0, sticky=tk.W, pady=5)
            ttk.Entry(frame, textvariable=var_nume).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

            ttk.Label(frame, text="Prenume:").grid(row=2, column=0, sticky=tk.W, pady=5)
            ttk.Entry(frame, textvariable=var_prenume).grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

            ttk.Label(frame, text="Vârstă:").grid(row=3, column=0, sticky=tk.W, pady=5)
            ttk.Entry(frame, textvariable=var_varsta, validate="key", validatecommand=vcmd_numeric).grid(row=3,
                                                                                                         column=1,
                                                                                                         sticky=(tk.W,
                                                                                                                 tk.E),
                                                                                                         pady=5, padx=5)

            ttk.Label(frame, text="Telefon:").grid(row=4, column=0, sticky=tk.W, pady=5)
            ttk.Entry(frame, textvariable=var_telefon, validate="key", validatecommand=vcmd_phone).grid(row=4, column=1,
                                                                                                        sticky=(tk.W,
                                                                                                                tk.E),
                                                                                                        pady=5, padx=5)

            ttk.Label(frame, text="Diagnostic:").grid(row=5, column=0, sticky=tk.W, pady=5)
            ttk.Entry(frame, textvariable=var_diagnostic).grid(row=5, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

            ttk.Label(frame, text="Data Internare (YYYY-MM-DD):").grid(row=6, column=0, sticky=tk.W, pady=5)
            ttk.Entry(frame, textvariable=var_data, validate="key", validatecommand=vcmd_date).grid(row=6, column=1,
                                                                                                    sticky=(tk.W, tk.E),
                                                                                                    pady=5, padx=5)

            # Informații validare
            ttk.Label(frame, text="* CNP trebuie să aibă 13 cifre", font=("Arial", 8)).grid(row=7, column=0,
                                                                                            columnspan=2, sticky=tk.W,
                                                                                            pady=2)
            ttk.Label(frame, text="* Telefon trebuie să aibă 10 cifre", font=("Arial", 8)).grid(row=8, column=0,
                                                                                                columnspan=2,
                                                                                                sticky=tk.W, pady=2)
            ttk.Label(frame, text="* Data trebuie să fie în formatul YYYY-MM-DD", font=("Arial", 8)).grid(row=9,
                                                                                                          column=0,
                                                                                                          columnspan=2,
                                                                                                          sticky=tk.W,
                                                                                                          pady=2)

            # Funcția pentru salvare
            def update_patient():
                # Validare câmpuri obligatorii
                if not var_cnp.get() or not var_nume.get() or not var_prenume.get():
                    messagebox.showerror("Eroare", "CNP, Nume și Prenume sunt câmpuri obligatorii!")
                    return

                # Validare CNP - exact 13 cifre
                if len(var_cnp.get()) != 13:
                    messagebox.showerror("Eroare", "CNP-ul trebuie să aibă exact 13 cifre!")
                    return

                # Validare telefon - exact 10 cifre
                if var_telefon.get() and len(var_telefon.get()) != 10:
                    messagebox.showerror("Eroare", "Numărul de telefon trebuie să aibă exact 10 cifre!")
                    return

                # Validare dată
                if var_data.get():
                    try:
                        datetime.strptime(var_data.get(), "%Y-%m-%d")
                    except ValueError:
                        messagebox.showerror("Eroare", "Data trebuie să fie în formatul YYYY-MM-DD!")
                        return

                try:
                    # Actualizăm datele pacientului
                    patient_elem.find("cnp").text = var_cnp.get()
                    patient_elem.find("nume").text = var_nume.get()
                    patient_elem.find("prenume").text = var_prenume.get()

                    # Actualizăm elementele opționale
                    if patient_elem.find("varsta") is not None:
                        patient_elem.find("varsta").text = var_varsta.get()
                    else:
                        ET.SubElement(patient_elem, "varsta").text = var_varsta.get()

                    if patient_elem.find("telefon") is not None:
                        patient_elem.find("telefon").text = var_telefon.get()
                    else:
                        ET.SubElement(patient_elem, "telefon").text = var_telefon.get()

                    if patient_elem.find("diagnostic") is not None:
                        patient_elem.find("diagnostic").text = var_diagnostic.get()
                    else:
                        ET.SubElement(patient_elem, "diagnostic").text = var_diagnostic.get()

                    if patient_elem.find("data_internare") is not None:
                        patient_elem.find("data_internare").text = var_data.get()
                    else:
                        ET.SubElement(patient_elem, "data_internare").text = var_data.get()

                    # Salvăm fișierul
                    tree.write(self.patients_file, encoding="utf-8", xml_declaration=True)

                    messagebox.showinfo("Succes", "Datele pacientului au fost actualizate cu succes!")
                    edit_window.destroy()

                    # Reîncărcăm datele în tabel
                    self.load_patients_data()

                except Exception as e:
                    messagebox.showerror("Eroare", f"Eroare la actualizarea datelor: {str(e)}")

            # Butoane
            button_frame = ttk.Frame(frame)
            button_frame.grid(row=10, column=0, columnspan=2, pady=20)

            ttk.Button(button_frame, text="Salvează", command=update_patient).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Anulează", command=edit_window.destroy).pack(side=tk.LEFT, padx=5)

        except Exception as e:
            messagebox.showerror("Eroare", f"Eroare la încărcarea datelor pacientului: {str(e)}")

    def delete_patient(self):
        # Verifică dacă este selectat un pacient
        selected_items = self.patients_tree.selection()
        if not selected_items:
            messagebox.showwarning("Avertisment", "Vă rugăm să selectați un pacient pentru ștergere!")
            return

        # Obține ID-ul pacientului selectat
        patient_id = self.patients_tree.item(selected_items[0], "values")[0]
        patient_name = self.patients_tree.item(selected_items[0], "values")[2] + " " + \
                       self.patients_tree.item(selected_items[0], "values")[3]

        # Confirmă ștergerea
        confirm = messagebox.askyesno("Confirmare",
                                      f"Sunteți sigur că doriți să ștergeți pacientul {patient_name} (ID: {patient_id})?")
        if not confirm:
            return

        try:
            # Încarcă fișierul XML
            tree = ET.parse(self.patients_file)
            root = tree.getroot()

            # Găsește și șterge pacientul
            for patient in root.findall("patient"):
                if patient.find("id").text == patient_id:
                    root.remove(patient)
                    break

            # Salvează fișierul
            tree.write(self.patients_file, encoding="utf-8", xml_declaration=True)

            messagebox.showinfo("Succes", f"Pacientul {patient_name} a fost șters cu succes!")

            # Reîncărcăm datele în tabel
            self.load_patients_data()

        except Exception as e:
            messagebox.showerror("Eroare", f"Eroare la ștergerea pacientului: {str(e)}")

    def search_patient(self):
        # Deschide o fereastră pentru căutare
        search_window = tk.Toplevel(self.root)
        search_window.title("Caută Pacient")
        search_window.geometry("400x250")
        search_window.grab_set()  # Blochează fereastra principală

        # Frame pentru câmpuri
        frame = ttk.Frame(search_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # Variabile pentru căutare
        search_type = tk.StringVar(value="cnp")
        search_text = tk.StringVar()

        # Etichete și câmpuri
        ttk.Label(frame, text="Caută după:").grid(row=0, column=0, sticky=tk.W, pady=5)

        # Opțiuni de căutare
        search_options = ttk.Combobox(frame, textvariable=search_type)
        search_options['values'] = ('cnp', 'nume', 'prenume', 'diagnostic')
        search_options['state'] = 'readonly'
        search_options.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        ttk.Label(frame, text="Text căutare:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, textvariable=search_text).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        # Funcția pentru căutare
        def do_search():
            search_value = search_text.get().strip()
            if not search_value:
                messagebox.showwarning("Avertisment", "Vă rugăm să introduceți un text de căutare!")
                return

            field = search_type.get()

            try:
                # Încarcă fișierul XML
                tree = ET.parse(self.patients_file)
                root = tree.getroot()

                # Șterge selecțiile anterioare
                for item in self.patients_tree.selection():
                    self.patients_tree.selection_remove(item)

                # Caută și selectează pacienții care se potrivesc
                found = False
                for i, item in enumerate(self.patients_tree.get_children()):
                    values = self.patients_tree.item(item, "values")

                    # Stabilește indexul coloanei pentru căutare
                    if field == "cnp":
                        col_index = 1
                    elif field == "nume":
                        col_index = 2
                    elif field == "prenume":
                        col_index = 3
                    elif field == "diagnostic":
                        col_index = 6
                    else:
                        col_index = 2  # Default la nume

                    # Verifică dacă valoarea conține textul căutat (case insensitive)
                    if search_value.lower() in str(values[col_index]).lower():
                        self.patients_tree.selection_add(item)
                        self.patients_tree.see(item)  # Asigură că elementul este vizibil
                        found = True

                # Afișează un mesaj cu rezultatul căutării
                if found:
                    search_window.destroy()
                else:
                    messagebox.showinfo("Informație",
                                        "Nu a fost găsit niciun pacient care să corespundă criteriilor de căutare!")

            except Exception as e:
                messagebox.showerror("Eroare", f"Eroare la căutare: {str(e)}")

        # Butoane
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=20)

        ttk.Button(button_frame, text="Caută", command=do_search).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Anulează", command=search_window.destroy).pack(side=tk.LEFT, padx=5)

    def view_patient_details(self):
        # Verifică dacă este selectat un pacient
        selected_items = self.patients_tree.selection()
        if not selected_items:
            messagebox.showwarning("Avertisment", "Vă rugăm să selectați un pacient pentru vizualizare!")
            return

        # Obține datele pacientului selectat
        values = self.patients_tree.item(selected_items[0], "values")

        # Deschide o fereastră pentru afișarea detaliilor
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Detalii Pacient - {values[2]} {values[3]}")
        details_window.geometry("400x350")

        # Frame pentru detalii
        frame = ttk.Frame(details_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # Afișează detaliile
        ttk.Label(frame, text="Detalii Pacient", font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2,
                                                                                  pady=10)

        ttk.Label(frame, text="ID:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=values[0]).grid(row=1, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="CNP:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=values[1]).grid(row=2, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="Nume:").grid(row=3, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=values[2]).grid(row=3, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="Prenume:").grid(row=4, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=values[3]).grid(row=4, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="Vârstă:").grid(row=5, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=values[4]).grid(row=5, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="Telefon:").grid(row=6, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=values[5]).grid(row=6, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="Diagnostic:").grid(row=7, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=values[6]).grid(row=7, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="Data Internare:").grid(row=8, column=0, sticky=tk.W, pady=5)
        ttk.Label(frame, text=values[7]).grid(row=8, column=1, sticky=tk.W, pady=5)

        # Buton închidere
        ttk.Button(frame, text="Închide", command=details_window.destroy).grid(row=9, column=0, columnspan=2, pady=20)

    def add_user(self):
        # Doar administratorii pot adăuga utilizatori
        if self.current_user['role'] != 'administrator':
            messagebox.showerror("Eroare", "Doar administratorii pot adăuga utilizatori!")
            return

        # Deschide o fereastră pentru adăugarea unui nou utilizator
        add_window = tk.Toplevel(self.root)
        add_window.title("Adaugă Utilizator Nou")
        add_window.geometry("400x250")
        add_window.grab_set()  # Blochează fereastra principală

        # Frame pentru câmpuri
        frame = ttk.Frame(add_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # Variabile pentru câmpuri
        var_username = tk.StringVar()
        var_password = tk.StringVar()
        var_role = tk.StringVar(value="operator")

        # Etichete și câmpuri
        ttk.Label(frame, text="Nume utilizator:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, textvariable=var_username).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        ttk.Label(frame, text="Parolă:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(frame, textvariable=var_password, show="*").grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        ttk.Label(frame, text="Rol:").grid(row=2, column=0, sticky=tk.W, pady=5)

        # Opțiuni pentru rol
        role_options = ttk.Combobox(frame, textvariable=var_role)
        role_options['values'] = ('operator', 'administrator')
        role_options['state'] = 'readonly'
        role_options.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        # Funcția pentru salvare
        def save_user():
            # Validare câmpuri obligatorii
            if not var_username.get() or not var_password.get():
                messagebox.showerror("Eroare", "Numele de utilizator și parola sunt obligatorii!")
                return

            try:
                # Încarcă fișierul XML
                tree = ET.parse(self.users_file)
                root = tree.getroot()

                # Verifică dacă numele de utilizator există deja
                for user in root.findall("user"):
                    if user.find("username").text == var_username.get():
                        messagebox.showerror("Eroare", "Acest nume de utilizator există deja!")
                        return

                # Adaugă utilizatorul nou
                new_user = ET.SubElement(root, "user")
                ET.SubElement(new_user, "username").text = var_username.get()
                ET.SubElement(new_user, "password").text = var_password.get()
                ET.SubElement(new_user, "role").text = var_role.get()

                # Salvează fișierul
                tree.write(self.users_file, encoding="utf-8", xml_declaration=True)

                messagebox.showinfo("Succes", "Utilizator adăugat cu succes!")
                add_window.destroy()

            except Exception as e:
                messagebox.showerror("Eroare", f"Eroare la salvarea utilizatorului: {str(e)}")

        # Butoane
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)

        ttk.Button(button_frame, text="Salvează", command=save_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Anulează", command=add_window.destroy).pack(side=tk.LEFT, padx=5)


if __name__ == "__main__":
    root = tk.Tk()
    app = PatientManagementSystem(root)
    root.mainloop()