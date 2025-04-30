# main.py - Fișier de execuție pentru aplicație

import tkinter as tk
from patient_management import PatientManagementSystem

if __name__ == "__main__":
    root = tk.Tk()
    app = PatientManagementSystem(root)
    root.mainloop()