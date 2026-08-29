import tkinter as tk
from tkinter import ttk
from gui_app import IoMT_IDS_App


def main():
    root = tk.Tk()
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    app = IoMT_IDS_App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
