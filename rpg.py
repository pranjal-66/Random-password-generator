import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import string
import secrets
import csv
import os
from datetime import datetime

APP_TITLE = "Random Password Generator"

# ---------- Helper functions ----------
def build_charset(ups, lows, nums, syms, exclude):
    pool = ""
    if ups:
        pool += string.ascii_uppercase
    if lows:
        pool += string.ascii_lowercase
    if nums:
        pool += string.digits
    if syms:
        pool += string.punctuation
    # Remove excluded characters
    if exclude:
        pool = ''.join(ch for ch in pool if ch not in exclude)
    return pool

def secure_shuffle(chars):
    # secrets.SystemRandom has shuffle via random.sample
    return ''.join(secrets.choice(chars) for _ in range(len(chars)))

def estimate_strength(pw):
    length = len(pw)
    variety = 0
    if any(c.islower() for c in pw): variety += 1
    if any(c.isupper() for c in pw): variety += 1
    if any(c.isdigit() for c in pw): variety += 1
    if any(c in string.punctuation for c in pw): variety += 1

    score = variety + (0 if length < 8 else (1 if length < 12 else 2))  # range roughly 0-6

    if score <= 1:
        return "Very Weak", 10
    elif score == 2:
        return "Weak", 30
    elif score == 3:
        return "Medium", 55
    elif score == 4:
        return "Strong", 75
    else:
        return "Very Strong", 95

# ---------- Core generation ----------
history = []  # store tuples (timestamp, password, settings)

def generate_password():
    try:
        length = int(length_var.get())
    except Exception:
        messagebox.showerror("Invalid length", "Please enter a valid number for length.")
        return

    if length < 1:
        messagebox.showerror("Invalid length", "Password length must be at least 1.")
        return

    ups = uppercase_var.get()
    lows = lowercase_var.get()
    nums = numbers_var.get()
    syms = symbols_var.get()
    exclude = exclude_var.get()
    enforce = enforce_var.get()

    charset = build_charset(ups, lows, nums, syms, exclude)
    if not charset:
        messagebox.showerror("No character types", "Select at least one character type and ensure exclude characters don't remove everything.")
        return

    # Build password ensuring rules if enforce is True
    password_chars = []

    if enforce:
        # For each selected type, add at least one from that category
        if ups:
            ch = secrets.choice(''.join(c for c in string.ascii_uppercase if c not in exclude))
            password_chars.append(ch)
        if lows:
            ch = secrets.choice(''.join(c for c in string.ascii_lowercase if c not in exclude))
            password_chars.append(ch)
        if nums:
            ch = secrets.choice(''.join(c for c in string.digits if c not in exclude))
            password_chars.append(ch)
        if syms:
            available_syms = ''.join(c for c in string.punctuation if c not in exclude)
            if not available_syms and syms:
                messagebox.showerror("Excluded symbols", "You've excluded all symbol characters but Symbols is selected.")
                return
            ch = secrets.choice(available_syms) if syms else ''
            if ch: password_chars.append(ch)

    # Fill the rest
    remaining = length - len(password_chars)
    password_chars += [secrets.choice(charset) for _ in range(max(0, remaining))]

    # Shuffle securely
    secrets.SystemRandom().shuffle(password_chars)
    password = ''.join(password_chars)

    # Put into UI
    password_var.set(password)
    show_password_var.set(1)  # show by default in desktop app

    # Update strength
    rating, pct = estimate_strength(password)
    strength_label_var.set(f"{rating} ({len(password)} chars)")
    strength_bar['value'] = pct

    # Add to history
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    settings = f"len={length},U={ups},L={lows},N={nums},S={syms},enforce={enforce}"
    history.append((ts, password, settings))
    update_history_listbox()

def copy_password():
    pw = password_var.get()
    if not pw:
        messagebox.showwarning("No password", "Generate a password first.")
        return
    root.clipboard_clear()
    root.clipboard_append(pw)
    messagebox.showinfo("Copied", "Password copied to clipboard.")

def save_history_csv():
    if not history:
        messagebox.showinfo("No history", "No passwords in history to save.")
        return
    fn = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv"),("All files","*.*")])
    if not fn:
        return
    try:
        with open(fn, "w", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp","password","settings"])
            writer.writerows(history)
        messagebox.showinfo("Saved", f"History saved to {os.path.basename(fn)}")
    except Exception as e:
        messagebox.showerror("Save failed", str(e))

def clear_history():
    global history
    if not history:
        return
    if messagebox.askyesno("Clear history", "Are you sure you want to clear the saved history in this session?"):
        history = []
        update_history_listbox()

def update_history_listbox():
    hist_listbox.delete(0, tk.END)
    for ts, pw, settings in reversed(history[-100:]):  # show last 100
        hist_listbox.insert(tk.END, f"{ts} | {pw} | {settings}")

def toggle_show_password():
    if show_password_var.get():
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

# ---------- Build UI ----------
root = tk.Tk()
root.title(APP_TITLE)
root.geometry("560x520")
root.resizable(False, False)

style = ttk.Style(root)
# Attempt to choose a modern theme
try:
    style.theme_use('clam')
except Exception:
    pass

# Global frame with padding
main = ttk.Frame(root, padding=(18, 18, 18, 18))
main.pack(fill=tk.BOTH, expand=True)

# Title
title_label = ttk.Label(main, text="Random Password Generator", font=("Segoe UI", 18, "bold"))
title_label.pack(anchor="center", pady=(0,12))

# Settings frame
settings_frame = ttk.Labelframe(main, text="Settings", padding=(12,12))
settings_frame.pack(fill=tk.X, padx=6, pady=6)

# Length slider and entry
length_row = ttk.Frame(settings_frame)
length_row.pack(fill=tk.X, pady=6)
ttk.Label(length_row, text="Length:", width=10).pack(side=tk.LEFT)
length_var = tk.IntVar(value=16)
length_slider = ttk.Scale(length_row, from_=4, to=64, orient=tk.HORIZONTAL, command=lambda e: length_var.set(int(float(e))))
length_slider.set(16)
length_slider.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4,8))
length_entry = ttk.Entry(length_row, textvariable=length_var, width=6, justify="center")
length_entry.pack(side=tk.LEFT)

# Character toggles
toggles_frame = ttk.Frame(settings_frame)
toggles_frame.pack(fill=tk.X, pady=6)
uppercase_var = tk.BooleanVar(value=True)
lowercase_var = tk.BooleanVar(value=True)
numbers_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=True)

ttk.Checkbutton(toggles_frame, text="Uppercase (A-Z)", variable=uppercase_var).grid(row=0,column=0,sticky="w",padx=6,pady=4)
ttk.Checkbutton(toggles_frame, text="Lowercase (a-z)", variable=lowercase_var).grid(row=0,column=1,sticky="w",padx=6,pady=4)
ttk.Checkbutton(toggles_frame, text="Numbers (0-9)", variable=numbers_var).grid(row=1,column=0,sticky="w",padx=6,pady=4)
ttk.Checkbutton(toggles_frame, text="Symbols (!@#...)", variable=symbols_var).grid(row=1,column=1,sticky="w",padx=6,pady=4)

# Enforce rules & exclude
options_frame = ttk.Frame(settings_frame)
options_frame.pack(fill=tk.X, pady=6)
enforce_var = tk.BooleanVar(value=True)
ttk.Checkbutton(options_frame, text="Enforce strong rules (ensure types present)", variable=enforce_var).pack(side=tk.LEFT, padx=6)

exclude_frame = ttk.Frame(settings_frame)
exclude_frame.pack(fill=tk.X, pady=(8,0))
ttk.Label(exclude_frame, text="Exclude characters (optional):") \
    .pack(side=tk.LEFT, padx=(0, 6))
exclude_var = tk.StringVar(value="")
exclude_entry = ttk.Entry(exclude_frame, textvariable=exclude_var)
exclude_entry.pack(side=tk.LEFT, fill=tk.X, expand=True )

# Generate button and actions
actions_frame = ttk.Frame(main)
actions_frame.pack(fill=tk.X, pady=(8,6))
generate_btn = ttk.Button(actions_frame, text="Generate Password", command=generate_password)
generate_btn.pack(side=tk.LEFT, padx=(0,8))
copy_btn = ttk.Button(actions_frame, text="Copy to Clipboard", command=copy_password)
copy_btn.pack(side=tk.LEFT)
save_btn = ttk.Button(actions_frame, text="Export History (CSV)", command=save_history_csv)
save_btn.pack(side=tk.RIGHT)

# Password display
display_frame = ttk.Frame(main, padding=(0,8))
display_frame.pack(fill=tk.X)
password_var = tk.StringVar()
show_password_var = tk.IntVar(value=1)
password_entry = ttk.Entry(display_frame, textvariable=password_var, font=("Courier New", 12), justify="center")
password_entry.pack(fill=tk.X, padx=2, pady=(0,6))
ttk.Checkbutton(display_frame, text="Show Password", variable=show_password_var, command=toggle_show_password).pack(anchor="w")

# Strength meter
strength_frame = ttk.Frame(main)
strength_frame.pack(fill=tk.X, pady=(8,4))
strength_label_var = tk.StringVar(value="Strength:")
strength_label = ttk.Label(strength_frame, textvariable=strength_label_var)
strength_label.pack(side=tk.LEFT)
strength_bar = ttk.Progressbar(strength_frame, orient=tk.HORIZONTAL, length=240, mode='determinate')
strength_bar.pack(side=tk.RIGHT)

# History box
history_frame = ttk.Labelframe(main, text="Session History (latest first)", padding=(8,8))
history_frame.pack(fill=tk.BOTH, expand=True, pady=(10,0))
hist_listbox = tk.Listbox(history_frame, height=6, font=("Consolas",9))
hist_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
hist_scroll = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=hist_listbox.yview)
hist_scroll.pack(side=tk.RIGHT, fill=tk.Y)
hist_listbox.config(yscrollcommand=hist_scroll.set)

# Clear history button
bottom_frame = ttk.Frame(main)
bottom_frame.pack(fill=tk.X, pady=(6,0))
ttk.Button(bottom_frame, text="Clear History", command=clear_history).pack(side=tk.LEFT)

# Fill a default password at start
generate_password()

# Start loop
root.mainloop()
