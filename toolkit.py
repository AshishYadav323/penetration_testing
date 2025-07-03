import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import paramiko
import time
import re
from concurrent.futures import ThreadPoolExecutor

# --- Utility Functions ---
def is_valid_ip(ip):
    """Validate IP address format."""
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(pattern, ip) is not None

def is_valid_port(port):
    """Validate port number."""
    try:
        port = int(port)
        return 1 <= port <= 65535
    except ValueError:
        return False

# --- Port Scanner Module ---
class PortScanner:
    def __init__(self, output_widget):
        self.output_widget = output_widget
        self.stop_flag = False

    def scan_port(self, ip, port):
        """Scan a single port on the target IP."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port, result == 0
        except Exception as e:
            return port, False, str(e)

    def scan(self, ip, start_port, end_port):
        """Scan a range of ports on the target IP."""
        self.stop_flag = False
        open_ports = []
        self.output_widget.insert(tk.END, f"Starting port scan on {ip}...\n")
        self.output_widget.see(tk.END)

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(self.scan_port, ip, port) for port in range(start_port, end_port + 1)]
            for future in futures:
                if self.stop_flag:
                    break
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    self.output_widget.insert(tk.END, f"Port {port} is open\n")
                    self.output_widget.see(tk.END)

        return open_ports

    def stop(self):
        """Stop the port scanning process."""
        self.stop_flag = True
        self.output_widget.insert(tk.END, "Port scan stopped.\n")
        self.output_widget.see(tk.END)

# --- Brute Forcer Module ---
class BruteForcer:
    def __init__(self, output_widget):
        self.output_widget = output_widget
        self.stop_flag = False

    def try_ssh_login(self, ip, username, password, port=22):
        """Attempt SSH login with given credentials."""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, port=port, username=username, password=password, timeout=5)
            ssh.close()
            return True, f"Success: {username}:{password}"
        except Exception as e:
            return False, f"Failed: {username}:{password} - {str(e)}"

    def brute_force_ssh(self, ip, usernames, passwords, port=22):
        """Perform SSH brute force attack."""
        self.stop_flag = False
        self.output_widget.insert(tk.END, f"Starting SSH brute force on {ip}:{port}...\n")
        self.output_widget.see(tk.END)

        for username in usernames:
            for password in passwords:
                if self.stop_flag:
                    self.output_widget.insert(tk.END, "Brute force stopped.\n")
                    self.output_widget.see(tk.END)
                    return None
                success, message = self.try_ssh_login(ip, username, password, port)
                self.output_widget.insert(tk.END, message + "\n")
                self.output_widget.see(tk.END)
                if success:
                    self.stop_flag = True
                    return username, password
        return None

    def stop(self):
        """Stop the brute force process."""
        self.stop_flag = True

# --- GUI Application ---
class PenTestToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Penetration Testing Toolkit")
        self.root.geometry("800x600")
        self.root.configure(bg="#2e2e2e")

        # Style configuration
        style = ttk.Style()
        style.configure("TButton", padding=6, font=("Arial", 10))
        style.configure("TLabel", background="#2e2e2e", foreground="#ffffff", font=("Arial", 10))
        style.configure("TEntry", padding=5)

        # Initialize modules
        self.output_text = scrolledtext.ScrolledText(root, height=15, bg="#1e1e1e", fg="#ffffff", font=("Arial", 10))
        self.port_scanner = PortScanner(self.output_text)
        self.brute_forcer = BruteForcer(self.output_text)

        # Create GUI elements
        self.create_gui()

    def create_gui(self):
        """Create the main GUI layout."""
        # Warning Label
        warning_label = ttk.Label(self.root, text="WARNING: Use this tool only with explicit permission on authorized systems.", foreground="red")
        warning_label.pack(pady=10)

        # Notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(pady=10, fill="both", expand=True)

        # Port Scanner Tab
        port_frame = ttk.Frame(notebook)
        notebook.add(port_frame, text="Port Scanner")
        self.create_port_scanner_tab(port_frame)

        # Brute Forcer Tab
        brute_frame = ttk.Frame(notebook)
        notebook.add(brute_frame, text="SSH Brute Forcer")
        self.create_brute_forcer_tab(brute_frame)

        # Output Area
        self.output_text.pack(pady=10, padx=10, fill="both", expand=True)

    def create_port_scanner_tab(self, frame):
        """Create the port scanner tab."""
        ttk.Label(frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.ip_entry = ttk.Entry(frame, width=20)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Start Port:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.start_port_entry = ttk.Entry(frame, width=10)
        self.start_port_entry.grid(row=1, column=1, padx=5, pady=5, stick="w")

        ttk.Label(frame, text="End Port:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.end_port_entry = ttk.Entry(frame, width=10)
        self.end_port_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        ttk.Button(frame, text="Start Scan", command=self.start_port_scan).grid(row=3, column=0, padx=5, pady=10)
        ttk.Button(frame, text="Stop Scan", command=self.stop_port_scan).grid(row=3, column=1, padx=5, pady=10)

    def create_brute_forcer_tab(self, frame):
        """Create the brute forcer tab."""
        ttk.Label(frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.brute_ip_entry = ttk.Entry(frame, width=20)
        self.brute_ip_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Port:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.brute_port_entry = ttk.Entry(frame, width=10)
        self.brute_port_entry.insert(0, "22")
        self.brute_port_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(frame, text="Usernames (comma-separated):").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.usernames_entry = ttk.Entry(frame, width=30)
        self.usernames_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Passwords (comma-separated):").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.passwords_entry = ttk.Entry(frame, width=30)
        self.passwords_entry.grid(row=3, column=1, padx=5, pady=5)

        ttk.Button(frame, text="Start Brute Force", command=self.start_brute_force).grid(row=4, column=0, padx=5, pady=10)
        ttk.Button(frame, text="Stop Brute Force", command=self.stop_brute_force).grid(row=4, column=1, padx=5, pady=10)

    def start_port_scan(self):
        """Start the port scanning process in a separate thread."""
        ip = self.ip_entry.get()
        start_port = self.start_port_entry.get()
        end_port = self.end_port_entry.get()

        if not is_valid_ip(ip):
            messagebox.showerror("Error", "Invalid IP address.")
            return
        if not (is_valid_port(start_port) and is_valid_port(end_port)):
            messagebox.showerror("Error", "Invalid port range.")
            return

        start_port, end_port = int(start_port), int(end_port)
        if start_port > end_port:
            messagebox.showerror("Error", "Start port must be less than or equal to end port.")
            return

        threading.Thread(target=self.port_scanner.scan, args=(ip, start_port, end_port), daemon=True).start()

    def stop_port_scan(self):
        """Stop the port scanning process."""
        self.port_scanner.stop()

    def start_brute_force(self):
        """Start the brute force process in a separate thread."""
        ip = self.brute_ip_entry.get()
        port = self.brute_port_entry.get()
        usernames = [u.strip() for u in self.usernames_entry.get().split(",")]
        passwords = [p.strip() for p in self.passwords_entry.get().split(",")]

        if not is_valid_ip(ip):
            messagebox.showerror("Error", "Invalid IP address.")
            return
        if not is_valid_port(port):
            messagebox.showerror("Error", "Invalid port number.")
            return
        if not usernames or not passwords:
            messagebox.showerror("Error", "Please provide usernames and passwords.")
            return

        threading.Thread(target=self.brute_forcer.brute_force_ssh, args=(ip, usernames, passwords, int(port)), daemon=True).start()

    def stop_brute_force(self):
        """Stop the brute force process."""
        self.brute_forcer.stop()

# --- Main Application ---
if __name__ == "__main__":
    root = tk.Tk()
    app = PenTestToolkitGUI(root)
    root.mainloop()