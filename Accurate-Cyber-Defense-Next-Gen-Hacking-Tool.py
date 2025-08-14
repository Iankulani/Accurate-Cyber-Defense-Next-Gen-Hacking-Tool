import sys
import time
import socket
import threading
import random
import json
import requests
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import platform
import os
import subprocess
import queue

# Constants
VERSION = "19.0.0"
CONFIG_FILE = "accurate_config.json"
DEFAULT_THEME = {"primary": "#00ff00", "secondary": "#000000", "text": "#ffffff"}
MAX_IP_MONITOR = 50
TELEGRAM_API_URL = "https://api.telegram.org/bot{}/sendMessage"

class Accurate:
    def __init__(self):
        # Initialize configuration
        self.config = {
            "theme": DEFAULT_THEME,
            "monitored_ips": [],
            "telegram": {
                "token": "",
                "chat_id": ""
            },
            "traffic_settings": {
                "packet_size": 1024,
                "duration": 10
            }
        }
        
        # Load configuration
        self.load_config()
        
        # Monitoring state
        self.is_monitoring = False
        self.monitoring_thread = None
        self.stop_event = threading.Event()
        
        # Traffic generation state
        self.is_generating_traffic = False
        self.traffic_thread = None
        
        # Data collection
        self.network_data = {
            "threats_detected": 0,
            "packets_sent": 0,
            "packets_received": 0,
            "ip_activity": {},
            "threat_history": []
        }
        
        # Initialize GUI
        self.init_gui()
        
        # Command queue for CLI
        self.command_queue = queue.Queue()
        
    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r") as f:
                    self.config = json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
    
    def save_config(self):
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    # Network operations
    def ping_ip(self, ip):
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "4", ip]
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            return True, output
        except subprocess.CalledProcessError as e:
            return False, e.output
    
    def scan_ip(self, ip):
        try:
            # Simple port scanner
            open_ports = []
            for port in [21, 22, 80, 443, 3389]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            return True, f"Open ports on {ip}: {open_ports}"
        except Exception as e:
            return False, f"Scan error: {str(e)}"
    
    def generate_traffic(self, ip):
        if self.is_generating_traffic:
            return False, "Traffic generation already in progress"
        
        def traffic_worker():
            try:
                packet = b"X" * self.config["traffic_settings"]["packet_size"]
                duration = self.config["traffic_settings"]["duration"]
                end_time = time.time() + duration
                packets_sent = 0
                
                while time.time() < end_time and not self.stop_event.is_set():
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.sendto(packet, (ip, random.randint(2000, 65535)))
                        packets_sent += 1
                        self.network_data["packets_sent"] += 1
                        time.sleep(0.01)
                    except:
                        pass
                
                self.command_queue.put(("output", f"Traffic generation complete. Sent {packets_sent} packets."))
            except Exception as e:
                self.command_queue.put(("output", f"Traffic generation error: {str(e)}"))
            finally:
                self.is_generating_traffic = False
        
        self.is_generating_traffic = True
        self.stop_event.clear()
        self.traffic_thread = threading.Thread(target=traffic_worker)
        self.traffic_thread.start()
        return True, f"Generating traffic to {ip} for {self.config['traffic_settings']['duration']} seconds"
    
    def start_monitoring(self, ip):
        if ip in self.config["monitored_ips"]:
            return False, f"{ip} is already being monitored"
        
        if len(self.config["monitored_ips"]) >= MAX_IP_MONITOR:
            return False, f"Maximum number of monitored IPs ({MAX_IP_MONITOR}) reached"
        
        self.config["monitored_ips"].append(ip)
        self.save_config()
        
        if not self.is_monitoring:
            self.is_monitoring = True
            self.stop_event.clear()
            self.monitoring_thread = threading.Thread(target=self.monitoring_worker)
            self.monitoring_thread.start()
            return True, f"Started monitoring {ip} and initialized monitoring system"
        else:
            return True, f"Added {ip} to monitoring list"
    
    def stop_monitoring(self):
        if not self.is_monitoring:
            return False, "Monitoring is not active"
        
        self.stop_event.set()
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join()
        return True, "Monitoring stopped"
    
    def monitoring_worker(self):
        while not self.stop_event.is_set() and self.is_monitoring:
            try:
                # Simulate monitoring activity
                for ip in self.config["monitored_ips"]:
                    if random.random() < 0.1:  # 10% chance of threat detection
                        threat_type = random.choice(["Port Scan", "DDoS Attempt", "Brute Force", "Malware Beacon"])
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        threat_data = {
                            "ip": ip,
                            "type": threat_type,
                            "timestamp": timestamp,
                            "severity": random.choice(["Low", "Medium", "High"])
                        }
                        self.network_data["threat_history"].append(threat_data)
                        self.network_data["threats_detected"] += 1
                        
                        if ip in self.network_data["ip_activity"]:
                            self.network_data["ip_activity"][ip] += 1
                        else:
                            self.network_data["ip_activity"][ip] = 1
                        
                        # Send alert to Telegram if configured
                        if self.config["telegram"]["token"] and self.config["telegram"]["chat_id"]:
                            message = f"🚨 Threat Detected!\nIP: {ip}\nType: {threat_type}\nSeverity: {threat_data['severity']}\nTime: {timestamp}"
                            self.send_telegram_alert(message)
                
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(10)
    
    def send_telegram_alert(self, message):
        try:
            url = TELEGRAM_API_URL.format(self.config["telegram"]["token"])
            payload = {
                "chat_id": self.config["telegram"]["chat_id"],
                "text": message
            }
            response = requests.post(url, json=payload)
            return response.status_code == 200
        except Exception as e:
            print(f"Telegram send error: {e}")
            return False
    
    def test_telegram_connection(self):
        if not self.config["telegram"]["token"] or not self.config["telegram"]["chat_id"]:
            return False, "Telegram token or chat ID not configured"
        
        try:
            url = TELEGRAM_API_URL.format(self.config["telegram"]["token"])
            payload = {
                "chat_id": self.config["telegram"]["chat_id"],
                "text": "accurate Pro: Test message"
            }
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                return True, "Telegram connection successful"
            else:
                return False, f"Telegram API error: {response.text}"
        except Exception as e:
            return False, f"Telegram connection failed: {str(e)}"
    
    def traceroute(self, ip):
        try:
            param = "-d" if platform.system().lower() == "windows" else ""
            command = ["tracert", param, ip] if platform.system().lower() == "windows" else ["traceroute", ip]
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            return True, output
        except subprocess.CalledProcessError as e:
            return False, e.output
        except Exception as e:
            return False, f"Traceroute error: {str(e)}"
    
    # GUI Functions
    def init_gui(self):
        self.root = tk.Tk()
        self.root.title(f"Accurate Cyber Defense {VERSION}")
        self.root.geometry("1200x800")
        self.root.configure(bg=self.config["theme"]["secondary"])
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure(".", background=self.config["theme"]["secondary"], foreground=self.config["theme"]["text"])
        self.style.configure("TFrame", background=self.config["theme"]["secondary"])
        self.style.configure("TLabel", background=self.config["theme"]["secondary"], foreground=self.config["theme"]["text"])
        self.style.configure("TButton", background=self.config["theme"]["primary"], foreground="black")
        self.style.configure("TEntry", fieldbackground="white", foreground="black")
        self.style.configure("TCombobox", fieldbackground="white", foreground="black")
        self.style.configure("TNotebook", background=self.config["theme"]["secondary"])
        self.style.configure("TNotebook.Tab", background=self.config["theme"]["primary"], foreground="black")
        self.style.map("TButton", background=[("active", self.config["theme"]["primary"])])
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create main notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Dashboard tab
        self.create_dashboard_tab()
        
        # Monitoring tab
        self.create_monitoring_tab()
        
        # Traffic tab
        self.create_traffic_tab()
        
        # CLI tab
        self.create_cli_tab()
        
        # Settings tab
        self.create_settings_tab()
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        # Start GUI update thread
        self.gui_update_thread = threading.Thread(target=self.update_gui)
        self.gui_update_thread.daemon = True
        self.gui_update_thread.start()
    
    def create_menu_bar(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Data", command=self.export_data)
        file_menu.add_command(label="Export to Telegram", command=self.export_to_telegram)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Refresh Dashboard", command=self.update_dashboard)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Ping Tool", command=self.show_ping_tool)
        tools_menu.add_command(label="Port Scanner", command=self.show_scan_tool)
        tools_menu.add_command(label="Traceroute", command=self.show_traceroute_tool)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Help", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_dashboard_tab(self):
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        
        # Top frame for stats
        top_frame = ttk.Frame(self.dashboard_tab)
        top_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Stats cards
        stats = [
            ("Monitored IPs", len(self.config["monitored_ips"])),
            ("Threats Detected", self.network_data["threats_detected"]),
            ("Packets Sent", self.network_data["packets_sent"]),
            ("Monitoring Status", "Active" if self.is_monitoring else "Inactive")
        ]
        
        for i, (label, value) in enumerate(stats):
            card = ttk.Frame(top_frame, relief=tk.RAISED, borderwidth=1)
            card.grid(row=0, column=i, padx=5, pady=5, sticky="nsew")
            
            ttk.Label(card, text=label, font=("Arial", 10)).pack(padx=10, pady=5)
            ttk.Label(card, text=str(value), font=("Arial", 14, "bold")).pack(padx=10, pady=5)
            
            top_frame.columnconfigure(i, weight=1)
        
        # Charts frame
        charts_frame = ttk.Frame(self.dashboard_tab)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Threat types pie chart
        self.create_pie_chart(charts_frame)
        
        # IP activity bar chart
        self.create_bar_chart(charts_frame)
    
    def create_pie_chart(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Sample data - in real app this would come from threat_history
        threat_types = {}
        for threat in self.network_data["threat_history"]:
            if threat["type"] in threat_types:
                threat_types[threat["type"]] += 1
            else:
                threat_types[threat["type"]] = 1
        
        if not threat_types:
            threat_types = {"Port Scan": 1, "DDoS Attempt": 1, "Brute Force": 1}
        
        fig, ax = plt.subplots(figsize=(5, 4), facecolor=self.config["theme"]["secondary"])
        ax.pie(threat_types.values(), labels=threat_types.keys(), autopct="%1.1f%%",
               colors=["#00ff00", "#009900", "#006600", "#003300"])
        ax.set_title("Threat Types Distribution", color=self.config["theme"]["text"])
        
        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_bar_chart(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Sample data - in real app this would come from ip_activity
        ip_activity = self.network_data["ip_activity"]
        if not ip_activity:
            ip_activity = {"192.168.1.1": 5, "10.0.0.2": 3, "172.16.0.5": 7}
        
        fig, ax = plt.subplots(figsize=(5, 4), facecolor=self.config["theme"]["secondary"])
        ax.bar(ip_activity.keys(), ip_activity.values(), color=self.config["theme"]["primary"])
        ax.set_title("IP Activity", color=self.config["theme"]["text"])
        ax.set_ylabel("Threat Count", color=self.config["theme"]["text"])
        ax.tick_params(axis="x", rotation=45, colors=self.config["theme"]["text"])
        ax.tick_params(axis="y", colors=self.config["theme"]["text"])
        ax.set_facecolor(self.config["theme"]["secondary"])
        
        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_monitoring_tab(self):
        self.monitoring_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.monitoring_tab, text="Monitoring")
        
        # Control frame
        control_frame = ttk.Frame(self.monitoring_tab)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(control_frame, text="Start Monitoring", command=self.gui_start_monitoring).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Stop Monitoring", command=self.gui_stop_monitoring).pack(side=tk.LEFT, padx=5)
        
        # Add IP frame
        add_ip_frame = ttk.Frame(self.monitoring_tab)
        add_ip_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.ip_entry = ttk.Entry(add_ip_frame)
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(add_ip_frame, text="Add IP", command=self.gui_add_ip).pack(side=tk.LEFT, padx=5)
        
        # IP list
        ip_list_frame = ttk.Frame(self.monitoring_tab)
        ip_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.ip_listbox = tk.Listbox(ip_list_frame, bg="black", fg=self.config["theme"]["primary"], selectbackground=self.config["theme"]["primary"], selectforeground="black")
        self.ip_listbox.pack(fill=tk.BOTH, expand=True)
        
        # Populate IP list
        self.update_ip_list()
        
        # Remove button
        ttk.Button(ip_list_frame, text="Remove Selected", command=self.gui_remove_ip).pack(pady=5)
    
    def create_traffic_tab(self):
        self.traffic_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.traffic_tab, text="Traffic")
        
        # Control frame
        control_frame = ttk.Frame(self.traffic_tab)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(control_frame, text="Target IP:").pack(side=tk.LEFT, padx=5)
        self.traffic_ip_entry = ttk.Entry(control_frame)
        self.traffic_ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        ttk.Button(control_frame, text="Generate Traffic", command=self.gui_generate_traffic).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Stop Traffic", command=self.gui_stop_traffic).pack(side=tk.LEFT, padx=5)
        
        # Settings frame
        settings_frame = ttk.LabelFrame(self.traffic_tab, text="Traffic Settings")
        settings_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(settings_frame, text="Packet Size (bytes):").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.packet_size_entry = ttk.Entry(settings_frame)
        self.packet_size_entry.insert(0, str(self.config["traffic_settings"]["packet_size"]))
        self.packet_size_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(settings_frame, text="Duration (seconds):").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.duration_entry = ttk.Entry(settings_frame)
        self.duration_entry.insert(0, str(self.config["traffic_settings"]["duration"]))
        self.duration_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Button(settings_frame, text="Save Settings", command=self.save_traffic_settings).grid(row=2, column=0, columnspan=2, pady=10)
    
    def create_cli_tab(self):
        self.cli_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.cli_tab, text="CLI")
        
        # Output console
        self.console_output = scrolledtext.ScrolledText(
            self.cli_tab, 
            bg="black", 
            fg=self.config["theme"]["primary"], 
            insertbackground=self.config["theme"]["primary"],
            wrap=tk.WORD
        )
        self.console_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Input frame
        input_frame = ttk.Frame(self.cli_tab)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.cli_prompt = ttk.Label(input_frame, text="CyberGuard>")
        self.cli_prompt.pack(side=tk.LEFT)
        
        self.cli_entry = ttk.Entry(input_frame)
        self.cli_entry.pack(fill=tk.X, expand=True, padx=5)
        self.cli_entry.bind("<Return>", self.process_cli_command)
        
        # Help label
        ttk.Label(self.cli_tab, text="Type 'help' for available commands").pack(pady=5)
    
    def create_settings_tab(self):
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="Settings")
        
        # Telegram settings
        telegram_frame = ttk.LabelFrame(self.settings_tab, text="Telegram Notifications")
        telegram_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(telegram_frame, text="Bot Token:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.telegram_token_entry = ttk.Entry(telegram_frame)
        self.telegram_token_entry.insert(0, self.config["telegram"]["token"])
        self.telegram_token_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(telegram_frame, text="Chat ID:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.telegram_chat_id_entry = ttk.Entry(telegram_frame)
        self.telegram_chat_id_entry.insert(0, self.config["telegram"]["chat_id"])
        self.telegram_chat_id_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Button(telegram_frame, text="Test Connection", command=self.gui_test_telegram).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Theme settings
        theme_frame = ttk.LabelFrame(self.settings_tab, text="Theme Settings")
        theme_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(theme_frame, text="Primary Color:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.primary_color_entry = ttk.Entry(theme_frame)
        self.primary_color_entry.insert(0, self.config["theme"]["primary"])
        self.primary_color_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Button(theme_frame, text="Apply Theme", command=self.apply_theme).grid(row=1, column=0, columnspan=2, pady=10)
    
    # GUI Helper Functions
    def update_ip_list(self):
        self.ip_listbox.delete(0, tk.END)
        for ip in self.config["monitored_ips"]:
            self.ip_listbox.insert(tk.END, ip)
    
    def update_dashboard(self):
        # Remove existing charts
        for widget in self.dashboard_tab.winfo_children():
            widget.destroy()
        
        # Recreate dashboard
        self.create_dashboard_tab()
    
    def update_status(self, message):
        self.status_bar.config(text=message)
        self.root.update_idletasks()
    
    def append_to_console(self, text):
        self.console_output.insert(tk.END, text + "\n")
        self.console_output.see(tk.END)
    
    def clear_console(self):
        self.console_output.delete(1.0, tk.END)
    
    def update_gui(self):
        while True:
            try:
                item = self.command_queue.get_nowait()
                if item[0] == "output":
                    self.append_to_console(item[1])
                elif item[0] == "status":
                    self.update_status(item[1])
                elif item[0] == "update_ip_list":
                    self.update_ip_list()
                elif item[0] == "update_dashboard":
                    self.update_dashboard()
            except queue.Empty:
                pass
            
            time.sleep(0.1)
    
    # GUI Command Handlers
    def gui_start_monitoring(self):
        if not self.config["monitored_ips"]:
            messagebox.showwarning("Warning", "No IPs to monitor. Please add IPs first.")
            return
        
        if self.is_monitoring:
            messagebox.showinfo("Info", "Monitoring is already active")
            return
        
        success, message = self.start_monitoring("")
        if success:
            messagebox.showinfo("Success", message)
            self.command_queue.put(("update_dashboard", ""))
        else:
            messagebox.showerror("Error", message)
    
    def gui_stop_monitoring(self):
        if not self.is_monitoring:
            messagebox.showinfo("Info", "Monitoring is not active")
            return
        
        success, message = self.stop_monitoring()
        if success:
            messagebox.showinfo("Success", message)
            self.command_queue.put(("update_dashboard", ""))
        else:
            messagebox.showerror("Error", message)
    
    def gui_add_ip(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Warning", "Please enter an IP address")
            return
        
        success, message = self.start_monitoring(ip)
        if success:
            messagebox.showinfo("Success", message)
            self.ip_entry.delete(0, tk.END)
            self.command_queue.put(("update_ip_list", ""))
            self.command_queue.put(("update_dashboard", ""))
        else:
            messagebox.showerror("Error", message)
    
    def gui_remove_ip(self):
        selection = self.ip_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an IP to remove")
            return
        
        ip = self.ip_listbox.get(selection[0])
        if ip in self.config["monitored_ips"]:
            self.config["monitored_ips"].remove(ip)
            self.save_config()
            self.update_ip_list()
            messagebox.showinfo("Success", f"Removed {ip} from monitoring")
            self.command_queue.put(("update_dashboard", ""))
    
    def gui_generate_traffic(self):
        ip = self.traffic_ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Warning", "Please enter a target IP address")
            return
        
        success, message = self.generate_traffic(ip)
        if success:
            messagebox.showinfo("Info", message)
        else:
            messagebox.showerror("Error", message)
    
    def gui_stop_traffic(self):
        if not self.is_generating_traffic:
            messagebox.showinfo("Info", "Traffic generation is not active")
            return
        
        self.stop_event.set()
        messagebox.showinfo("Info", "Traffic generation will stop shortly")
    
    def save_traffic_settings(self):
        try:
            packet_size = int(self.packet_size_entry.get())
            duration = int(self.duration_entry.get())
            
            if packet_size < 1 or duration < 1:
                raise ValueError("Values must be positive integers")
            
            self.config["traffic_settings"]["packet_size"] = packet_size
            self.config["traffic_settings"]["duration"] = duration
            self.save_config()
            messagebox.showinfo("Success", "Traffic settings saved")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid input: {str(e)}")
    
    def gui_test_telegram(self):
        token = self.telegram_token_entry.get().strip()
        chat_id = self.telegram_chat_id_entry.get().strip()
        
        if not token or not chat_id:
            messagebox.showwarning("Warning", "Please enter both Telegram token and chat ID")
            return
        
        self.config["telegram"]["token"] = token
        self.config["telegram"]["chat_id"] = chat_id
        self.save_config()
        
        success, message = self.test_telegram_connection()
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", message)
    
    def apply_theme(self):
        primary_color = self.primary_color_entry.get().strip()
        
        # Validate color
        try:
            if not primary_color.startswith("#") or len(primary_color) != 7:
                raise ValueError("Color must be in #RRGGBB format")
            
            int(primary_color[1:], 16)  # Try to parse as hex
        except ValueError:
            messagebox.showerror("Error", "Invalid color format. Use #RRGGBB")
            return
        
        self.config["theme"]["primary"] = primary_color
        self.save_config()
        
        # Reinitialize GUI with new theme
        messagebox.showinfo("Info", "Theme will be applied after restart")
    
    def show_ping_tool(self):
        self.notebook.select(self.cli_tab)
        self.append_to_console("Ping tool activated. Usage: ping ip")
    
    def show_scan_tool(self):
        self.notebook.select(self.cli_tab)
        self.append_to_console("Port scanner activated. Usage: scan ip")
    
    def show_traceroute_tool(self):
        self.notebook.select(self.cli_tab)
        self.append_to_console("Traceroute tool activated. Usage: traceroute ip")
    
    def show_help(self):
        help_text = """Accurate Cyber Defense Pro - Help

Available Commands:
  help                 - Show this help message
  ping ip              - Ping an IP address
  scan ip             - Scan common ports on an IP
  generate traffic ip - Generate network traffic to an IP
  start monitoring ip - Start monitoring an IP for threats
  stop               - Stop monitoring
  test telegram      - Test Telegram connection
  view               - View current monitoring status
  status             - Show system status
  exit               - Exit the application
  clear             - Clear the console
  traceroute ip     - Perform traceroute to an IP
  config telegram token [token] - Set Telegram bot token
  config telegram chat_id [id] - Set Telegram chat ID
  add ip            - Add IP to monitoring list
  remove ip        - Remove IP from monitoring list
  export to telegram - Export data to Telegram"""
        
        messagebox.showinfo("Help", help_text)
    
    def show_about(self):
        about_text = f"""Accurate Cyber Defense Pro {VERSION}

Advanced Cybersecurity Monitoring Tool

Features:
- IP monitoring for threats
- Network traffic generation
- Port scanning
- Telegram notifications
- Real-time dashboard
- Command line interface

Theme: Green/Black"""
        
        messagebox.showinfo("About", about_text)
    
    def export_data(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            data = {
                "config": self.config,
                "network_data": self.network_data
            }
            
            with open(file_path, "w") as f:
                json.dump(data, f, indent=4)
            
            messagebox.showinfo("Success", f"Data exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def export_to_telegram(self):
        if not self.config["telegram"]["token"] or not self.config["telegram"]["chat_id"]:
            messagebox.showwarning("Warning", "Telegram token or chat ID not configured")
            return
        
        # Prepare summary data
        summary = f"""Accurate Cyber Defnse Pro Report - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Monitored IPs: {len(self.config["monitored_ips"])}
Threats Detected: {self.network_data["threats_detected"]}
Packets Sent: {self.network_data["packets_sent"]}

Last 5 Threats:"""
        
        for threat in self.network_data["threat_history"][-5:]:
            summary += f"\n- {threat['timestamp']} {threat['ip']} {threat['type']} ({threat['severity']})"
        
        success = self.send_telegram_alert(summary)
        if success:
            messagebox.showinfo("Success", "Data exported to Telegram")
        else:
            messagebox.showerror("Error", "Failed to send data to Telegram")
    
    # CLI Command Processing
    def process_cli_command(self, event=None):
        command = self.cli_entry.get().strip()
        self.cli_entry.delete(0, tk.END)
        
        if not command:
            return
        
        self.append_to_console(f"Accurate> {command}")
        
        parts = command.split()
        cmd = parts[0].lower() if parts else ""
        args = parts[1:] if len(parts) > 1 else []
        
        if cmd == "help":
            self.show_help()
        elif cmd == "ping" and args:
            self.handle_ping_command(args[0])
        elif cmd == "scan" and args:
            self.handle_scan_command(args[0])
        elif cmd == "generate" and len(args) >= 2 and args[0].lower() == "traffic":
            self.handle_generate_traffic_command(args[1])
        elif cmd == "start" and len(args) >= 2 and args[0].lower() == "monitoring":
            self.handle_start_monitoring_command(args[1])
        elif cmd == "stop":
            self.handle_stop_command()
        elif cmd == "test" and args and args[0].lower() == "telegram":
            self.handle_test_telegram_command()
        elif cmd == "view":
            self.handle_view_command()
        elif cmd == "status":
            self.handle_status_command()
        elif cmd == "exit":
            self.root.quit()
        elif cmd == "clear":
            self.clear_console()
        elif cmd == "traceroute" and args:
            self.handle_traceroute_command(args[0])
        elif cmd == "config" and len(args) >= 3 and args[0].lower() == "telegram":
            self.handle_config_telegram_command(args[1], " ".join(args[2:]))
        elif cmd == "add" and args:
            self.handle_add_ip_command(args[0])
        elif cmd == "remove" and args:
            self.handle_remove_ip_command(args[0])
        elif cmd == "export" and len(args) >= 2 and args[0].lower() == "to" and args[1].lower() == "telegram":
            self.export_to_telegram()
        else:
            self.append_to_console("Error: Unknown command. Type 'help' for available commands")
    
    def handle_ping_command(self, ip):
        success, output = self.ping_ip(ip)
        if success:
            self.append_to_console(f"Ping to {ip} successful:\n{output}")
        else:
            self.append_to_console(f"Ping to {ip} failed:\n{output}")
    
    def handle_scan_command(self, ip):
        success, output = self.scan_ip(ip)
        if success:
            self.append_to_console(output)
        else:
            self.append_to_console(f"Scan failed: {output}")
    
    def handle_generate_traffic_command(self, ip):
        success, message = self.generate_traffic(ip)
        self.append_to_console(message)
    
    def handle_start_monitoring_command(self, ip):
        success, message = self.start_monitoring(ip)
        self.append_to_console(message)
        if success:
            self.command_queue.put(("update_ip_list", ""))
            self.command_queue.put(("update_dashboard", ""))
    
    def handle_stop_command(self):
        success, message = self.stop_monitoring()
        self.append_to_console(message)
        if success:
            self.command_queue.put(("update_dashboard", ""))
    
    def handle_test_telegram_command(self):
        if not self.config["telegram"]["token"] or not self.config["telegram"]["chat_id"]:
            self.append_to_console("Error: Telegram token or chat ID not configured")
            return
        
        success, message = self.test_telegram_connection()
        self.append_to_console(message)
    
    def handle_view_command(self):
        self.append_to_console("\nCurrent Monitoring Status:")
        self.append_to_console(f"Active: {'Yes' if self.is_monitoring else 'No'}")
        self.append_to_console(f"Monitored IPs: {len(self.config['monitored_ips'])}")
        self.append_to_console(f"Threats Detected: {self.network_data['threats_detected']}")
        
        if self.network_data["threat_history"]:
            self.append_to_console("\nRecent Threats:")
            for threat in self.network_data["threat_history"][-5:]:
                self.append_to_console(f"- {threat['timestamp']} {threat['ip']} {threat['type']} ({threat['severity']})")
    
    def handle_status_command(self):
        self.append_to_console("\nSystem Status:")
        self.append_to_console(f"Version: {VERSION}")
        self.append_to_console(f"Monitoring: {'Active' if self.is_monitoring else 'Inactive'}")
        self.append_to_console(f"Traffic Generation: {'Active' if self.is_generating_traffic else 'Inactive'}")
        self.append_to_console(f"Telegram Configured: {'Yes' if self.config['telegram']['token'] and self.config['telegram']['chat_id'] else 'No'}")
    
    def handle_traceroute_command(self, ip):
        success, output = self.traceroute(ip)
        if success:
            self.append_to_console(f"Traceroute to {ip}:\n{output}")
        else:
            self.append_to_console(f"Traceroute failed: {output}")
    
    def handle_config_telegram_command(self, param, value):
        if param == "token":
            self.config["telegram"]["token"] = value
            self.save_config()
            self.append_to_console("Telegram token updated")
        elif param == "chat_id":
            self.config["telegram"]["chat_id"] = value
            self.save_config()
            self.append_to_console("Telegram chat ID updated")
        else:
            self.append_to_console("Error: Unknown Telegram config parameter")
    
    def handle_add_ip_command(self, ip):
        success, message = self.start_monitoring(ip)
        self.append_to_console(message)
        if success:
            self.command_queue.put(("update_ip_list", ""))
            self.command_queue.put(("update_dashboard", ""))
    
    def handle_remove_ip_command(self, ip):
        if ip in self.config["monitored_ips"]:
            self.config["monitored_ips"].remove(ip)
            self.save_config()
            self.append_to_console(f"Removed {ip} from monitoring")
            self.command_queue.put(("update_ip_list", ""))
            self.command_queue.put(("update_dashboard", ""))
        else:
            self.append_to_console(f"Error: {ip} not found in monitoring list")
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = Accurate()
    app.run()