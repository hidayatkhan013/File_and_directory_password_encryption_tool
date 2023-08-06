import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QFileDialog, QMessageBox, QProgressBar, QHBoxLayout, QCheckBox
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures  # Add this import
from cryptography.fernet import Fernet, InvalidToken

class EncryptionApp(QMainWindow):
    encryption_progress = pyqtSignal(int)
    decryption_progress = pyqtSignal(int)
    decryption_error = pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.salt = None
        self.initUI()
        self.encryption_progress.connect(self.progress_bar.setValue)
        self.decryption_progress.connect(self.progress_bar.setValue)
        self.decryption_error.connect(self.handle_error)
        self.error_displayed = False 

    def initUI(self):
        self.setWindowTitle('File & Directory Encryption | By Hidayat Ur Rehman')
        self.setGeometry(100, 100, 400, 200)
        self.key_cache = {}
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        self.files_to_encrypt = []
        self.files_to_decrypt = []
        self.salt = None
        layout = QVBoxLayout()

        self.directory_label = QLabel('Select Directory:')
        layout.addWidget(self.directory_label)

        self.directory_lineedit = QLineEdit()
        layout.addWidget(self.directory_lineedit)

        self.directory_button = QPushButton('Browse')
        self.directory_button.clicked.connect(self.browse_directory)
        layout.addWidget(self.directory_button)

        password_layout = QHBoxLayout()

        self.password_label = QLabel('Enter Password:')
        password_layout.addWidget(self.password_label)

        self.password_lineedit = QLineEdit()
        self.password_lineedit.setEchoMode(QLineEdit.Password)  # Mask the password input
        password_layout.addWidget(self.password_lineedit)

        self.view_password_checkbox = QCheckBox('View Password')
        self.view_password_checkbox.stateChanged.connect(self.toggle_password_visibility)
        password_layout.addWidget(self.view_password_checkbox)

        layout.addLayout(password_layout)
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        self.encrypt_button = QPushButton('Encrypt Directory')
        self.encrypt_button.clicked.connect(self.encrypt_directory)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton('Decrypt Directory')
        self.decrypt_button.clicked.connect(self.decrypt_directory)
        layout.addWidget(self.decrypt_button)

        central_widget.setLayout(layout)

    def toggle_password_visibility(self):
        if self.view_password_checkbox.isChecked():
            self.password_lineedit.setEchoMode(QLineEdit.Normal)
        else:
            self.password_lineedit.setEchoMode(QLineEdit.Password)

    def browse_directory(self):
        directory = QFileDialog.getExistingDirectory(self, 'Select Directory')
        if directory:
            self.directory_lineedit.setText(directory)

    def handle_error(self, message):
        QMessageBox.critical(self, "Error", message)

    def encrypt_file(self, file_path, key,salt):
        try:
            fernet = Fernet(key)
            with open(file_path, "rb") as file:
                file_data = file.read()
            encrypted_data = fernet.encrypt(file_data)
            with open(file_path + ".encrypted", "wb") as encrypted_file:
                encrypted_file.write(salt + encrypted_data)

            # Remove the original file after successful encryption
            os.remove(file_path)
        except Exception as e:
            self.handle_error(self, "invalid file format.")
            exit()

    def decrypt_file(self, file_path, password):
        
        try:
            with open(file_path, "rb") as encrypted_file:
                data = encrypted_file.read()
                salt, encrypted_data = data[:16], data[16:]
            key = self.generate_key_from_password(password.encode(), salt)
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            original_file_path = file_path[:-10]  # Remove the ".encrypted" extension
            with open(original_file_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted_data)
            os.remove(file_path)
        except InvalidToken as e:
            if not self.error_displayed:  # Show error only once
                self.error_displayed = True
                self.decryption_error.emit("Invalid password or file format.")
        except Exception as e:
            if not self.error_displayed:  # Show error only once
                self.error_displayed = True
                self.decryption_error.emit("An error occurred during decryption.")

        

    def generate_key_from_password(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def encrypt_directory(self):
        directory = self.directory_lineedit.text()
        password = self.password_lineedit.text()
        if directory not in self.key_cache:
            self.salt = os.urandom(16)
            key = self.generate_key_from_password(password.encode(), self.salt)
            self.key_cache[directory] = key
        else:
            key = self.key_cache[directory]
        self.files_to_encrypt=[]
        for root, _, files in os.walk(directory):
            self.files_to_encrypt.extend(os.path.join(root, file) for file in files)
            self.total_files = len(self.files_to_encrypt)

        # Create a separate thread to perform the encryption
        with ThreadPoolExecutor() as executor:
            future_to_file = {
                executor.submit(self.encrypt_file, file, key,self.salt): file for file in self.files_to_encrypt
            }

            # Track the progress of the encryption
            completed_count = 0
            for future in concurrent.futures.as_completed(future_to_file):
                completed_count += 1
                progress = int(completed_count * 100 / self.total_files)
                self.progress_bar.setValue(progress)

    def handle_progress(self, value):
        self.progress_bar.setValue(value)



    def decrypt_directory(self):
        # try:
        directory = self.directory_lineedit.text()
        password = self.password_lineedit.text()
        self.error_displayed = False
        self.files_to_decrypt = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".encrypted"):
                    self.files_to_decrypt.append(os.path.join(root, file))
        self.total_files = len(self.files_to_decrypt)
        with ThreadPoolExecutor() as executor:
            future_to_file = {
                executor.submit(self.decrypt_file, file, password): file for file in self.files_to_decrypt
            }

            completed_count = 0
            for future in concurrent.futures.as_completed(future_to_file):
                completed_count += 1
                progress = int(completed_count * 100 / self.total_files)
                self.progress_bar.setValue(progress)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = EncryptionApp()
    window.show()
    sys.exit(app.exec_())