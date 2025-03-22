import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from ui.caesar import Ui_Dialog  # Đúng với class trong file bạn gửi
import requests

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)

        # Dùng đúng tên widget như trong file caesar.py
        self.ui.pushButton.clicked.connect(self.call_api_encrypt)
        self.ui.pushButton_2.clicked.connect(self.call_api_decrypt)
    
    def call_api_encrypt(self):
        url = "http://127.0.0.1:5000/api/caesar/encrypt"
        payload = {
            "plain_text": self.ui.lineEdit.text(),
            "key": self.ui.lineEdit_2.text()
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.lineEdit_3.setText(data["encrypted_message"])

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Encrypted Successfully")
                msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print("Error: %s" % e)
    
    def call_api_decrypt(self):
        url = "http://127.0.0.1:5000/api/caesar/decrypt"
        payload = {
            "cipher_text": self.ui.lineEdit_3.text(),
            "key": self.ui.lineEdit_2.text()
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.lineEdit.setText(data["decrypted_message"])

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Decrypted Successfully")
                msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print("Error: %s" % e)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())
