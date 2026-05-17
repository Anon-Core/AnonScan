# main.py
import sys
from PySide6.QtWidgets import QApplication
from ui_main import AnonScanWindow

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = AnonScanWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
