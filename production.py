import sys
import socket
import csv
import time
import re
import json
from datetime import datetime
from pathlib import Path
import urllib.parse
import urllib.request
import urllib.error

from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QTextDocument, QFont, QIcon
from PyQt6.QtPrintSupport import QPrinter, QPrintDialog
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QGroupBox,
    QGridLayout,
    QHBoxLayout,
    QVBoxLayout,
    QMessageBox,
    QTabWidget,
    QRadioButton,
    QButtonGroup,
    QDialog,
    QSizePolicy,
    QScrollArea,
)
import bcrypt


# ============================================================
# CONFIG
# ============================================================

DEFAULT_IP = "192.168.1.190"
DEFAULT_PORT = 6000

BASE_DIR = Path(__file__).resolve().parent

LOG_FILE = BASE_DIR / "rfid_tags.txt"
ROUND_FILE = BASE_DIR / "round.txt"
STUDENT_FILE = BASE_DIR / "student.csv"

READER_ADDRESS = 0x00


# ============================================================
# HELPERS
# ============================================================

def normalize_rfid(value):
    if value is None:
        return ""

    value = str(value).strip().upper()

    value = re.sub(
        r"[\s\-:]+",
        "",
        value
    )

    if value in ("", "NULL", "NONE", "-"):
        return ""

    return value


def normalize_text(value):
    if value is None:
        return ""

    return str(value).strip()


# ============================================================
# CRC16
# ============================================================

def crc16(data):
    crc = 0xFFFF
    polynomial = 0x8408

    for byte in data:
        crc ^= byte

        for _ in range(8):
            if crc & 0x0001:
                crc = (
                    crc >> 1
                ) ^ polynomial
            else:
                crc >>= 1

    return crc


# ============================================================
# INVENTORY COMMAND
#
# Tested command:
# 06 00 01 04 FF D4 39
# ============================================================

def make_inventory_command():
    data = bytes([
        0x06,
        READER_ADDRESS,
        0x01,
        0x04,
        0xFF
    ])

    crc = crc16(data)

    return data + bytes([
        crc & 0xFF,
        (crc >> 8) & 0xFF
    ])


# ============================================================
# RFID WORKER
# ============================================================

class RFIDWorker(QThread):

    tag_found = pyqtSignal(
        str,
        int,
        int,
        int
    )

    status_changed = pyqtSignal(str)
    raw_data = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    reader_finished = pyqtSignal()


    def __init__(
        self,
        ip,
        port,
        interval_ms
    ):
        super().__init__()

        self.ip = ip
        self.port = port
        self.interval_ms = interval_ms

        self.running = True
        self.scanning = False

        self.round_token = ""

        self.sock = None


    def start_scan(self):
        self.scanning = True

        self.status_changed.emit(
            "Scanning..."
        )


    def stop_scan(self):
        self.scanning = False

        if self.running:
            self.status_changed.emit(
                "Connected - Ready"
            )


    def stop_worker(self):
        self.running = False
        self.scanning = False

        if self.sock:

            try:
                self.sock.shutdown(
                    socket.SHUT_RDWR
                )
            except Exception:
                pass

            try:
                self.sock.close()
            except Exception:
                pass


    def read_frame(self):

        try:

            first = self.sock.recv(1)

            if not first:
                return None

            length = first[0]

            data = bytearray(first)

            remaining = length

            while remaining > 0:

                chunk = self.sock.recv(
                    remaining
                )

                if not chunk:
                    return None

                data.extend(chunk)

                remaining -= len(chunk)

            return bytes(data)

        except socket.timeout:
            return None

        except Exception:
            return None


    def parse_response(self, frame):

        if len(frame) < 9:
            return []


        command = frame[2]
        status = frame[3]


        if command != 0x01:
            return []


        # 0x01 = no tag
        if status == 0x01:
            return []


        # Responses containing tag data
        if status not in (
            0x02,
            0x03,
            0x04
        ):
            return []


        antenna = frame[4]

        epc_len = frame[5]

        if epc_len <= 0:
            return []


        required_length = (
            6
            + epc_len
            + 1
            + 2
        )


        if len(frame) < required_length:
            return []


        epc_start = 6

        epc_end = (
            epc_start
            + epc_len
        )


        epc = (
            frame[
                epc_start:
                epc_end
            ]
            .hex()
            .upper()
        )


        rssi = frame[epc_end]


        return [
            {
                "epc": epc,
                "epc_len": epc_len,
                "antenna": antenna,
                "rssi": rssi
            }
        ]


    def save_tag(
        self,
        epc,
        rssi
    ):

        # IMPORTANT:
        # บันทึก RFID ทุกตัว
        # ไม่ตรวจ student.csv
        # ไม่ตรวจว่า RFID เคยมีหรือไม่

        now = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        line = (
            f"{now}\t"
            f"{self.round_token}\t"
            f"{epc}\t"
            f"RSSI={rssi}\n"
        )

        try:

            with open(
                LOG_FILE,
                "a",
                encoding="utf-8"
            ) as file:

                file.write(line)

        except Exception as e:

            self.error_occurred.emit(
                f"บันทึกไฟล์ไม่ได้: {e}"
            )


    def run(self):

        try:

            self.status_changed.emit(
                "Connecting..."
            )


            self.sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            self.sock.settimeout(
                1.0
            )


            self.sock.connect(
                (
                    self.ip,
                    self.port
                )
            )


            self.status_changed.emit(
                f"Connected - Ready"
            )


            print(
                "=" * 65
            )

            print(
                f"Connected to "
                f"{self.ip}:{self.port}"
            )


            command = (
                make_inventory_command()
            )


            print(
                "TX:",
                command.hex(" ").upper()
            )


            while self.running:

                if not self.scanning:

                    time.sleep(
                        0.05
                    )

                    continue


                self.sock.sendall(
                    command
                )


                self.raw_data.emit(
                    "TX: "
                    + command.hex(
                        " "
                    ).upper()
                )


                frame = (
                    self.read_frame()
                )


                if frame is None:

                    continue


                self.raw_data.emit(
                    "RX: "
                    + frame.hex(
                        " "
                    ).upper()
                )


                tags = (
                    self.parse_response(
                        frame
                    )
                )


                for tag in tags:

                    self.tag_found.emit(
                        tag["epc"],
                        tag["epc_len"],
                        tag["rssi"],
                        tag["antenna"]
                    )


                    self.save_tag(
                        tag["epc"],
                        tag["rssi"]
                    )


                time.sleep(
                    self.interval_ms
                    / 1000
                )


        except Exception as e:

            if self.running:

                self.error_occurred.emit(
                    str(e)
                )


        finally:

            if self.sock:

                try:
                    self.sock.close()
                except Exception:
                    pass


            self.sock = None

            self.reader_finished.emit()


# ============================================================
# MAIN WINDOW
# ============================================================

class MainWindow(QMainWindow):


    def __init__(self):

        super().__init__()


        self.setWindowTitle(
            "ระบบตรวจนับบัณฑิต"
        )

        # -----------------------------------------------------
        # Application Icon
        # -----------------------------------------------------
        # วางไฟล์ mcru.png ไว้โฟลเดอร์เดียวกับไฟล์ Python
        icon_path = BASE_DIR / "mcru.png"
        if icon_path.exists():
            self.setWindowIcon(
                QIcon(str(icon_path))
            )

        self.resize(
            800,
            600
        )

        self.setMinimumSize(
            700,
            500
        )

        # UI อ่านง่าย โดยเฉพาะหน้าจอขนาดเล็ก
        self.setStyleSheet("""
            QLabel {
                font-size: 10pt;
            }
            QLineEdit, QComboBox {
                min-height: 28px;
                font-size: 10pt;
            }
            QPushButton {
                min-height: 28px;
                font-size: 10pt;
            }
            QGroupBox {
                font-weight: bold;
            }
        """)


        self.worker = None

        self.tags = {}

        # -----------------------------------------------------
        # API Sender
        # -----------------------------------------------------

        self.api_timer = QTimer(
            self
        )

        self.api_timer.timeout.connect(
            self.api_send_next_record
        )

        self.api_file_position = 0

        self.api_running = False

        self.api_connected = False
        self.api_authenticated = False

        self.api_sent_count = 0

        self.api_last_file_size = 0


        # -----------------------------------------------------
        # Round Token
        # -----------------------------------------------------

        self.round_tokens = (
            self.load_round_tokens()
        )

        self.current_round = "R1"

        self.round_token = ""


        # -----------------------------------------------------
        # Student
        # -----------------------------------------------------

        self.student_data = []

        self.load_student_data()


        # -----------------------------------------------------
        # UI
        # -----------------------------------------------------

        self.api_last_json = {
            "request": {},
            "response": None
        }

        self.create_ui()


    # ========================================================
    # ROUND TOKEN
    # ========================================================

    def load_round_tokens(self):

        tokens = {}


        if not ROUND_FILE.exists():

            print(
                f"ไม่พบไฟล์ {ROUND_FILE.name}"
            )

            return tokens


        try:

            with open(
                ROUND_FILE,
                "r",
                encoding="utf-8-sig"
            ) as file:

                for line in file:

                    line = line.strip()

                    if not line:
                        continue


                    parts = line.split(
                        None,
                        1
                    )


                    if len(parts) < 2:
                        continue


                    round_name = (
                        parts[0]
                        .strip()
                        .upper()
                    )

                    token = (
                        parts[1]
                        .strip()
                    )


                    if re.fullmatch(
                        r"R(?:10|[1-9])",
                        round_name
                    ):

                        tokens[
                            round_name
                        ] = token


        except Exception as e:

            print(
                "Round file error:",
                e
            )


        print(
            "Loaded Round-Token:",
            tokens
        )

        return tokens


    def get_round_token(
        self,
        round_name
    ):

        return self.round_tokens.get(
            round_name.strip().upper(),
            ""
        )


    # ========================================================
    # STUDENT CSV
    # ========================================================

    def load_student_data(self):

        self.student_data = []


        if not STUDENT_FILE.exists():

            print(
                "ไม่พบ student.csv"
            )

            return


        try:

            with open(
                STUDENT_FILE,
                "r",
                encoding="utf-8-sig",
                newline=""
            ) as file:

                reader = csv.DictReader(
                    file
                )


                fields = (
                    reader.fieldnames
                    or []
                )


                field_map = {}

                for field in fields:

                    key = (
                        str(field)
                        .strip()
                        .lower()
                        .replace(
                            "\ufeff",
                            ""
                        )
                    )

                    field_map[
                        key
                    ] = field


                def get_value(
                    row,
                    *names
                ):

                    for name in names:

                        original = (
                            field_map.get(
                                name.lower()
                            )
                        )

                        if original is not None:

                            value = normalize_text(
                                row.get(
                                    original
                                )
                            )

                            if value:
                                return value

                    return ""


                for row in reader:

                    rfid = normalize_rfid(
                        get_value(
                            row,
                            "rfid",
                            "epc",
                            "tag",
                            "tag_id"
                        )
                    )


                    self.student_data.append(
                        {
                            "rfid": rfid,

                            "std_id": get_value(
                                row,
                                "std_id",
                                "student_id",
                                "studentid",
                                "รหัสนักศึกษา"
                            ),

                            "seq": get_value(
                                row,
                                "seq",
                                "sequence",
                                "ลำดับ"
                            ),

                            "fullname": get_value(
                                row,
                                "fullname",
                                "full_name",
                                "name",
                                "ชื่อ-นามสกุล"
                            ),

                            "faculty": get_value(
                                row,
                                "faculty",
                                "คณะ"
                            ),

                            "major": get_value(
                                row,
                                "major",
                                "program",
                                "สาขาวิชา"
                            ),

                            "educational": get_value(
                                row,
                                "educational",
                                "education",
                                "degree",
                                "ชื่อปริญญา"
                            )
                        }
                    )


        except Exception as e:

            print(
                "Student CSV error:",
                e
            )


        print(
            "Dashboard Student:",
            len(
                self.student_data
            )
        )

        print(
            "Dashboard RFID:",
            sum(
                1
                for row
                in self.student_data
                if row["rfid"]
            )
        )


    # ========================================================
    # READ RFID LOG
    # ========================================================

    def read_rfid_log(self):

        records = []


        if not LOG_FILE.exists():
            return records


        # Token -> R1/R2/...
        token_to_round = {}

        for round_name, token in (
            self.round_tokens.items()
        ):

            key = normalize_rfid(
                token
            )

            if key:

                token_to_round[
                    key
                ] = round_name


        try:

            with open(
                LOG_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                for line in file:

                    line = line.strip()

                    if not line:
                        continue


                    parts = line.split(
                        "\t"
                    )


                    if len(parts) < 3:
                        continue


                    timestamp = (
                        parts[0].strip()
                    )

                    token_or_round = (
                        parts[1].strip()
                    )

                    epc = normalize_rfid(
                        parts[2]
                    )


                    if not epc:
                        continue


                    round_key = (
                        token_or_round.upper()
                    )


                    if re.fullmatch(
                        r"R(?:10|[1-9])",
                        round_key
                    ):

                        round_name = (
                            round_key
                        )

                    else:

                        round_name = (
                            token_to_round.get(
                                normalize_rfid(
                                    token_or_round
                                ),
                                ""
                            )
                        )


                    records.append(
                        {
                            "timestamp": timestamp,
                            "token": token_or_round,
                            "round": round_name,
                            "epc": epc
                        }
                    )


        except Exception as e:

            print(
                "RFID log error:",
                e
            )


        return records


    # ========================================================
    # CREATE UI
    # ========================================================

    def confirm_exit(self):
        """ถามยืนยันก่อนออกจากโปรแกรม"""
        reply = QMessageBox.question(
            self,
            "ยืนยันการออกจากโปรแกรม",
            "ต้องการออกจากโปรแกรมหรือไม่?",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.close()

    def closeEvent(self, event):
        """ถามยืนยันเมื่อกด X หรือสั่งปิดหน้าต่าง"""
        reply = QMessageBox.question(
            self,
            "ยืนยันการออกจากโปรแกรม",
            "ต้องการออกจากโปรแกรมหรือไม่?",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            event.accept()
        else:
            event.ignore()

    def create_ui(self):

        central = QWidget()

        self.setCentralWidget(
            central
        )


        layout = QVBoxLayout(
            central
        )


        self.tabs = QTabWidget()


        self.dashboard_tab = QWidget()

        self.result_tab = QWidget()

        self.rfid_tab = QWidget()

        self.api_tab = QWidget()


        self.tabs.addTab(
            self.dashboard_tab,
            "Dashboard"
        )

        self.tabs.addTab(
            self.result_tab,
            "Result"
        )

        self.tabs.addTab(
            self.rfid_tab,
            "RFID Check-in"
        )

        self.tabs.addTab(
            self.api_tab,
            "Api"
        )


        layout.addWidget(
            self.tabs,
            1
        )

        # -----------------------------------------------------
        # Footer
        # -----------------------------------------------------
        footer = QLabel(
            "พัฒนาโดยศูนย์สร้างสรรค์นวัตกรรมการเรียนรู้อัจฉริยะ "
            "ร่วมกับนักศึกษาวิทยาการคอมพิวเตอร์ "
            "มหาวิทยาลัยราชภัฏหมู่บ้านจอมบึง"
        )
        footer.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        footer.setWordWrap(True)
        footer.setMinimumHeight(34)
        footer.setStyleSheet("""
            QLabel {
                color: #64748b;
                font-size: 10px;
                padding: 6px 10px;
                border-top: 1px solid #e2e8f0;
                background: #f8fafc;
            }
        """)
        layout.addWidget(footer, 0)

        # -----------------------------------------------------
        # Bottom-right Exit button (อยู่นอก Query Tag)
        # -----------------------------------------------------
        bottom_bar = QHBoxLayout()
        bottom_bar.setContentsMargins(8, 4, 8, 6)

        bottom_bar.addStretch()

        self.main_exit_button = QPushButton("Exit")
        self.main_exit_button.setStyleSheet("""            QPushButton { background-color: #fee2e2; color: #b91c1c; font-weight: bold; }            QPushButton:hover { background-color: #fecaca; }        """)
        self.main_exit_button.setFixedSize(100, 32)
        self.main_exit_button.clicked.connect(self.confirm_exit)
        bottom_bar.addWidget(self.main_exit_button)

        layout.addLayout(bottom_bar)

        self.create_dashboard()

        self.create_result_page()

        self.create_rfid_page()

        self.create_api_page()


        self.tabs.currentChanged.connect(
            self.tab_changed
        )


        # เปิด RFID Check-in เป็นหน้าแรก
        self.tabs.setCurrentIndex(
            2
        )



    # ========================================================
    # API PAGE
    # ========================================================

    def create_api_page(self):
        """
        API Page แบบ Responsive
        - หน้าจอเล็กสามารถเลื่อนขึ้น/ลง และซ้าย/ขวาได้
        - ไม่ตัดข้อมูลเดิม
        - API Log เลื่อนดูได้เต็มตาราง
        - JSON สามารถเลื่อนแนวนอน/แนวตั้งได้
        """

        # -----------------------------------------------------
        # Outer layout
        # -----------------------------------------------------
        outer_layout = QVBoxLayout(self.api_tab)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # Scroll Area สำหรับทั้งหน้า API
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        scroll_area.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        scroll_area.setFrameShape(QScrollArea.Shape.NoFrame)

        # Content ด้านใน
        content = QWidget()

        # กำหนดความกว้างขั้นต่ำ เพื่อไม่ให้ช่องข้อมูลถูกบีบจนอ่านไม่ได้
        content.setMinimumWidth(1050)

        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 10, 12, 12)
        layout.setSpacing(8)

        scroll_area.setWidget(content)
        outer_layout.addWidget(scroll_area)

        # -----------------------------------------------------
        # Title
        # -----------------------------------------------------
        title = QLabel("API - ส่งข้อมูล RFID")
        title.setStyleSheet("""
            QLabel {
                font-size: 20px;
                font-weight: bold;
                padding: 4px 0px;
            }
        """)
        layout.addWidget(title)

        # -----------------------------------------------------
        # Session Storage / Authentication
        # -----------------------------------------------------
        session_box = QGroupBox("Session Storage / Authentication")
        session_layout = QGridLayout(session_box)
        session_layout.setContentsMargins(8, 8, 8, 8)
        session_layout.setHorizontalSpacing(8)
        session_layout.setVerticalSpacing(5)

        session_layout.addWidget(QLabel("Authen Link"), 0, 0)

        self.api_auth_url_edit = QLineEdit()
        self.api_auth_url_edit.setPlaceholderText(
            "https://example.com/api/authen"
        )
        self.api_auth_url_edit.setText(
            "https://chanwitduangbupha.xyz/cg/api/api-auth-login"
        )
        session_layout.addWidget(self.api_auth_url_edit, 0, 1, 1, 3)

        session_layout.addWidget(QLabel("email"), 1, 0)

        self.api_session_email = QLineEdit("admin@mcru.ac.th")
        session_layout.addWidget(self.api_session_email, 1, 1, 1, 3)

        session_layout.addWidget(QLabel("password"), 2, 0)

        self.api_session_password = QLineEdit("@Chanwit04")
        self.api_session_password.setEchoMode(
            QLineEdit.EchoMode.Password
        )
        session_layout.addWidget(self.api_session_password, 2, 1, 1, 3)

        session_layout.addWidget(QLabel("token"), 3, 0)

        self.api_session_token = QLineEdit(
            self.generate_api_token()
        )
        self.api_session_token.setMinimumWidth(400)
        session_layout.addWidget(self.api_session_token, 3, 1, 1, 2)

        regenerate_token_button = QPushButton("สร้าง Token ใหม่")
        regenerate_token_button.clicked.connect(
            self.api_regenerate_token
        )
        session_layout.addWidget(regenerate_token_button, 3, 3)

        self.api_auth_button = QPushButton("Authen")
        self.api_auth_button.clicked.connect(
            self.api_authenticate
        )
        session_layout.addWidget(self.api_auth_button, 4, 1)

        self.api_logout_button = QPushButton("Logout")
        self.api_logout_button.setEnabled(False)
        self.api_logout_button.clicked.connect(
            self.api_logout
        )
        session_layout.addWidget(self.api_logout_button, 4, 2)

        self.api_auth_status = QLabel(
            "Status: Not Authenticated"
        )
        self.api_auth_status.setStyleSheet("""
            QLabel {
                color: #dc2626;
                font-weight: bold;
            }
        """)
        self.api_auth_status.setWordWrap(True)
        session_layout.addWidget(self.api_auth_status, 4, 3)

        session_layout.addWidget(
            QLabel("Authen JSON Response"),
            5, 0, 1, 4
        )

        self.api_auth_json = QPlainTextEdit()
        self.api_auth_json.setReadOnly(True)
        self.api_auth_json.setPlaceholderText(
            "เมื่อ Authen สำเร็จ จะแสดง JSON Response จาก Server ที่นี่"
        )
        self.api_auth_json.setMinimumHeight(120)
        self.api_auth_json.setMaximumHeight(180)
        self.api_auth_json.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.api_auth_json.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.api_auth_json.setLineWrapMode(
            QPlainTextEdit.LineWrapMode.NoWrap
        )
        self.api_auth_json.setStyleSheet("""
            QPlainTextEdit {
                font-family: Consolas, "Courier New";
                font-size: 11px;
                background: #ffffff;
                border: 1px solid #cbd5e1;
            }
        """)
        session_layout.addWidget(
            self.api_auth_json,
            6, 0, 1, 4
        )

        session_note = QLabel(
            "ต้อง Authen สำเร็จก่อน จึงจะเริ่มส่งข้อมูล RFID ได้"
        )
        session_note.setStyleSheet("color: #64748b;")
        session_note.setWordWrap(True)
        session_layout.addWidget(
            session_note,
            7, 0, 1, 4
        )

        session_layout.setColumnStretch(1, 1)
        session_layout.setColumnStretch(2, 1)
        session_layout.setColumnStretch(3, 1)

        layout.addWidget(session_box)

        # -----------------------------------------------------
        # API Connection
        # -----------------------------------------------------
        connection_box = QGroupBox("API Connection")
        grid = QGridLayout(connection_box)
        grid.setContentsMargins(8, 8, 8, 8)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(5)

        grid.addWidget(QLabel("API Link:"), 0, 0)

        self.api_url_edit = QLineEdit(
            "https://chanwitduangbupha.xyz/cg/api/admin-exam-add"
        )
        grid.addWidget(self.api_url_edit, 0, 1, 1, 5)

        grid.addWidget(QLabel("Method:"), 1, 0)

        self.api_method_combo = QComboBox()
        self.api_method_combo.addItems(["POST"])
        self.api_method_combo.setCurrentText("POST")
        self.api_method_combo.setFixedWidth(80)
        grid.addWidget(self.api_method_combo, 1, 1)

        grid.addWidget(QLabel("room:"), 1, 2)

        self.api_room_token_edit = QLineEdit()
        self.api_room_token_edit.setPlaceholderText(
            "กรอก Room ด้วยตนเอง"
        )
        self.api_room_token_edit.setText(
            "2y12WxpxM3zSf0vcOuljgG7yxOi31SQYnwpOM8FLvKeZ8B7hmuDhELh1m"
        )
        grid.addWidget(self.api_room_token_edit, 1, 3)

        grid.addWidget(QLabel("Type:"), 1, 4)

        self.api_type_value = QLineEdit("rfid")
        self.api_type_value.setReadOnly(True)
        self.api_type_value.setFixedWidth(100)
        grid.addWidget(self.api_type_value, 1, 5)

        grid.addWidget(QLabel("ส่งทุก:"), 2, 0)

        self.api_interval_spin = QComboBox()
        self.api_interval_spin.addItems(
            ["1", "2", "3", "5", "10", "15", "30", "60"]
        )
        self.api_interval_spin.setCurrentText("5")
        self.api_interval_spin.setFixedWidth(80)
        grid.addWidget(self.api_interval_spin, 2, 1)

        grid.addWidget(QLabel("วินาที"), 2, 2)

        self.api_connection_status = QLabel(
            "Status: Not Authenticated"
        )
        self.api_connection_status.setStyleSheet("""
            QLabel {
                color: #dc2626;
                font-weight: bold;
            }
        """)
        self.api_connection_status.setWordWrap(True)
        grid.addWidget(
            self.api_connection_status,
            2, 3, 1, 3
        )

        grid.setColumnStretch(3, 1)

        layout.addWidget(connection_box)

        # -----------------------------------------------------
        # Parameters
        # -----------------------------------------------------
        parameter_box = QGroupBox("Parameters ที่ส่งไป")
        parameter_layout = QGridLayout(parameter_box)
        parameter_layout.setContentsMargins(8, 8, 8, 8)
        parameter_layout.setHorizontalSpacing(8)
        parameter_layout.setVerticalSpacing(5)

        parameter_layout.addWidget(
            QLabel("round"), 0, 0
        )

        self.api_round_value = QComboBox()
        self.api_round_value.addItems(
            ["R1", "R2", "R3", "R4", "R5"]
        )
        self.api_round_value.setCurrentText("R1")
        self.api_round_value.currentTextChanged.connect(
            self.api_round_selection_changed
        )
        self.api_round_value.setFixedWidth(100)
        parameter_layout.addWidget(
            self.api_round_value, 0, 1
        )

        parameter_layout.addWidget(
            QLabel("round-token"), 0, 2
        )

        self.api_round_token_value = QLineEdit()
        self.api_round_token_value.setReadOnly(True)
        self.api_round_token_value.setPlaceholderText(
            "Token จาก round.txt"
        )
        parameter_layout.addWidget(
            self.api_round_token_value, 0, 3
        )

        parameter_layout.addWidget(
            QLabel("std_id"), 1, 0
        )

        self.api_std_id_value = QLineEdit("-")
        self.api_std_id_value.setReadOnly(True)
        parameter_layout.addWidget(
            self.api_std_id_value, 1, 1
        )

        parameter_layout.addWidget(
            QLabel("code"), 1, 2
        )

        self.api_code_value = QLineEdit("-")
        self.api_code_value.setReadOnly(True)
        parameter_layout.addWidget(
            self.api_code_value, 1, 3
        )

        note = QLabel(
            "round = เลือก R1-R5 และระบบใช้ Token ของรอบนั้นจาก round.txt; "
            "room = กรอกเอง"
        )
        note.setStyleSheet("color: #64748b;")
        note.setWordWrap(True)
        parameter_layout.addWidget(
            note, 2, 0, 1, 4
        )

        parameter_layout.setColumnStretch(3, 1)

        # สำคัญ: เพิ่ม parameter_box เพียงครั้งเดียว
        layout.addWidget(parameter_box)

        # -----------------------------------------------------
        # Control
        # -----------------------------------------------------
        control_layout = QHBoxLayout()
        control_layout.setSpacing(6)

        self.api_start_button = QPushButton("เริ่มส่งข้อมูล")
        self.api_start_button.clicked.connect(
            self.start_api_sender
        )
        control_layout.addWidget(self.api_start_button)

        self.api_stop_button = QPushButton("หยุดส่งข้อมูล")
        self.api_stop_button.setEnabled(False)
        self.api_stop_button.clicked.connect(
            self.stop_api_sender
        )
        control_layout.addWidget(self.api_stop_button)

        self.api_reset_button = QPushButton(
            "เริ่มอ่านจากท้ายไฟล์ใหม่"
        )
        self.api_reset_button.clicked.connect(
            self.reset_api_position
        )
        control_layout.addWidget(self.api_reset_button)

        self.api_view_json_button = QPushButton("ดู JSON")
        self.api_view_json_button.clicked.connect(
            self.show_api_json
        )
        control_layout.addWidget(self.api_view_json_button)

        control_layout.addStretch()

        self.api_status_label = QLabel(
            "สถานะ: หยุดส่ง"
        )
        self.api_status_label.setStyleSheet(
            "font-weight: bold;"
        )
        self.api_status_label.setWordWrap(True)
        control_layout.addWidget(self.api_status_label)

        self.api_http_status_label = QLabel("HTTP: -")
        self.api_http_status_label.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: #64748b;
            }
        """)
        control_layout.addWidget(
            self.api_http_status_label
        )

        self.api_sent_label = QLabel("ส่งแล้ว: 0")
        control_layout.addWidget(
            self.api_sent_label
        )

        layout.addLayout(control_layout)

        # -----------------------------------------------------
        # API Log
        # -----------------------------------------------------
        log_box = QGroupBox("API Log")
        log_layout = QVBoxLayout(log_box)
        log_layout.setContentsMargins(6, 6, 6, 6)

        self.api_log = QTableWidget()
        self.api_log.setColumnCount(5)
        self.api_log.setHorizontalHeaderLabels(
            [
                "เวลา",
                "Round",
                "std_id",
                "RFID",
                "Result"
            ]
        )

        self.api_log.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        self.api_log.cellDoubleClicked.connect(
            self.show_api_log_json
        )

        self.api_log.setAlternatingRowColors(True)

        # เลื่อนตารางได้ทั้งแนวนอนและแนวตั้ง
        self.api_log.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.api_log.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )

        # ทำให้เลือกทั้งแถวได้ อ่านง่ายขึ้น
        self.api_log.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.api_log.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )

        # ปรับขนาดคอลัมน์
        self.api_log.setColumnWidth(0, 155)
        self.api_log.setColumnWidth(1, 75)
        self.api_log.setColumnWidth(2, 140)
        self.api_log.setColumnWidth(3, 230)
        self.api_log.setColumnWidth(4, 360)

        # Header ปรับขนาดได้
        self.api_log.horizontalHeader().setStretchLastSection(False)

        # ความสูงเริ่มต้นให้เห็นหลายรายการ
        self.api_log.setMinimumHeight(260)

        log_layout.addWidget(self.api_log)
        layout.addWidget(log_box, 1)

        # -----------------------------------------------------
        # Initial values
        # -----------------------------------------------------
        self.api_round_selection_changed(
            self.api_round_value.currentText()
        )

        # เริ่มจากท้ายไฟล์ ไม่ส่งข้อมูลเก่าทันที
        self.reset_api_position()

    def generate_api_token(self):

        # PHP Server ตรวจด้วย password_verify():
        #
        # password_verify(
        #     '@pbMLauMcru00123456#',
        #     $passwd
        # )
        #
        # ดังนั้น Token ต้องเป็น bcrypt password hash
        # ที่สามารถตรวจสอบด้วย password_verify() ได้

        password = "@pbMLauMcru00123456#"

        hashed = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt(
                rounds=10
            )
        )

        return hashed.decode("utf-8")

    def set_api_round(self, round_name):

        if hasattr(
            self,
            "api_round_value"
        ):

            index = (
                self.api_round_value
                .findText(
                    round_name
                )
            )

            if index >= 0:

                self.api_round_value.setCurrentIndex(
                    index
                )


    def api_round_selection_changed(
        self,
        round_name
    ):

        round_name = (
            round_name
            .strip()
            .upper()
        )

        round_token = (
            self.round_tokens.get(
                round_name,
                ""
            )
        )

        self.api_round_token_value.setText(
            round_token
        )


    def api_regenerate_token(self):

        self.api_session_token.setText(
            self.generate_api_token()
        )


    def api_get_session_storage(self):

        return {
            "email": (
                self.api_session_email
                .text()
                .strip()
            ),
            "password": (
                self.api_session_password
                .text()
            ),
            "token": (
                self.api_session_token
                .text()
                .strip()
            )
        }



    # ========================================================
    # API CONNECTION
    # ========================================================

    def api_set_connection_status(
        self,
        connected,
        message=None
    ):

        self.api_connected = connected


        if connected:

            text = (
                "Status: Connected"
            )

            if message:

                text += (
                    f" - {message}"
                )

            self.api_connection_status.setText(
                text
            )

            self.api_connection_status.setStyleSheet(
                """
                color: #16a34a;
                font-weight: bold;
                """
            )

            self.api_connect_button.setEnabled(
                False
            )

            self.api_close_button.setEnabled(
                True
            )

        else:

            text = (
                "Status: Disconnected"
            )

            if message:

                text += (
                    f" - {message}"
                )

            self.api_connection_status.setText(
                text
            )

            self.api_connection_status.setStyleSheet(
                """
                color: #dc2626;
                font-weight: bold;
                """
            )

            self.api_connect_button.setEnabled(
                True
            )

            self.api_close_button.setEnabled(
                False
            )


    def api_connect(self):

        url = (
            self.api_url_edit
            .text()
            .strip()
        )


        if not url:

            self.api_set_connection_status(
                False,
                "กรุณาระบุ API Link"
            )

            return


        if not (
            url.startswith("http://")
            or url.startswith("https://")
        ):

            self.api_set_connection_status(
                False,
                "Invalid URL"
            )

            return


        method = (
            self.api_method_combo
            .currentText()
            .upper()
        )


        params = {
            "round": (
                self.api_round_value
                .text()
                .strip()
                or "R1"
            ),
            "std_id": (
                self.api_std_id_value
                .text()
                .strip()
                or ""
            )
        }


        try:

            if method in (
                "GET",
                "DELETE"
            ):

                query = urllib.parse.urlencode(
                    params
                )

                separator = (
                    "&"
                    if "?" in url
                    else "?"
                )

                request = urllib.request.Request(
                    url
                    + separator
                    + query,
                    method=method
                )

            else:

                body = (
                    urllib.parse.urlencode(
                        params
                    ).encode(
                        "utf-8"
                    )
                )

                request = urllib.request.Request(
                    url,
                    data=body,
                    method=method
                )

                request.add_header(
                    "Content-Type",
                    "application/x-www-form-urlencoded; charset=utf-8"
                )


            session = (
                self.api_get_session_storage()
            )


            request.headers["email"] = (
                session["email"]
            )

            request.headers["password"] = (
                session["password"]
            )

            request.headers["token"] = (
                session["token"]
            )


            # ทดสอบการเชื่อมต่อด้วย Request จริง
            # HTTP 2xx / 3xx ถือว่า API ติดต่อได้
            with urllib.request.urlopen(
                request,
                timeout=5
            ) as response:

                status_code = (
                    response.status
                )


            self.api_set_connection_status(
                True,
                f"HTTP {status_code}"
            )


        except urllib.error.HTTPError as e:

            # แม้ API ตอบ 4xx/5xx แปลว่า Server ติดต่อถึงแล้ว
            self.api_set_connection_status(
                True,
                f"Server reachable - HTTP {e.code}"
            )


        except urllib.error.URLError as e:

            self.api_set_connection_status(
                False,
                str(e.reason)
            )


        except Exception as e:

            self.api_set_connection_status(
                False,
                str(e)
            )


    def api_disconnect(self):

        self.api_logout()



    # ========================================================
    # API AUTHENTICATION
    # ========================================================

    def api_set_auth_status(
        self,
        authenticated,
        message=None
    ):

        self.api_authenticated = authenticated


        if authenticated:

            text = "Status: Authenticated"

            if message:
                text += f" - {message}"

            self.api_auth_status.setText(
                text
            )

            self.api_auth_status.setStyleSheet(
                """
                color: #16a34a;
                font-weight: bold;
                """
            )

            self.api_connection_status.setText(
                text
            )

            self.api_connection_status.setStyleSheet(
                """
                color: #16a34a;
                font-weight: bold;
                """
            )

            self.api_auth_button.setEnabled(
                False
            )

            self.api_logout_button.setEnabled(
                True
            )

            self.api_auth_url_edit.setEnabled(
                False
            )

            self.api_session_email.setEnabled(
                False
            )

            self.api_session_password.setEnabled(
                False
            )

            self.api_session_token.setEnabled(
                False
            )

        else:

            text = "Status: Not Authenticated"

            if message:
                text += f" - {message}"

            self.api_auth_status.setText(
                text
            )

            self.api_auth_status.setStyleSheet(
                """
                color: #dc2626;
                font-weight: bold;
                """
            )

            self.api_connection_status.setText(
                text
            )

            self.api_connection_status.setStyleSheet(
                """
                color: #dc2626;
                font-weight: bold;
                """
            )

            self.api_auth_button.setEnabled(
                True
            )

            self.api_logout_button.setEnabled(
                False
            )

            self.api_auth_url_edit.setEnabled(
                True
            )

            self.api_session_email.setEnabled(
                True
            )

            self.api_session_password.setEnabled(
                True
            )

            self.api_session_token.setEnabled(
                True
            )


    def api_authenticate(self):

        url = (
            self.api_auth_url_edit
            .text()
            .strip()
        )


        if not url:

            self.api_set_auth_status(
                False,
                "กรุณาระบุ Authen Link"
            )

            return


        if not (
            url.startswith("http://")
            or url.startswith("https://")
        ):

            self.api_set_auth_status(
                False,
                "Invalid URL"
            )

            return


        session = (
            self.api_get_session_storage()
        )


        if not session["email"]:

            self.api_set_auth_status(
                False,
                "กรุณาระบุ email"
            )

            return


        if not session["password"]:

            self.api_set_auth_status(
                False,
                "กรุณาระบุ password"
            )

            return


        if not session["token"]:

            self.api_set_auth_status(
                False,
                "กรุณาระบุ token"
            )

            return


        try:

            # -------------------------------------------------
            # Authen Request
            #
            # ตาม Request จริง:
            #
            # POST /cfg/api/api-auth-login
            # Content-Type:
            # application/x-www-form-urlencoded
            #
            # Body:
            # email=...
            # &password=...
            # &token=...
            # -------------------------------------------------

            auth_payload = {
                "email": session["email"],
                "password": session["password"],
                "token": session["token"]
            }


            auth_body = (
                urllib.parse.urlencode(
                    auth_payload
                ).encode(
                    "utf-8"
                )
            )


            request = urllib.request.Request(
                url,
                data=auth_body,
                method="POST"
            )


            request.add_header(
                "Content-Type",
                "application/x-www-form-urlencoded; charset=UTF-8"
            )

            request.add_header(
                "Accept",
                "application/json"
            )


            with urllib.request.urlopen(
                request,
                timeout=10
            ) as response:

                status_code = (
                    response.status
                )

                response_text = (
                    response.read()
                    .decode(
                        "utf-8",
                        errors="replace"
                    )
                )


            # -------------------------------------------------
            # แสดง JSON Response เต็มบน UI
            # -------------------------------------------------

            try:

                auth_json = json.loads(
                    response_text
                )


                self.api_auth_json.setPlainText(
                    json.dumps(
                        auth_json,
                        ensure_ascii=False,
                        indent=2
                    )
                )


            except json.JSONDecodeError:

                self.api_auth_json.setPlainText(
                    response_text
                )

                self.api_set_auth_status(
                    False,
                    "Authen Response ไม่ใช่ JSON"
                )

                return


            # -------------------------------------------------
            # ตรวจสอบผล Authen
            #
            # ต้องได้:
            #
            # token  = true
            # email  = true
            # status = true
            # -------------------------------------------------

            token_ok = (
                auth_json.get(
                    "token"
                ) is True
            )

            email_ok = (
                auth_json.get(
                    "email"
                ) is True
            )

            status_ok = (
                auth_json.get(
                    "status"
                ) is True
            )


            # -------------------------------------------------
            # ดึง Token จริงจาก Server
            # data.token
            # -------------------------------------------------

            data = auth_json.get(
                "data",
                {}
            )


            server_token = ""


            if isinstance(
                data,
                dict
            ):

                server_token = str(
                    data.get(
                        "token",
                        ""
                    )
                ).strip()


            # -------------------------------------------------
            # Authen ไม่ผ่าน
            # -------------------------------------------------

            if not (
                token_ok
                and email_ok
                and status_ok
            ):

                self.api_set_auth_status(
                    False,
                    f"HTTP {status_code} - Authen ไม่สำเร็จ"
                )

                return


            # -------------------------------------------------
            # Authen ผ่าน
            # ใช้ Token ที่ Server ส่งกลับมา
            # -------------------------------------------------

            if server_token:

                self.api_session_token.setText(
                    server_token
                )


            self.api_set_auth_status(
                True,
                f"HTTP {status_code}"
            )


        except urllib.error.HTTPError as e:

            response_text = ""

            try:

                response_text = (
                    e.read()
                    .decode(
                        "utf-8",
                        errors="replace"
                    )
                )

            except Exception:
                pass


            if response_text:

                self.api_auth_json.setPlainText(
                    response_text
                )


            self.api_set_auth_status(
                False,
                f"HTTP {e.code}"
            )


        except urllib.error.URLError as e:

            self.api_set_auth_status(
                False,
                str(e.reason)
            )


        except Exception as e:

            self.api_set_auth_status(
                False,
                str(e)
            )


    def api_logout(self):

        if self.api_running:

            self.stop_api_sender()


        self.api_set_auth_status(
            False
        )

        if hasattr(
            self,
            "api_auth_json"
        ):

            self.api_auth_json.clear()


    # ========================================================
    # API FILE POSITION
    # ========================================================

    def reset_api_position(self):

        try:

            if LOG_FILE.exists():

                self.api_file_position = (
                    LOG_FILE.stat().st_size
                )

                self.api_last_file_size = (
                    self.api_file_position
                )

            else:

                self.api_file_position = 0
                self.api_last_file_size = 0

        except Exception:

            self.api_file_position = 0
            self.api_last_file_size = 0


    # ========================================================
    # API START
    # ========================================================

    def start_api_sender(self):

        if not self.api_authenticated:

            self.api_set_auth_status(
                False,
                "กรุณา Authen ก่อนเริ่มส่งข้อมูล"
            )

            return


        url = (
            self.api_url_edit
            .text()
            .strip()
        )


        if not url:

            QMessageBox.warning(
                self,
                "API",
                "กรุณาระบุ API Link"
            )

            return


        if not (
            url.startswith("http://")
            or url.startswith("https://")
        ):

            QMessageBox.warning(
                self,
                "API",
                "API Link ต้องขึ้นต้นด้วย http:// หรือ https://"
            )

            return


        if not self.api_room_token_edit.text().strip():

            QMessageBox.warning(
                self,
                "API",
                "กรุณาระบุ Room Token"
            )

            return


        try:

            seconds = float(
                self.api_interval_spin
                .currentText()
            )

        except Exception:

            seconds = 5


        self.api_timer.setInterval(
            max(
                100,
                int(
                    seconds * 1000
                )
            )
        )


        # ทุกครั้งที่กดเริ่ม จะอ่านเฉพาะข้อมูลใหม่
        self.reset_api_position()


        self.api_running = True

        self.api_sent_count = 0


        self.api_sent_label.setText(
            "ส่งแล้ว: 0"
        )

        self.api_status_label.setText(
            "สถานะ: กำลังส่งข้อมูล"
        )

        self.api_http_status_label.setText(
            "HTTP: -"
        )

        self.api_http_status_label.setStyleSheet(
            """
            font-weight: bold;
            color: #64748b;
            """
        )


        self.api_start_button.setEnabled(
            False
        )

        self.api_stop_button.setEnabled(
            True
        )

        self.api_url_edit.setEnabled(
            False
        )

        self.api_method_combo.setEnabled(
            False
        )

        self.api_interval_spin.setEnabled(
            False
        )

        self.api_room_token_edit.setEnabled(
            False
        )


        self.api_timer.start()


        # เช็คข้อมูลทันที 1 ครั้ง
        self.api_send_next_record()


    # ========================================================
    # API STOP
    # ========================================================

    def stop_api_sender(self):

        self.api_running = False

        self.api_timer.stop()


        self.api_status_label.setText(
            "สถานะ: หยุดส่ง"
        )


        self.api_start_button.setEnabled(
            True
        )

        self.api_stop_button.setEnabled(
            False
        )

        self.api_url_edit.setEnabled(
            True
        )

        self.api_method_combo.setEnabled(
            True
        )

        self.api_interval_spin.setEnabled(
            True
        )

        self.api_room_token_edit.setEnabled(
            True
        )


    # ========================================================
    # API READ NEXT RFID LOG
    # ========================================================

    def api_read_next_record(self):

        if not LOG_FILE.exists():
            return None


        try:

            file_size = (
                LOG_FILE.stat().st_size
            )


            # ถ้าไฟล์ถูกล้างหรือสร้างใหม่
            if file_size < self.api_file_position:

                self.api_file_position = 0


            with open(
                LOG_FILE,
                "rb"
            ) as file:

                file.seek(
                    self.api_file_position
                )

                position_before = (
                    file.tell()
                )

                line = file.readline()


                # ยังไม่มีบรรทัดใหม่
                if not line:

                    return None


                # ถ้าบรรทัดยังเขียนไม่จบ
                # อย่าเลื่อนตำแหน่ง เพื่อรอรอบถัดไป
                if not line.endswith(
                    b"\n"
                ):

                    self.api_file_position = (
                        position_before
                    )

                    return None


                self.api_file_position = (
                    file.tell()
                )


            text = line.decode(
                "utf-8",
                errors="ignore"
            ).strip()


            parts = text.split(
                "\t"
            )


            if len(parts) < 3:

                return {
                    "timestamp": "",
                    "token": "",
                    "epc": ""
                }


            return {
                "timestamp": parts[0].strip(),
                "token": parts[1].strip(),
                "epc": normalize_rfid(
                    parts[2]
                )
            }


        except Exception as e:

            self.api_add_log(
                "",
                "",
                "",
                f"อ่าน rfid_tags.txt ไม่ได้: {e}"
            )

            return None


    # ========================================================
    # API SEND NEXT RECORD
    # ========================================================

    def api_send_next_record(self):

        if not self.api_running:
            return


        record = (
            self.api_read_next_record()
        )


        if record is None:
            return


        epc = record.get(
            "epc",
            ""
        )


        if not epc:
            return


        # หา student จาก RFID
        student = None

        for row in self.student_data:

            if normalize_rfid(
                row.get("rfid", "")
            ) == epc:

                student = row
                break


        std_id = ""

        if student is not None:

            std_id = normalize_text(
                student.get(
                    "std_id",
                    ""
                )
            )


        # รอบที่ส่ง API ให้ใช้รอบที่ผู้ใช้เลือกจาก ComboBox R1-R5
        # ไม่ใช้ setText() เพราะ api_round_value เป็น QComboBox
        round_name = (
            self.api_round_value
            .currentText()
            .strip()
            .upper()
        )


        if not re.fullmatch(
            r"R[1-5]",
            round_name
        ):

            round_name = "R1"

            index = (
                self.api_round_value
                .findText(
                    round_name
                )
            )

            if index >= 0:

                self.api_round_value.setCurrentIndex(
                    index
                )


        self.api_std_id_value.setText(
            std_id or "-"
        )


        # ส่งข้อมูลตาม Method
        success, result = (
            self.api_call(
                round_name,
                std_id,
                epc
            )
        )


        # ใช้วันที่และเวลาที่ RFID ถูกอ่านจริงจาก rfid_tags.txt
        # ถ้าไฟล์ไม่มี timestamp จึง fallback เป็นเวลาปัจจุบัน
        timestamp = record.get(
            "timestamp",
            ""
        ).strip()

        if not timestamp:
            timestamp = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )


        self.api_add_log(
            timestamp,
            round_name,
            std_id,
            epc,
            result
        )


        if success:

            self.api_sent_count += 1

            self.api_sent_label.setText(
                f"ส่งแล้ว: {self.api_sent_count:,}"
            )


    # ========================================================
    # API CALL
    # ========================================================

    def api_call(
        self,
        round_name,
        std_id,
        epc
    ):

        """
        ส่งข้อมูลไปยัง admin-exam-add ให้ตรงกับ PHP:

            $code     = $this->input->post('code');
            $round    = $this->input->post('round');
            $room     = $this->input->post('room');
            $type     = $this->input->post('type');
            $username = $this->input->post('username');

        ดังนั้น Request ใช้:
            POST
            application/x-www-form-urlencoded

        ไม่ส่ง JSON body และไม่ส่ง email/password/token
        เป็น parameter ของ admin-exam-add
        """

        url = (
            self.api_url_edit
            .text()
            .strip()
        )

        if not url:
            return (
                False,
                "API URL ว่าง"
            )


        # ----------------------------------------------------------
        # Authen ต้องผ่านก่อน
        # ----------------------------------------------------------
        if not getattr(
            self,
            "api_authenticated",
            False
        ):

            return (
                False,
                "ยังไม่ได้ Authen"
            )


        # ----------------------------------------------------------
        # Round
        #
        # UI = R1-R5
        # API = Token จริงจาก round.txt
        # ----------------------------------------------------------
        selected_round = (
            str(round_name)
            .strip()
            .upper()
        )

        # จำกัดรอบที่ API รองรับไว้ R1-R5
        if selected_round not in (
            "R1",
            "R2",
            "R3",
            "R4",
            "R5"
        ):
            selected_round = (
                self.api_round_value
                .currentText()
                .strip()
                .upper()
            )

        # อัปเดต Dropdown ให้ตรงกับรายการที่กำลังส่ง
        index = self.api_round_value.findText(
            selected_round
        )

        if index >= 0:
            self.api_round_value.setCurrentIndex(
                index
            )

        round_token = (
            self.round_tokens.get(
                selected_round,
                ""
            )
        )


        if not round_token:

            return (
                False,
                f"ไม่พบ Round Token ของ {selected_round}"
            )


        # ----------------------------------------------------------
        # Room
        #
        # กรอกเอง ไม่อ่าน room.txt
        # ----------------------------------------------------------
        room = (
            self.api_room_token_edit
            .text()
            .strip()
        )


        # ----------------------------------------------------------
        # Type
        # ----------------------------------------------------------
        api_type = (
            self.api_type_value
            .text()
            .strip()
        )

        if not api_type:
            api_type = "rfid"


        # ----------------------------------------------------------
        # Username
        #
        # ใช้ email ที่ Authen
        # ----------------------------------------------------------
        session = (
            self.api_get_session_storage()
        )

        username = (
            session.get(
                "email",
                ""
            )
            .strip()
        )


        # ----------------------------------------------------------
        # POST DATA
        #
        # ตรงกับ PHP input->post() ทั้ง 5 ตัว
        # ----------------------------------------------------------
        #payload = {
        #    "code": str(epc).strip(),
        #    "round": round_token,
        #    "room": room,
        #    "type": api_type,
        #    "username": username
        #}

        payload = {
            "code": str(epc).strip(),
            "round": str(round_token).strip(),
            "room": str(room).strip(),
            "type": str(api_type).strip(),
            "username": str(username).strip()
            }


        # ----------------------------------------------------------
        # แสดงค่าใน Parameters UI
        # ----------------------------------------------------------
        if hasattr(
            self,
            "api_round_token_value"
        ):

            self.api_round_token_value.setText(
                round_token
            )


        if hasattr(
            self,
            "api_code_value"
        ):

            self.api_code_value.setText(
                str(epc).strip()
            )


        if hasattr(
            self,
            "api_std_id_value"
        ):

            self.api_std_id_value.setText(
                str(std_id).strip()
                or "-"
            )


        # ----------------------------------------------------------
        # POST x-www-form-urlencoded
        #
        # ตรงกับ Postman:
        # Body -> x-www-form-urlencoded
        #
        # PHP รับโดยตรงด้วย:
        # $this->input->post('code')
        # $this->input->post('round')
        # $this->input->post('room')
        # $this->input->post('type')
        # $this->input->post('username')
        #
        # ไม่มี data:{} และไม่มี application/x-www-form-urlencoded
        # ----------------------------------------------------------

        body = urllib.parse.urlencode(
            payload
        ).encode(
            "utf-8"
        )

        request = urllib.request.Request(
            url,
            data=body,
            method="POST"
        )

        request.add_header(
            "Content-Type",
            "application/x-www-form-urlencoded; charset=UTF-8"
        )

        request.add_header(
            "Accept",
            "application/json, text/plain, */*"
        )

        request.add_header(
            "Connection",
            "keep-alive"
        )



        # ----------------------------------------------------------
        # เก็บ Request JSON สำหรับปุ่ม "ดู JSON"
        # ----------------------------------------------------------
        # เก็บข้อมูลสำหรับ JSON Viewer โดยไม่สร้าง "data:{}"
        # เพราะ PHP รับค่าโดยตรงจาก $this->input->post(...)
        self.api_last_json = {
            "request": {
                "method": "POST",
                "url": url,
                "headers": {
                    "Content-Type":
                        "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept":
                        "application/json, text/plain, */*",
                    "Connection":
                        "keep-alive"
                },

                # Form fields ที่ส่งจริง
                "code": payload["code"],
                "round": payload["round"],
                "room": payload["room"],
                "type": payload["type"],
                "username": payload["username"],

                # ข้อมูลที่ส่งแบบ Postman form-data
                "form_data": payload,

                # Body จริงบน wire
                "form_body": body.decode(
                    "utf-8",
                    errors="replace"
                ),

                # PHP ปลายทางรับด้วย input->post() โดยตรง
                "post_parameters": payload
            },

            "response": None
        }


        # ----------------------------------------------------------
        # ส่ง Request
        # ----------------------------------------------------------
        try:

            with urllib.request.urlopen(
                request,
                timeout=15
            ) as response:

                status_code = (
                    response.status
                )

                response_body = (
                    response.read()
                    .decode(
                        "utf-8",
                        errors="replace"
                    )
                )


            parsed_response = (
                self._try_parse_json(
                    response_body
                )
            )


            self.api_last_json["response"] = {
                "http_status": status_code,
                "body": parsed_response
            }


            # แสดง HTTP Status บริเวณสถานะการส่ง
            self.api_http_status_label.setText(
                f"HTTP: {status_code}"
            )

            self.api_http_status_label.setStyleSheet(
                """
                font-weight: bold;
                color: #16a34a;
                """
                if 200 <= status_code < 300
                else
                """
                font-weight: bold;
                color: #dc2626;
                """
            )


            # ------------------------------------------------------
            # HTTP 2xx = ส่งสำเร็จ
            # ------------------------------------------------------
            if 200 <= status_code < 300:

                return (
                    True,
                    f"HTTP {status_code}: {response_body}"
                )


            return (
                False,
                f"HTTP {status_code}: {response_body}"
            )


        except urllib.error.HTTPError as e:

            error_body = ""

            try:

                error_body = (
                    e.read()
                    .decode(
                        "utf-8",
                        errors="replace"
                    )
                )

            except Exception:
                pass


            self.api_last_json["response"] = {
                "http_status": e.code,
                "body": self._try_parse_json(
                    error_body
                )
            }


            # Server ตอบกลับด้วย 4xx / 5xx
            self.api_http_status_label.setText(
                f"HTTP: {e.code}"
            )

            self.api_http_status_label.setStyleSheet(
                """
                font-weight: bold;
                color: #dc2626;
                """
            )


            return (
                False,
                f"HTTP {e.code}: {error_body}"
            )


        except urllib.error.URLError as e:

            self.api_last_json["response"] = {
                "http_status": None,
                "body": str(e.reason)
            }


            self.api_http_status_label.setText(
                "HTTP: Connection Error"
            )

            self.api_http_status_label.setStyleSheet(
                """
                font-weight: bold;
                color: #dc2626;
                """
            )


            return (
                False,
                f"Connection Error: {e.reason}"
            )


        except Exception as e:

            self.api_last_json["response"] = {
                "http_status": None,
                "body": str(e)
            }


            self.api_http_status_label.setText(
                "HTTP: ERROR"
            )

            self.api_http_status_label.setStyleSheet(
                """
                font-weight: bold;
                color: #dc2626;
                """
            )


            return (
                False,
                f"ERROR: {e}"
            )



    def _try_parse_json(self, text):
        try:
            return json.loads(text)
        except Exception:
            return text


    def show_api_log_json(
        self,
        row,
        column
    ):

        if not hasattr(
            self,
            "api_log_json_data"
        ):
            return

        if row < 0 or row >= len(
            self.api_log_json_data
        ):
            return

        log_data = self.api_log_json_data[
            row
        ]

        request_data = (
            log_data
            .get("request", {})
        )

        # แสดงเฉพาะ Parameter ที่ PHP รับด้วย input->post()
        # ไม่สร้าง request.data และไม่ใส่ wrapper เพิ่ม
        post_json = {
            "code": request_data.get(
                "code",
                ""
            ),
            "round": request_data.get(
                "round",
                ""
            ),
            "room": request_data.get(
                "room",
                ""
            ),
            "type": request_data.get(
                "type",
                "rfid"
            ),
            "username": request_data.get(
                "username",
                ""
            )
        }

        response_data = (
            log_data.get(
                "response"
            )
        )

        dialog = QDialog(
            self
        )

        dialog.setWindowTitle(
            "API Log JSON"
        )

        dialog.resize(
            950,
            700
        )
        dialog.setMinimumSize(650, 450)

        layout = QVBoxLayout(
            dialog
        )

        label = QLabel(
            f"API Log รายการที่ {row + 1} — POST Parameters"
        )

        label.setStyleSheet(
            """
            font-weight: bold;
            font-size: 14px;
            """
        )

        layout.addWidget(
            label
        )

        text = QPlainTextEdit()

        text.setReadOnly(
            True
        )

        text.setLineWrapMode(
            QPlainTextEdit.LineWrapMode.NoWrap
        )

        # แสดง Parameter JSON ตรง ๆ
        # และ Response แยกต่างหาก
        display_data = {
            "code": post_json["code"],
            "round": post_json["round"],
            "room": post_json["room"],
            "type": post_json["type"],
            "username": post_json["username"]
        }

        text.setPlainText(
            json.dumps(
                display_data,
                ensure_ascii=False,
                indent=2
            )
        )

        layout.addWidget(
            text
        )

        response_label = QLabel(
            "Response"
        )

        response_label.setStyleSheet(
            """
            font-weight: bold;
            margin-top: 8px;
            """
        )

        layout.addWidget(
            response_label
        )

        response_text = QPlainTextEdit()

        response_text.setReadOnly(
            True
        )

        response_text.setLineWrapMode(
            QPlainTextEdit.LineWrapMode.NoWrap
        )

        response_text.setPlainText(
            json.dumps(
                response_data,
                ensure_ascii=False,
                indent=2
            )
            if isinstance(
                response_data,
                (dict, list)
            )
            else str(
                response_data or ""
            )
        )

        layout.addWidget(
            response_text
        )

        close_button = QPushButton(
            "ปิด"
        )

        close_button.clicked.connect(
            dialog.accept
        )

        layout.addWidget(
            close_button
        )

        # ไม่ใช้ exec() เพราะต้องการให้ Popup ทำงานอิสระจากหน้าหลัก
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()



    def show_api_json(self):

        dialog = QDialog(
            self
        )

        dialog.setWindowTitle(
            "API JSON - Request / Response"
        )

        dialog.resize(
            900,
            650
        )
        dialog.setMinimumSize(650, 450)

        layout = QVBoxLayout(
            dialog
        )

        text = QPlainTextEdit()
        text.setReadOnly(
            True
        )

        text.setLineWrapMode(
            QPlainTextEdit.LineWrapMode.NoWrap
        )

        data = {
            "request": self.api_last_json.get(
                "request",
                {}
            ),
            "response": self.api_last_json.get(
                "response"
            )
        }

        text.setPlainText(
            json.dumps(
                data,
                ensure_ascii=False,
                indent=2
            )
        )

        layout.addWidget(
            text
        )

        close_button = QPushButton(
            "ปิด"
        )

        close_button.clicked.connect(
            dialog.accept
        )

        layout.addWidget(
            close_button
        )

        dialog.exec()


    # ========================================================
    # API LOG
    # ========================================================

    def api_add_log(
        self,
        timestamp,
        round_name,
        std_id,
        epc,
        result
    ):

        if not hasattr(
            self,
            "api_log_json_data"
        ):
            self.api_log_json_data = []


        # ----------------------------------------------------
        # สร้าง Snapshot ของ JSON รายการนี้
        # ----------------------------------------------------

        request_snapshot = json.loads(
            json.dumps(
                self.api_last_json.get(
                    "request",
                    {}
                ),
                ensure_ascii=False
            )
        )

        response_snapshot = json.loads(
            json.dumps(
                self.api_last_json.get(
                    "response"
                ),
                ensure_ascii=False
            )
        )


        snapshot = {
            "request": request_snapshot,
            "response": response_snapshot
        }


        # ----------------------------------------------------
        # หา position ตามวันที่/เวลาที่ RFID ถูกอ่าน
        # เรียงใหม่ -> เก่า
        # ----------------------------------------------------

        def parse_timestamp(value):

            value = str(
                value or ""
            ).strip()

            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%H:%M:%S"
            ]

            for fmt in formats:

                try:

                    dt = datetime.strptime(
                        value,
                        fmt
                    )

                    # กรณีมีเฉพาะเวลา ให้ใช้วันที่ปัจจุบัน
                    if fmt == "%H:%M:%S":

                        dt = datetime.combine(
                            datetime.now().date(),
                            dt.time()
                        )

                    return dt

                except ValueError:
                    continue

            return datetime.min


        new_dt = parse_timestamp(
            timestamp
        )


        insert_row = (
            self.api_log.rowCount()
        )

        for row in range(
            self.api_log.rowCount()
        ):

            old_item = (
                self.api_log.item(
                    row,
                    0
                )
            )

            old_timestamp = (
                old_item.text()
                if old_item is not None
                else ""
            )

            old_dt = parse_timestamp(
                old_timestamp
            )

            if new_dt > old_dt:

                insert_row = row
                break


        # ----------------------------------------------------
        # แทรกแถวใหม่ตามวันที่/เวลาจริง
        # ----------------------------------------------------

        self.api_log.insertRow(
            insert_row
        )

        self.api_log_json_data.insert(
            insert_row,
            snapshot
        )


        values = [
            timestamp,
            round_name,
            std_id,
            epc,
            result
        ]


        for col, value in enumerate(
            values
        ):

            self.api_log.setItem(
                insert_row,
                col,
                QTableWidgetItem(
                    str(value)
                )
            )


        # ----------------------------------------------------
        # เก็บเฉพาะ Log ล่าสุด 300 รายการ
        # เพราะเรียงใหม่ -> เก่า จึงลบด้านล่าง
        # ----------------------------------------------------

        while self.api_log.rowCount() > 300:

            last_row = (
                self.api_log.rowCount()
                - 1
            )

            self.api_log.removeRow(
                last_row
            )

            if (
                self.api_log_json_data
                and last_row <
                len(
                    self.api_log_json_data
                )
            ):

                self.api_log_json_data.pop(
                    last_row
                )


        # ให้รายการล่าสุดอยู่บนสุด
        self.api_log.scrollToTop()

        self.api_log.selectRow(
            0
        )



    # ========================================================
    # RFID PAGE
    # ========================================================

    def create_rfid_page(self):
        """
        RFID Check-in แบบ Responsive
        - หน้าจอเล็กยังอ่านข้อมูลได้
        - มี Scroll แนวนอน/แนวตั้งเมื่อพื้นที่ไม่พอ
        - ไม่บีบตารางจนคอลัมน์อ่านยาก
        - ปุ่ม Exit หลักอยู่ด้านนอก Query Tag
        """

        outer_layout = QVBoxLayout(self.rfid_tab)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # =====================================================
        # Scroll ทั้งหน้า RFID
        # =====================================================
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        scroll_area.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )

        content = QWidget()

        # ความกว้างขั้นต่ำ เพื่อรักษาขนาดข้อมูล/ตาราง
        # ถ้าหน้าจอเล็กกว่านี้ จะใช้ Horizontal Scroll
        content.setMinimumWidth(980)

        main_layout = QVBoxLayout(content)
        main_layout.setContentsMargins(10, 8, 10, 10)
        main_layout.setSpacing(7)

        scroll_area.setWidget(content)
        outer_layout.addWidget(scroll_area)

        # =====================================================
        # Connection
        # =====================================================
        connection_box = QGroupBox("Connection")
        connection_layout = QGridLayout(connection_box)
        connection_layout.setContentsMargins(10, 8, 10, 8)
        connection_layout.setHorizontalSpacing(8)
        connection_layout.setVerticalSpacing(6)

        connection_layout.addWidget(QLabel("IP Address:"), 0, 0)

        self.ip_edit = QLineEdit(DEFAULT_IP)
        self.ip_edit.setFixedWidth(180)
        connection_layout.addWidget(self.ip_edit, 0, 1)

        connection_layout.addWidget(QLabel("Port:"), 0, 2)

        self.port_edit = QLineEdit(str(DEFAULT_PORT))
        self.port_edit.setFixedWidth(80)
        connection_layout.addWidget(self.port_edit, 0, 3)

        self.connect_button = QPushButton("Connect")
        self.connect_button.setMinimumWidth(100)
        self.connect_button.setStyleSheet("""
            QPushButton {
                background-color: #dcfce7;
                color: #166534;
                font-weight: bold;
                border: 1px solid #86efac;
                border-radius: 4px;
                padding: 5px 12px;
            }
            QPushButton:hover {
                background-color: #bbf7d0;
            }
            QPushButton:pressed {
                background-color: #86efac;
            }
        """)
        self.connect_button.clicked.connect(self.connect_reader)
        connection_layout.addWidget(self.connect_button, 0, 4)

        self.close_button = QPushButton("Close")
        self.close_button.setMinimumWidth(100)
        self.close_button.setEnabled(False)
        self.close_button.clicked.connect(self.close_reader)
        connection_layout.addWidget(self.close_button, 0, 5)

        connection_layout.addWidget(QLabel("Status:"), 0, 6)

        self.status_label = QLabel("Disconnected")
        self.status_label.setMinimumWidth(180)
        self.status_label.setStyleSheet("font-weight: bold;")
        connection_layout.addWidget(self.status_label, 0, 7)

        connection_layout.setColumnStretch(7, 1)

        main_layout.addWidget(connection_box)

        # =====================================================
        # Search EPC
        # =====================================================
        search_box = QGroupBox("Search EPC")
        search_layout = QHBoxLayout(search_box)
        search_layout.setContentsMargins(10, 7, 10, 7)
        search_layout.setSpacing(8)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(
            "กรอก EPC ที่ต้องการค้นหา..."
        )
        self.search_edit.returnPressed.connect(self.search_epc)
        search_layout.addWidget(self.search_edit, 1)

        self.search_button = QPushButton("ค้นหา")
        self.search_button.setFixedWidth(100)
        self.search_button.clicked.connect(self.search_epc)
        search_layout.addWidget(self.search_button)

        self.show_all_button = QPushButton("แสดงทั้งหมด")
        self.show_all_button.setFixedWidth(110)
        self.show_all_button.clicked.connect(self.show_all_tags)
        search_layout.addWidget(self.show_all_button)

        main_layout.addWidget(search_box)

        # =====================================================
        # LIVE MONITOR - คนล่าสุด
        # =====================================================
        latest_box = QGroupBox("คนล่าสุด")
        latest_box.setMinimumHeight(120)
        latest_box.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #b9d7ef;
                border-radius: 10px;
                margin-top: 8px;
                padding-top: 10px;
                background: #f8fbff;
            }
            QLabel {
                border: none;
                background: transparent;
            }
        """)

        latest_layout = QVBoxLayout(latest_box)
        latest_layout.setContentsMargins(12, 8, 12, 10)
        latest_layout.setSpacing(4)

        self.latest_status_label = QLabel("รอการอ่าน RFID...")
        self.latest_status_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self.latest_status_label.setStyleSheet("""
            font-size: 20px;
            font-weight: bold;
            color: #17324d;
        """)

        self.latest_detail_label = QLabel(
            "เมื่อมีการอ่าน RFID รายการล่าสุดจะแสดงที่นี่"
        )
        self.latest_detail_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self.latest_detail_label.setWordWrap(True)
        self.latest_detail_label.setStyleSheet("""
            font-size: 11pt;
            color: #475569;
        """)

        latest_layout.addWidget(self.latest_status_label)
        latest_layout.addWidget(self.latest_detail_label)

        main_layout.addWidget(latest_box)

        # =====================================================
        # LIVE SUMMARY BAR
        # =====================================================
        live_bar = QHBoxLayout()
        live_bar.setContentsMargins(4, 2, 4, 2)

        self.live_count_label = QLabel("อ่านแล้ว 0 รายการ")
        self.live_count_label.setStyleSheet(
            "font-weight: bold; font-size: 11pt;"
        )

        self.live_mode_label = QLabel("● LIVE")
        self.live_mode_label.setStyleSheet("""
            QLabel {
                color: #15803d;
                font-weight: bold;
                padding: 3px 10px;
                border: 1px solid #86efac;
                border-radius: 12px;
                background: #f0fdf4;
            }
        """)

        live_bar.addWidget(self.live_count_label)
        live_bar.addStretch()
        live_bar.addWidget(self.live_mode_label)

        main_layout.addLayout(live_bar)

        # =====================================================
        # Content
        # =====================================================
        content_layout = QHBoxLayout()
        content_layout.setSpacing(8)

        # -----------------------------------------------------
        # List EPC
        # -----------------------------------------------------
        list_box = QGroupBox("List EPC of Tags")
        list_layout = QVBoxLayout(list_box)
        list_layout.setContentsMargins(6, 6, 6, 6)

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "No.",
            "ID",
            "std_id",
            "seq",
            "fullname",
            "Round",
            "EPC Length",
            "Times"
        ])

        # กำหนดความกว้างแบบอ่านง่าย
        widths = [
            55,    # No.
            230,   # ID
            120,   # std_id
            70,    # seq
            190,   # fullname
            70,    # Round
            90,    # EPC Length
            70     # Times
        ]

        for i, width in enumerate(widths):
            self.table.setColumnWidth(i, width)

        self.table.setMinimumWidth(sum(widths) + 25)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.table.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.table.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )

        # ให้แถวอ่านง่ายขึ้นบนจอเล็ก
        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.setStyleSheet("""
            QTableWidget {
                font-size: 10pt;
                gridline-color: #d1d5db;
            }
            QHeaderView::section {
                font-weight: bold;
                padding: 5px;
            }
        """)

        list_layout.addWidget(self.table)
        content_layout.addWidget(list_box, 1)

        # -----------------------------------------------------
        # Query Tag
        # -----------------------------------------------------
        query_box = QGroupBox("Query Tag")
        query_box.setFixedWidth(165)

        query_layout = QVBoxLayout(query_box)
        query_layout.setContentsMargins(8, 8, 8, 8)
        query_layout.setSpacing(7)

        query_layout.addWidget(QLabel("Read Interval:"))

        self.interval_combo = QComboBox()
        self.interval_combo.addItems([
            "50ms",
            "100ms",
            "200ms",
            "300ms",
            "500ms",
            "1000ms"
        ])
        self.interval_combo.setCurrentText("50ms")
        query_layout.addWidget(self.interval_combo)

        self.query_button = QPushButton("Query Tag")
        self.query_button.setMinimumHeight(32)
        self.query_button.setStyleSheet("""
            QPushButton {
                background-color: #dbeafe;
                color: #1d4ed8;
                font-weight: bold;
                border: 1px solid #93c5fd;
                border-radius: 4px;
                padding: 5px 12px;
            }
            QPushButton:hover {
                background-color: #bfdbfe;
            }
            QPushButton:pressed {
                background-color: #93c5fd;
            }
            QPushButton:disabled {
                background-color: #dbeafe;
                color: #60a5fa;
                border: 1px solid #bfdbfe;
            }
        """)
        self.query_button.setEnabled(False)
        self.query_button.clicked.connect(self.start_query)
        query_layout.addWidget(self.query_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.setMinimumHeight(32)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_query)
        query_layout.addWidget(self.stop_button)

        self.clear_button = QPushButton("Clear")
        self.clear_button.setMinimumHeight(32)
        self.clear_button.clicked.connect(self.clear_tags)
        query_layout.addWidget(self.clear_button)

        # ไม่ใส่ Exit ใน Query Tag
        # Exit หลักอยู่ด้านล่างของหน้าต่าง

        query_layout.addSpacing(5)
        query_layout.addWidget(QLabel("Round"))

        self.round_group = QButtonGroup(self)

        round_grid = QGridLayout()
        round_grid.setHorizontalSpacing(8)
        round_grid.setVerticalSpacing(4)

        for i in range(1, 11):
            radio = QRadioButton(f"R{i}")
            radio.setObjectName(f"round_radio_R{i}")

            self.round_group.addButton(radio, i)

            row = (i - 1) // 2
            col = (i - 1) % 2

            round_grid.addWidget(radio, row, col)

            if i == 1:
                radio.setChecked(True)

        query_layout.addLayout(round_grid)

        self.round_token_label = QLabel("Token: -")
        self.round_token_label.setWordWrap(True)
        self.round_token_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.round_token_label.setStyleSheet("""
            QLabel {
                font-size: 9pt;
                color: #475569;
                padding-top: 4px;
            }
        """)
        query_layout.addWidget(self.round_token_label)

        self.round_group.idClicked.connect(self.round_changed)

        query_layout.addStretch()

        content_layout.addWidget(query_box)

        main_layout.addLayout(content_layout, 1)

        # =====================================================
        # Bottom status
        # =====================================================
        bottom_layout = QHBoxLayout()
        bottom_layout.setContentsMargins(4, 2, 4, 2)
        bottom_layout.setSpacing(12)

        self.tags_label = QLabel("Tags: 0")
        self.tags_label.setStyleSheet(
            "font-weight: bold;"
        )
        bottom_layout.addWidget(self.tags_label)

        bottom_layout.addStretch()

        self.last_label = QLabel("ล่าสุด: -")
        self.last_label.setMinimumWidth(450)
        self.last_label.setStyleSheet(
            "font-weight: bold;"
        )
        self.last_label.setWordWrap(True)
        self.last_label.setToolTip("")

        bottom_layout.addWidget(self.last_label)

        main_layout.addLayout(bottom_layout)

        self.round_changed(1)

    # ========================================================
    # ROUND CHANGED
    # ========================================================

    def round_changed(
        self,
        round_id
    ):

        round_name = (
            f"R{round_id}"
        )


        self.current_round = (
            round_name
        )


        self.round_token = (
            self.get_round_token(
                round_name
            )
        )


        self.round_token_label.setText(
            f"Token: {self.round_token}"
        )


        if self.worker is not None:

            self.worker.round_token = (
                self.round_token
            )


    # ========================================================
    # CONNECT
    # ========================================================

    def connect_reader(self):

        ip = (
            self.ip_edit
            .text()
            .strip()
        )


        try:

            port = int(
                self.port_edit
                .text()
                .strip()
            )

        except Exception:

            QMessageBox.warning(
                self,
                "Error",
                "Port ไม่ถูกต้อง"
            )

            return


        interval = int(
            self.interval_combo
            .currentText()
            .replace(
                "ms",
                ""
            )
        )


        self.worker = RFIDWorker(
            ip,
            port,
            interval
        )


        self.worker.tag_found.connect(
            self.on_tag_found
        )

        self.worker.status_changed.connect(
            self.on_status
        )

        self.worker.raw_data.connect(
            self.on_raw
        )

        self.worker.error_occurred.connect(
            self.on_error
        )

        self.worker.reader_finished.connect(
            self.on_reader_finished
        )


        self.worker.round_token = (
            self.round_token
        )


        self.worker.start()


        self.connect_button.setEnabled(
            False
        )

        self.close_button.setEnabled(
            True
        )

        self.query_button.setEnabled(
            True
        )

        self.ip_edit.setEnabled(
            False
        )

        self.port_edit.setEnabled(
            False
        )


    # ========================================================
    # QUERY
    # ========================================================

    def start_query(self):

        if self.worker is None:
            return

        if not self.worker.isRunning():
            return


        interval = int(
            self.interval_combo
            .currentText()
            .replace(
                "ms",
                ""
            )
        )


        self.worker.interval_ms = (
            interval
        )


        button = (
            self.round_group
            .checkedButton()
        )


        if button is not None:

            round_name = (
                button.text()
            )

            self.current_round = (
                round_name
            )

            self.round_token = (
                self.get_round_token(
                    round_name
                )
            )


        self.worker.round_token = (
            self.round_token
        )


        self.worker.start_scan()


        self.query_button.setEnabled(
            False
        )

        self.stop_button.setEnabled(
            True
        )


    # ========================================================
    # STOP
    # ========================================================

    def stop_query(self):

        if self.worker:

            self.worker.stop_scan()


        self.query_button.setEnabled(
            True
        )

        self.stop_button.setEnabled(
            False
        )


    # ========================================================
    # TAG FOUND
    # ========================================================

    def on_tag_found(
        self,
        epc,
        epc_length,
        rssi,
        antenna
    ):

        # -----------------------------------------------------
        # หา Student จาก RFID
        # -----------------------------------------------------
        normalized_epc = normalize_rfid(epc)

        student = None

        for student_row in self.student_data:
            if normalize_rfid(
                student_row.get("rfid", "")
            ) == normalized_epc:
                student = student_row
                break

        std_id = ""
        seq = ""
        fullname = ""

        if student is not None:
            std_id = str(
                student.get("std_id", "") or ""
            )
            seq = str(
                student.get("seq", "") or ""
            )

            # NULL / None / NaN -> ว่าง
            if seq.strip().lower() in (
                "null", "none", "nan"
            ):
                seq = ""

            fullname = str(
                student.get("fullname", "") or ""
            )

        # -----------------------------------------------------
        # RFID เดิม
        # -----------------------------------------------------
        if epc in self.tags:

            data = self.tags[epc]

            data["times"] += 1
            data["rssi"] = rssi

            if std_id:
                data["std_id"] = std_id

            if seq:
                data["seq"] = seq

            if fullname:
                data["fullname"] = fullname

            # -------------------------------------------------
            # ย้าย RFID ที่เพิ่งอ่านขึ้นแถวบนสุด
            # -------------------------------------------------
            old_row = data["row"]

            if old_row != 0:
                row_items = []

                for col in range(self.table.columnCount()):
                    item = self.table.takeItem(old_row, col)
                    row_items.append(
                        item.text() if item else ""
                    )

                self.table.removeRow(old_row)
                self.table.insertRow(0)

                for col, value in enumerate(row_items):
                    self.table.setItem(
                        0,
                        col,
                        QTableWidgetItem(value)
                    )

                # อัปเดต row ของ RFID ทุกตัว
                for r in range(self.table.rowCount()):
                    epc_item = self.table.item(r, 1)
                    if epc_item:
                        row_epc = epc_item.text()
                        if row_epc in self.tags:
                            self.tags[row_epc]["row"] = r

            row = 0

            # อัปเดตข้อมูลที่อาจเปลี่ยน
            self.table.setItem(
                row, 2,
                QTableWidgetItem(
                    data.get("std_id", "")
                )
            )

            self.table.setItem(
                row, 3,
                QTableWidgetItem(
                    data.get("seq", "")
                )
            )

            self.table.setItem(
                row, 4,
                QTableWidgetItem(
                    data.get("fullname", "")
                )
            )

            self.table.setItem(
                row, 5,
                QTableWidgetItem(
                    data.get(
                        "round",
                        self.current_round
                    )
                )
            )

            self.table.setItem(
                row, 6,
                QTableWidgetItem(
                    f"{data['length']:02X}"
                )
            )

            self.table.setItem(
                row, 7,
                QTableWidgetItem(
                    str(data["times"])
                )
            )

            # คืน row หลังแก้ไข
            data["row"] = 0

        # -----------------------------------------------------
        # RFID ใหม่
        # -----------------------------------------------------
        else:

            # แทรกด้านบนสุด
            self.table.insertRow(0)

            values = [
                "1",
                epc,
                std_id,
                seq,
                fullname,
                self.current_round,
                f"{epc_length:02X}",
                "1"
            ]

            for col, value in enumerate(values):

                item = QTableWidgetItem(value)

                if col == 5:
                    item.setToolTip(
                        self.round_token
                    )

                self.table.setItem(
                    0,
                    col,
                    item
                )

            self.tags[epc] = {
                "times": 1,
                "length": epc_length,
                "round": self.current_round,
                "round_token": self.round_token,
                "rssi": rssi,
                "antenna": antenna,
                "row": 0,
                "std_id": std_id,
                "seq": seq,
                "fullname": fullname
            }

            # อัปเดตเลข No. ใหม่ทั้งหมด
            for r in range(self.table.rowCount()):
                no_item = self.table.item(r, 0)
                if no_item:
                    no_item.setText(str(r + 1))

                epc_item = self.table.item(r, 1)
                if epc_item:
                    row_epc = epc_item.text()
                    if row_epc in self.tags:
                        self.tags[row_epc]["row"] = r

        # -----------------------------------------------------
        # ข้อมูลล่าสุด
        # -----------------------------------------------------
        latest_data = self.tags.get(epc, {})

        latest_std_id = (
            latest_data.get("std_id", "")
            or std_id
        )

        latest_seq = (
            latest_data.get("seq", "")
            or seq
        )

        latest_name = (
            latest_data.get("fullname", "")
            or fullname
        )

        now_text = datetime.now().strftime(
            "%H:%M:%S"
        )

        # -----------------------------------------------------
        # Live Monitor: คนล่าสุด
        # -----------------------------------------------------
        if latest_name:
            if latest_seq and latest_std_id:
                main_text = (
                    f"✓ {latest_seq}  {latest_name} "
                    f"({latest_std_id})"
                )
            elif latest_std_id:
                main_text = (
                    f"✓ {latest_name} "
                    f"({latest_std_id})"
                )
            elif latest_seq:
                main_text = (
                    f"✓ {latest_seq}  {latest_name}"
                )
            else:
                main_text = (
                    f"✓ {latest_name}"
                )

            self.latest_status_label.setText(
                main_text
            )
        else:
            self.latest_status_label.setText(
                "⚠ อ่าน RFID ได้ แต่ไม่พบข้อมูล"
            )

        detail_parts = [
            f"RFID: {epc}",
            f"รอบ: {latest_data.get('round', self.current_round)}",
            f"เวลา: {now_text}"
        ]

        self.latest_detail_label.setText(
            "   |   ".join(detail_parts)
        )

        # -----------------------------------------------------
        # Bottom status
        # -----------------------------------------------------
        self.tags_label.setText(
            f"Tags: {len(self.tags)}"
        )

        self.live_count_label.setText(
            f"อ่านแล้ว {len(self.tags):,} รายการ"
        )

        if latest_name:
            latest_text = (
                f"ล่าสุด: "
                f"{latest_seq + ' ' if latest_seq else ''}"
                f"{latest_name}"
                f"{' (' + latest_std_id + ')' if latest_std_id else ''}"
                f" | {epc} | {now_text}"
            )
        else:
            latest_text = (
                f"ล่าสุด: ไม่พบข้อมูลนักศึกษา | "
                f"{epc} | {now_text}"
            )

        self.last_label.setText(latest_text)
        self.last_label.setToolTip(latest_text)

        # -----------------------------------------------------
        # เลื่อนไปด้านบนสุดเสมอ
        # -----------------------------------------------------
        self.table.scrollToTop()

        # -----------------------------------------------------
        # Update dashboard/result after new RFID
        # -----------------------------------------------------
        self.refresh_dashboard()

        if hasattr(self, "result_table"):
            try:
                self.refresh_result()
            except Exception:
                pass


    # ========================================================
    # SEARCH EPC
    # ========================================================

    def search_epc(self):

        keyword = (
            self.search_edit
            .text()
            .strip()
            .upper()
        )


        if not keyword:

            self.show_all_tags()

            return


        for row in range(
            self.table.rowCount()
        ):

            item = self.table.item(
                row,
                1
            )


            if item is None:
                continue


            found = (
                keyword
                in item.text().upper()
            )


            self.table.setRowHidden(
                row,
                not found
            )


    def show_all_tags(self):

        self.search_edit.clear()


        for row in range(
            self.table.rowCount()
        ):

            self.table.setRowHidden(
                row,
                False
            )


    # ========================================================
    # CLEAR
    # ========================================================

    def clear_tags(self):

        self.table.setRowCount(
            0
        )

        self.tags.clear()


        self.tags_label.setText(
            "Tags: 0"
        )

        self.last_label.setText(
            "ล่าสุด: -"
        )

        if hasattr(self, "live_count_label"):
            self.live_count_label.setText(
                "อ่านแล้ว 0 รายการ"
            )

        if hasattr(self, "latest_status_label"):
            self.latest_status_label.setText(
                "รอการอ่าน RFID..."
            )

        if hasattr(self, "latest_detail_label"):
            self.latest_detail_label.setText(
                "เมื่อมีการอ่าน RFID รายการล่าสุดจะแสดงที่นี่"
            )


        self.search_edit.clear()


    # ========================================================
    # DASHBOARD
    # ========================================================

    def create_dashboard(self):
        """
        Dashboard แบบรองรับหน้าจอเล็ก
        - มี Scroll แนวตั้ง/แนวนอน
        - ไม่บีบตัวกรองและ Summary Card
        - ยังคงใช้ logic refresh_dashboard เดิม
        """

        outer_layout = QVBoxLayout(self.dashboard_tab)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # =====================================================
        # Scroll ทั้งหน้า Dashboard
        # =====================================================
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        scroll_area.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )

        content = QWidget()

        # กำหนดขนาดขั้นต่ำเพื่อไม่ให้ UI ถูกบีบเมื่อหน้าจอเล็ก
        content.setMinimumWidth(1050)
        content.setMinimumHeight(720)

        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(10)

        scroll_area.setWidget(content)
        outer_layout.addWidget(scroll_area)

        # =====================================================
        # Title
        # =====================================================
        title = QLabel("RFID Check-in Dashboard")
        title.setStyleSheet("""
            QLabel {
                font-size: 20px;
                font-weight: bold;
                padding: 6px 4px;
            }
        """)
        layout.addWidget(title)

        # =====================================================
        # Filters
        # =====================================================
        box = QGroupBox("ตัวกรองข้อมูล")
        grid = QGridLayout(box)
        grid.setContentsMargins(12, 10, 12, 10)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)

        # กำหนดสัดส่วนคอลัมน์ให้ label / combo อ่านง่าย
        grid.setColumnStretch(0, 0)
        grid.setColumnStretch(1, 2)
        grid.setColumnStretch(2, 0)
        grid.setColumnStretch(3, 2)
        grid.setColumnStretch(4, 0)

        grid.addWidget(QLabel("รอบ:"), 0, 0)

        self.dashboard_round_combo = QComboBox()
        self.dashboard_round_combo.addItem("ทั้งหมด", "")

        for i in range(1, 11):
            self.dashboard_round_combo.addItem(
                f"R{i}",
                f"R{i}"
            )

        self.dashboard_round_combo.setMinimumHeight(36)
        grid.addWidget(
            self.dashboard_round_combo,
            0, 1
        )

        grid.addWidget(QLabel("คณะ:"), 0, 2)

        self.dashboard_faculty_combo = QComboBox()
        self.dashboard_faculty_combo.setMinimumHeight(36)
        grid.addWidget(
            self.dashboard_faculty_combo,
            0, 3
        )

        grid.addWidget(QLabel("สาขาวิชา:"), 1, 0)

        self.dashboard_major_combo = QComboBox()
        self.dashboard_major_combo.setMinimumHeight(36)
        grid.addWidget(
            self.dashboard_major_combo,
            1, 1
        )

        grid.addWidget(QLabel("ชื่อปริญญา:"), 1, 2)

        self.dashboard_educational_combo = QComboBox()
        self.dashboard_educational_combo.setMinimumHeight(36)
        grid.addWidget(
            self.dashboard_educational_combo,
            1, 3
        )

        refresh = QPushButton("รีเฟรช")
        refresh.setMinimumHeight(36)
        refresh.setMinimumWidth(130)
        refresh.setStyleSheet("""
            QPushButton {
                font-weight: bold;
            }
        """)
        refresh.clicked.connect(
            self.refresh_dashboard
        )

        grid.addWidget(
            refresh,
            0, 4, 2, 1
        )

        layout.addWidget(box)

        # =====================================================
        # Total Card
        # =====================================================
        total_card = QWidget()
        total_card.setMinimumHeight(120)

        total_card.setStyleSheet("""
            QWidget {
                border: 1px solid #cfe0ef;
                border-radius: 12px;
                background: #F1F8FE;
            }

            QLabel {
                border: none;
                background: transparent;
                color: #334155;
            }
        """)

        total_layout = QVBoxLayout(total_card)
        total_layout.setContentsMargins(10, 8, 10, 8)

        # ปุ่มเปิดหน้าต่าง Popup สำหรับดูจำนวนแบบละเอียด
        total_top = QHBoxLayout()
        total_top.setContentsMargins(0, 0, 0, 0)

        total_top.addStretch()

        view_summary = QPushButton("ดูจำนวน")
        view_summary.setMinimumSize(120, 34)
        view_summary.setStyleSheet("""
            QPushButton {
                border: 1px solid #9cc7e8;
                border-radius: 7px;
                background: #eaf4ff;
                color: #2563a6;
                font-weight: bold;
                padding: 5px 14px;
            }
            QPushButton:hover {
                background: #dbeeff;
            }
            QPushButton:pressed {
                background: #c9e4fb;
            }
        """)
        view_summary.clicked.connect(
            self.show_dashboard_summary_popup
        )

        total_top.addWidget(view_summary)
        total_layout.addLayout(total_top)

        total_title = QLabel("จำนวนทั้งหมด")
        total_title.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        total_title.setStyleSheet("""
            font-size: 14px;
            font-weight: bold;
        """)

        self.dashboard_total_label = QLabel("0")
        self.dashboard_total_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self.dashboard_total_label.setStyleSheet("""
            font-size: 34px;
            font-weight: bold;
            padding: 4px;
        """)

        total_layout.addWidget(total_title)
        total_layout.addWidget(self.dashboard_total_label)

        layout.addWidget(total_card)

        # =====================================================
        # Summary Cards
        # =====================================================
        summary_box = QGroupBox("สรุปข้อมูล")
        summary_layout = QGridLayout(summary_box)

        summary_layout.setContentsMargins(12, 12, 12, 12)
        summary_layout.setHorizontalSpacing(10)
        summary_layout.setVerticalSpacing(10)

        self.dashboard_round_cards = (
            self.create_dashboard_card_panel(
                "สรุปจำนวนคนแต่ละรอบ"
            )
        )

        self.dashboard_faculty_cards = (
            self.create_dashboard_card_panel(
                "สรุปจำนวนคนตามคณะ"
            )
        )

        self.dashboard_major_cards = (
            self.create_dashboard_card_panel(
                "สรุปจำนวนคนตามสาขาวิชา"
            )
        )

        self.dashboard_educational_cards = (
            self.create_dashboard_card_panel(
                "สรุปจำนวนคนตามชื่อปริญญา"
            )
        )

        # ให้แต่ละกลุ่มมีพื้นที่เท่ากัน
        for i in range(2):
            summary_layout.setColumnStretch(i, 1)
            summary_layout.setRowStretch(i, 1)

        summary_layout.addWidget(
            self.dashboard_round_cards,
            0, 0
        )

        summary_layout.addWidget(
            self.dashboard_faculty_cards,
            0, 1
        )

        summary_layout.addWidget(
            self.dashboard_major_cards,
            1, 0
        )

        summary_layout.addWidget(
            self.dashboard_educational_cards,
            1, 1
        )

        layout.addWidget(
            summary_box,
            1
        )

        # =====================================================
        # Signals
        # =====================================================
        self.dashboard_round_combo.currentIndexChanged.connect(
            self.refresh_dashboard
        )

        self.dashboard_faculty_combo.currentIndexChanged.connect(
            self.refresh_dashboard
        )

        self.dashboard_major_combo.currentIndexChanged.connect(
            self.refresh_dashboard
        )

        self.dashboard_educational_combo.currentIndexChanged.connect(
            self.refresh_dashboard
        )

        self.populate_dashboard_filters()
        self.refresh_dashboard()



    def create_dashboard_card_panel(
        self,
        title
    ):

        panel = QGroupBox(title)

        panel.setStyleSheet(
            """
            QGroupBox {
                font-weight: bold;
                color: #374151;
                border: 1px solid #dbe3ea;
                border-radius: 12px;
                margin-top: 10px;
                padding-top: 12px;
                background: #fafcfd;
            }
            """
        )

        grid = QGridLayout(panel)

        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)

        return panel


    def clear_dashboard_cards(
        self,
        panel
    ):

        grid = panel.layout()

        while grid.count():

            item = grid.takeAt(0)

            widget = item.widget()

            if widget is not None:
                widget.deleteLater()


    def add_dashboard_card(
        self,
        panel,
        title,
        count,
        row,
        column=None
    ):

        # รองรับทั้งการส่ง row, column แยกกัน
        # และการส่งเป็น tuple (row, column)
        if column is None and isinstance(row, tuple):
            row, column = row

        if column is None:
            column = 0

        card = QWidget()

        card.setMinimumHeight(82)

        # สีพาสเทลอ่อน แยกตามกลุ่มของ Dashboard
        if "R" in str(title) and str(title).startswith("R"):
            bg = "#EAF4FF"
            border = "#C9DFF5"
        elif panel.title() == "สรุปจำนวนคนตามคณะ":
            bg = "#EEF9F0"
            border = "#CDE8D2"
        elif panel.title() == "สรุปจำนวนคนตามสาขาวิชา":
            bg = "#FFF7E8"
            border = "#F1DFC0"
        else:
            bg = "#F7EEFF"
            border = "#DFD0F0"

        card.setStyleSheet(
            f"""
            QWidget {{
                border: 1px solid {border};
                border-radius: 10px;
                background: {bg};
            }}

            QLabel {{
                border: none;
                background: transparent;
                color: #374151;
            }}
            """
        )

        layout = QVBoxLayout(card)

        layout.setContentsMargins(
            6,
            6,
            6,
            6
        )

        title_label = QLabel(
            str(title)
        )

        title_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        title_label.setWordWrap(True)

        title_label.setStyleSheet(
            """
            font-size: 11px;
            font-weight: bold;
            color: #4b5563;
            """
        )

        count_label = QLabel(
            f"{count:,}"
        )

        count_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        count_label.setStyleSheet(
            """
            font-size: 25px;
            font-weight: bold;
            color: #1f2937;
            """
        )

        layout.addWidget(title_label)
        layout.addWidget(count_label)

        panel.layout().addWidget(
            card,
            row,
            column
        )


    def populate_dashboard_filters(self):

        combos = [
            (
                self.dashboard_faculty_combo,
                "faculty"
            ),
            (
                self.dashboard_major_combo,
                "major"
            ),
            (
                self.dashboard_educational_combo,
                "educational"
            )
        ]

        for combo, key in combos:

            values = sorted(
                {
                    row.get(key, "")
                    for row in self.student_data
                    if row.get(key, "")
                }
            )

            combo.blockSignals(True)
            combo.clear()
            combo.addItem("ทั้งหมด", "")

            for value in values:
                combo.addItem(
                    value,
                    value
                )

            combo.blockSignals(False)


    def refresh_dashboard(self):

        records = self.read_rfid_log()

        round_filter = (
            self.dashboard_round_combo
            .currentData()
        )

        faculty_filter = (
            self.dashboard_faculty_combo
            .currentData()
        )

        major_filter = (
            self.dashboard_major_combo
            .currentData()
        )

        educational_filter = (
            self.dashboard_educational_combo
            .currentData()
        )

        student_map = {
            row["rfid"]: row
            for row in self.student_data
            if row["rfid"]
        }

        round_people = {
            f"R{i}": set()
            for i in range(1, 11)
        }

        faculty_people = {}
        major_people = {}
        educational_people = {}

        all_people = set()

        for record in records:

            epc = normalize_rfid(
                record.get("epc", "")
            )

            student = student_map.get(epc)

            if student is None:
                continue

            round_name = (
                record.get("round", "")
                or ""
            ).strip().upper()

            if not round_name:
                continue

            if (
                round_filter
                and round_name != round_filter
            ):
                continue

            if (
                faculty_filter
                and student["faculty"]
                != faculty_filter
            ):
                continue

            if (
                major_filter
                and student["major"]
                != major_filter
            ):
                continue

            if (
                educational_filter
                and student["educational"]
                != educational_filter
            ):
                continue

            person_id = (
                student["std_id"]
                or epc
            )

            unique_key = (
                person_id,
                round_name
            )

            # นับคนเพียงครั้งเดียวในรอบเดียวกัน
            if unique_key in all_people:
                continue

            all_people.add(unique_key)

            round_people.setdefault(
                round_name,
                set()
            ).add(person_id)

            faculty = (
                student["faculty"]
                or "ไม่ระบุ"
            )

            faculty_people.setdefault(
                faculty,
                set()
            ).add(unique_key)

            major = (
                student["major"]
                or "ไม่ระบุ"
            )

            major_people.setdefault(
                major,
                set()
            ).add(unique_key)

            educational = (
                student["educational"]
                or "ไม่ระบุ"
            )

            educational_people.setdefault(
                educational,
                set()
            ).add(unique_key)

        # Total
        self.dashboard_total_label.setText(
            f"{len(all_people):,}"
        )

        # -----------------------------------------------------
        # Round Cards
        # -----------------------------------------------------

        self.clear_dashboard_cards(
            self.dashboard_round_cards
        )

        for index in range(1, 11):

            name = f"R{index}"

            count = len(
                round_people.get(
                    name,
                    set()
                )
            )

            self.add_dashboard_card(
                self.dashboard_round_cards,
                name,
                count,
                (0, index - 1)
            )

        # -----------------------------------------------------
        # Faculty Cards
        # -----------------------------------------------------

        self.clear_dashboard_cards(
            self.dashboard_faculty_cards
        )

        faculty_data = sorted(
            faculty_people.items(),
            key=lambda x: (
                -len(x[1]),
                x[0]
            )
        )

        for index, (name, people) in enumerate(
            faculty_data
        ):

            self.add_dashboard_card(
                self.dashboard_faculty_cards,
                name,
                len(people),
                index // 3,
                index % 3
            )

        # -----------------------------------------------------
        # Major Cards
        # -----------------------------------------------------

        self.clear_dashboard_cards(
            self.dashboard_major_cards
        )

        major_data = sorted(
            major_people.items(),
            key=lambda x: (
                -len(x[1]),
                x[0]
            )
        )

        for index, (name, people) in enumerate(
            major_data
        ):

            self.add_dashboard_card(
                self.dashboard_major_cards,
                name,
                len(people),
                index // 3,
                index % 3
            )

        # -----------------------------------------------------
        # Educational Cards
        # -----------------------------------------------------

        self.clear_dashboard_cards(
            self.dashboard_educational_cards
        )

        educational_data = sorted(
            educational_people.items(),
            key=lambda x: (
                -len(x[1]),
                x[0]
            )
        )

        for index, (name, people) in enumerate(
            educational_data
        ):

            self.add_dashboard_card(
                self.dashboard_educational_cards,
                name,
                len(people),
                index // 3,
                index % 3
            )

        # เก็บข้อมูลล่าสุดไว้สำหรับ Popup
        self.dashboard_summary_data = {
            "round": [
                (f"R{i}", len(round_people.get(f"R{i}", set())))
                for i in range(1, 11)
            ],
            "faculty": [
                (name, len(people))
                for name, people in faculty_data
            ],
            "major": [
                (name, len(people))
                for name, people in major_data
            ],
            "educational": [
                (name, len(people))
                for name, people in educational_data
            ],
            "total": len(all_people),
        }


    def show_dashboard_summary_popup(self):
        """
        เปิดหน้าสรุปจำนวนเป็น Extend Window อิสระ
        สามารถวางบนจอที่ 2 ได้ และใช้งานหน้าหลักพร้อมกัน
        """

        # ถ้าเปิดอยู่แล้ว ให้เอาหน้าต่างเดิมขึ้นมา
        if getattr(self, "_dashboard_summary_window", None) is not None:
            try:
                if self._dashboard_summary_window.isVisible():
                    self._dashboard_summary_window.showNormal()
                    self._dashboard_summary_window.raise_()
                    self._dashboard_summary_window.activateWindow()
                    return
            except RuntimeError:
                self._dashboard_summary_window = None

        window = QWidget(None)
        window.setWindowTitle("ระบบตรวจนับบัณฑิต - สรุปจำนวน")
        window.setWindowFlag(Qt.WindowType.Window, True)
        window.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        window.resize(1200, 800)
        window.setMinimumSize(850, 600)

        self._dashboard_summary_window = window

        # -----------------------------------------------------
        # Main layout
        # -----------------------------------------------------
        outer = QVBoxLayout(window)
        outer.setContentsMargins(16, 12, 16, 12)
        outer.setSpacing(10)

        # -----------------------------------------------------
        # Header
        # -----------------------------------------------------
        header = QHBoxLayout()

        title = QLabel("สรุปจำนวนผู้เข้าร่วม")
        title.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #17324d;
            }
        """)

        header.addWidget(title)
        header.addStretch()

        close_btn = QPushButton("ปิดหน้าสรุป")
        close_btn.setMinimumSize(120, 38)
        close_btn.setStyleSheet("""
            QPushButton {
                border: 1px solid #e5bcbc;
                border-radius: 7px;
                background: #fff1f1;
                color: #c62828;
                font-weight: bold;
                padding: 6px 14px;
            }
            QPushButton:hover {
                background: #ffe2e2;
            }
        """)
        close_btn.clicked.connect(window.close)

        header.addWidget(close_btn)
        outer.addLayout(header)

        # -----------------------------------------------------
        # Current filters
        # -----------------------------------------------------
        filters_text = (
            f"รอบ: {self.dashboard_round_combo.currentText()}    |    "
            f"คณะ: {self.dashboard_faculty_combo.currentText()}    |    "
            f"สาขาวิชา: {self.dashboard_major_combo.currentText()}    |    "
            f"ชื่อปริญญา: {self.dashboard_educational_combo.currentText()}"
        )

        filters_label = QLabel(filters_text)
        filters_label.setWordWrap(True)
        filters_label.setStyleSheet("""
            QLabel {
                border: 1px solid #d7e0e8;
                border-radius: 8px;
                background: #f7fafc;
                color: #475569;
                padding: 9px 12px;
                font-size: 13px;
            }
        """)
        outer.addWidget(filters_label)

        # -----------------------------------------------------
        # Scroll area
        # -----------------------------------------------------
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        content = QWidget()
        content.setMinimumWidth(780)

        grid = QGridLayout(content)
        grid.setContentsMargins(4, 4, 4, 4)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)

        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

        data = getattr(
            self,
            "dashboard_summary_data",
            {
                "round": [],
                "faculty": [],
                "major": [],
                "educational": [],
                "total": 0,
            }
        )

        # -----------------------------------------------------
        # Total
        # -----------------------------------------------------
        total_box = QGroupBox("จำนวนทั้งหมด")
        total_box.setMinimumHeight(125)
        total_box.setStyleSheet("""
            QGroupBox {
                font-size: 14px;
                font-weight: bold;
                border: 1px solid #b9d7ef;
                border-radius: 10px;
                margin-top: 8px;
                padding-top: 12px;
                background: #f1f8fe;
            }
            QLabel {
                border: none;
                background: transparent;
            }
        """)

        total_layout = QVBoxLayout(total_box)

        total_count = QLabel(f"{data['total']:,}")
        total_count.setAlignment(Qt.AlignmentFlag.AlignCenter)
        total_count.setStyleSheet("""
            font-size: 38px;
            font-weight: bold;
            color: #17324d;
        """)

        total_layout.addWidget(total_count)

        grid.addWidget(total_box, 0, 0, 1, 2)

        # -----------------------------------------------------
        # Helper
        # -----------------------------------------------------
        def make_summary_box(title_text, items, bg, border):
            box = QGroupBox(title_text)
            box.setMinimumHeight(260)
            box.setStyleSheet(f"""
                QGroupBox {{
                    font-size: 14px;
                    font-weight: bold;
                    color: #374151;
                    border: 1px solid {border};
                    border-radius: 10px;
                    margin-top: 8px;
                    padding-top: 12px;
                    background: #ffffff;
                }}
            """)

            area = QScrollArea()
            area.setWidgetResizable(True)
            area.setFrameShape(QScrollArea.Shape.NoFrame)

            widget = QWidget()
            widget.setStyleSheet("background: transparent;")

            item_grid = QGridLayout(widget)
            item_grid.setContentsMargins(8, 8, 8, 8)
            item_grid.setHorizontalSpacing(10)
            item_grid.setVerticalSpacing(10)

            if not items:
                empty = QLabel("ไม่มีข้อมูล")
                empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
                empty.setStyleSheet("""
                    font-size: 16px;
                    color: #64748b;
                    padding: 30px;
                """)
                item_grid.addWidget(empty, 0, 0, 1, 2)
            else:
                for idx, (name, count) in enumerate(items):
                    card = QWidget()
                    card.setMinimumHeight(85)
                    card.setStyleSheet(f"""
                        QWidget {{
                            border: 1px solid {border};
                            border-radius: 9px;
                            background: {bg};
                        }}
                        QLabel {{
                            border: none;
                            background: transparent;
                            color: #334155;
                        }}
                    """)

                    card_layout = QVBoxLayout(card)
                    card_layout.setContentsMargins(8, 7, 8, 7)

                    name_label = QLabel(str(name))
                    name_label.setAlignment(
                        Qt.AlignmentFlag.AlignCenter
                    )
                    name_label.setWordWrap(True)
                    name_label.setStyleSheet("""
                        font-size: 12px;
                        font-weight: bold;
                    """)

                    count_label = QLabel(f"{count:,}")
                    count_label.setAlignment(
                        Qt.AlignmentFlag.AlignCenter
                    )
                    count_label.setStyleSheet("""
                        font-size: 23px;
                        font-weight: bold;
                    """)

                    card_layout.addWidget(name_label)
                    card_layout.addWidget(count_label)

                    item_grid.addWidget(
                        card,
                        idx // 2,
                        idx % 2
                    )

            item_grid.setColumnStretch(0, 1)
            item_grid.setColumnStretch(1, 1)

            area.setWidget(widget)

            box_layout = QVBoxLayout(box)
            box_layout.addWidget(area)

            return box

        # -----------------------------------------------------
        # Four summary groups
        # -----------------------------------------------------
        grid.addWidget(
            make_summary_box(
                "จำนวนคนแต่ละรอบ",
                data["round"],
                "#EAF4FF",
                "#C9DFF5"
            ),
            1, 0
        )

        grid.addWidget(
            make_summary_box(
                "จำนวนคนตามคณะ",
                data["faculty"],
                "#EEF9F0",
                "#CDE8D2"
            ),
            1, 1
        )

        grid.addWidget(
            make_summary_box(
                "จำนวนคนตามสาขาวิชา",
                data["major"],
                "#FFF7E8",
                "#F1DFC0"
            ),
            2, 0
        )

        grid.addWidget(
            make_summary_box(
                "จำนวนคนตามชื่อปริญญา",
                data["educational"],
                "#F7EEFF",
                "#DFD0F0"
            ),
            2, 1
        )

        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setRowStretch(1, 1)
        grid.setRowStretch(2, 1)

        # -----------------------------------------------------
        # เปิดเป็นหน้าต่างอิสระ
        # -----------------------------------------------------
        window.show()
        window.raise_()
        window.activateWindow()


    # ========================================================
    # RESULT PAGE
    # ========================================================

    def create_result_page(self):
        """
        Result Page แบบอ่านง่าย
        - รองรับหน้าจอเล็กด้วย Scroll แนวนอน/แนวตั้ง
        - ตารางไม่ถูกบีบจนข้อความอ่านยาก
        - ปุ่มค้นหาและ Print มีขนาดเหมาะสม
        - ไม่เปลี่ยน logic การค้นหา/แบ่งหน้า/คลิกแถว
        """

        outer_layout = QVBoxLayout(self.result_tab)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # =====================================================
        # Scroll ทั้งหน้า Result
        # =====================================================
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        scroll_area.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )

        content = QWidget()

        # รักษาความกว้างขั้นต่ำของตาราง
        # จอเล็กจะเลื่อนซ้าย/ขวาแทนการบีบคอลัมน์
        content.setMinimumWidth(1100)

        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        scroll_area.setWidget(content)
        outer_layout.addWidget(scroll_area)

        # =====================================================
        # Title
        # =====================================================
        title = QLabel("Result - รายงานการเช็กชื่อ")
        title.setStyleSheet("""
            QLabel {
                font-size: 20px;
                font-weight: bold;
                padding: 6px 4px;
            }
        """)
        layout.addWidget(title)

        # =====================================================
        # Search
        # =====================================================
        search_box = QGroupBox("ค้นหา")
        search_layout = QHBoxLayout(search_box)
        search_layout.setContentsMargins(10, 8, 10, 8)
        search_layout.setSpacing(8)

        search_layout.addWidget(QLabel("ค้นหา:"))

        self.result_search_edit = QLineEdit()
        self.result_search_edit.setPlaceholderText(
            "รหัสนักศึกษา / ชื่อ / นามสกุล / RFID"
        )
        self.result_search_edit.setMinimumHeight(32)
        self.result_search_edit.returnPressed.connect(
            self.result_search
        )
        search_layout.addWidget(self.result_search_edit, 1)

        self.result_search_button = QPushButton("ค้นหา")
        self.result_search_button.setFixedSize(105, 32)
        self.result_search_button.clicked.connect(
            self.result_search
        )
        search_layout.addWidget(self.result_search_button)

        self.result_clear_button = QPushButton("แสดงทั้งหมด")
        self.result_clear_button.setFixedSize(115, 32)
        self.result_clear_button.clicked.connect(
            self.result_clear_search
        )
        search_layout.addWidget(self.result_clear_button)

        self.result_print_button = QPushButton("Print")
        self.result_print_button.setFixedSize(105, 32)
        self.result_print_button.clicked.connect(
            self.print_result
        )
        search_layout.addWidget(self.result_print_button)

        layout.addWidget(search_box)

        # =====================================================
        # Result Table
        # =====================================================
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(8)

        self.result_table.setHorizontalHeaderLabels([
            "No.",
            "std_id",
            "ชื่อ-นามสกุล",
            "RFID",
            "คณะ",
            "สาขาวิชา",
            "ชื่อปริญญา",
            "รอบ"
        ])

        # กำหนดความกว้างให้เหมาะกับข้อมูลจริง
        widths = [
            55,    # No.
            120,   # std_id
            190,   # ชื่อ-นามสกุล
            230,   # RFID
            180,   # คณะ
            180,   # สาขาวิชา
            190,   # ชื่อปริญญา
            70     # รอบ
        ]

        for i, width in enumerate(widths):
            self.result_table.setColumnWidth(i, width)

        self.result_table.setMinimumWidth(sum(widths) + 25)

        self.result_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.result_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.result_table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.result_table.setAlternatingRowColors(True)

        self.result_table.verticalHeader().setVisible(False)
        self.result_table.verticalHeader().setDefaultSectionSize(30)

        self.result_table.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.result_table.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )

        self.result_table.setStyleSheet("""
            QTableWidget {
                font-size: 10pt;
                gridline-color: #d1d5db;
                selection-background-color: #dbeafe;
                selection-color: #111827;
            }

            QHeaderView::section {
                font-weight: bold;
                font-size: 10pt;
                padding: 6px 5px;
                background-color: #f1f5f9;
                border: 1px solid #cbd5e1;
            }
        """)

        # คลิกแถวเพื่อดู Log ของ RFID คนนั้น
        self.result_table.cellClicked.connect(
            self.result_row_clicked
        )

        layout.addWidget(self.result_table, 1)

        # =====================================================
        # Pagination
        # =====================================================
        page_layout = QHBoxLayout()
        page_layout.setContentsMargins(2, 2, 2, 2)
        page_layout.setSpacing(8)

        self.result_previous_button = QPushButton("‹ ก่อนหน้า")
        self.result_previous_button.setFixedSize(110, 34)
        self.result_previous_button.clicked.connect(
            self.result_previous_page
        )
        page_layout.addWidget(self.result_previous_button)

        self.result_page_label = QLabel("หน้า 1 / 1")
        self.result_page_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self.result_page_label.setStyleSheet(
            "font-weight: bold; font-size: 10pt;"
        )
        page_layout.addWidget(self.result_page_label, 1)

        self.result_next_button = QPushButton("ถัดไป ›")
        self.result_next_button.setFixedSize(110, 34)
        self.result_next_button.clicked.connect(
            self.result_next_page
        )
        page_layout.addWidget(self.result_next_button)

        self.result_info_label = QLabel("0 รายการ")
        self.result_info_label.setMinimumWidth(100)
        self.result_info_label.setAlignment(
            Qt.AlignmentFlag.AlignRight |
            Qt.AlignmentFlag.AlignVCenter
        )
        page_layout.addWidget(self.result_info_label)

        layout.addLayout(page_layout)

        self.result_all_rows = []
        self.result_current_page = 1
        self.result_page_size = 15

        self.result_search()

    # ========================================================
    # RESULT DATA
    # ========================================================

    def load_result_data(self):

        # RFID จาก student.csv
        student_by_rfid = {}


        for student in self.student_data:

            rfid = normalize_rfid(
                student.get(
                    "rfid",
                    ""
                )
            )


            if rfid:

                student_by_rfid[
                    rfid
                ] = student


        # RFID จาก rfid_tags.txt
        records = (
            self.read_rfid_log()
        )


        result = {}


        for record in records:

            reader_rfid = normalize_rfid(
                record.get(
                    "epc",
                    ""
                )
            )


            if not reader_rfid:
                continue


            # =================================================
            # RFID MATCH
            # reader RFID == student RFID
            # =================================================

            student = (
                student_by_rfid.get(
                    reader_rfid
                )
            )


            # ไม่ตรง = ไม่แสดงใน Result
            if student is None:
                continue


            round_name = (
                record.get(
                    "round",
                    ""
                )
                or ""
            ).strip().upper()


            # คนเดียวกัน + รอบเดียวกัน = 1 record
            key = (
                reader_rfid,
                round_name
            )


            if key not in result:

                result[key] = {
                    "std_id": student.get(
                        "std_id",
                        ""
                    ),

                    "fullname": student.get(
                        "fullname",
                        ""
                    ),

                    "rfid": reader_rfid,

                    "faculty": student.get(
                        "faculty",
                        ""
                    ),

                    "major": student.get(
                        "major",
                        ""
                    ),

                    "educational": student.get(
                        "educational",
                        ""
                    ),

                    "round": round_name
                }


        rows = list(
            result.values()
        )


        rows.sort(
            key=lambda x: (
                x["std_id"],
                x["fullname"],
                x["round"]
            )
        )


        print(
            "Result matched:",
            len(rows)
        )


        return rows


    # ========================================================
    # RESULT RFID LOG POPUP
    # ========================================================

    def result_row_clicked(
        self,
        row,
        column
    ):
        """เมื่อคลิกแถว Result ให้เปิด Popup แสดงประวัติ RFID"""

        item = self.result_table.item(
            row,
            3
        )

        if item is None:
            return

        rfid = normalize_rfid(
            item.text()
        )

        if not rfid:
            return

        student = None

        for data in self.student_data:
            if normalize_rfid(
                data.get("rfid", "")
            ) == rfid:
                student = data
                break

        self.show_rfid_log_popup(
            rfid,
            student
        )


    def show_rfid_log_popup(
        self,
        rfid,
        student=None
    ):
        """แสดง Log ของ RFID ที่เลือก โดยสรุปแยกตาม R1-R10"""

        records = [
            record
            for record in self.read_rfid_log()
            if normalize_rfid(
                record.get("epc", "")
            ) == rfid
        ]

        dialog = QDialog(
            self
        )

        dialog.setWindowTitle(
            f"RFID Log - {rfid}"
        )

        dialog.resize(
            720,
            520
        )


        layout = QVBoxLayout(
            dialog
        )


        # -----------------------------------------------------
        # Student information
        # -----------------------------------------------------

        if student is not None:

            info = QLabel(
                f"รหัสนักศึกษา: {student.get('std_id', '')}    "
                f"ชื่อ: {student.get('fullname', '')}"
            )

        else:

            info = QLabel(
                "ไม่พบข้อมูลนักศึกษาใน student.csv"
            )


        info.setStyleSheet(
            """
            font-size: 14px;
            font-weight: bold;
            padding: 4px;
            """
        )


        layout.addWidget(
            info
        )


        layout.addWidget(
            QLabel(
                f"RFID: {rfid}"
            )
        )


        layout.addWidget(
            QLabel(
                f"บันทึกทั้งหมด: {len(records):,} ครั้ง"
            )
        )


        # -----------------------------------------------------
        # Summary by round
        # -----------------------------------------------------

        summary_title = QLabel(
            "สรุปการบันทึกแต่ละรอบ"
        )

        summary_title.setStyleSheet(
            """
            font-size: 14px;
            font-weight: bold;
            margin-top: 6px;
            """
        )

        layout.addWidget(
            summary_title
        )


        summary_table = QTableWidget()

        summary_table.setColumnCount(
            3
        )

        summary_table.setHorizontalHeaderLabels(
            [
                "รอบ",
                "จำนวนครั้ง",
                "เวลา"
            ]
        )

        summary_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        summary_table.setAlternatingRowColors(
            True
        )

        summary_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )


        # Group log by round
        grouped = {
            f"R{i}": []
            for i in range(1, 11)
        }


        unknown = []


        for record in records:

            round_name = (
                record.get(
                    "round",
                    ""
                )
                or ""
            ).strip().upper()

            timestamp = (
                record.get(
                    "timestamp",
                    ""
                )
                or ""
            ).strip()


            if round_name in grouped:

                grouped[
                    round_name
                ].append(
                    timestamp
                )

            else:

                unknown.append(
                    timestamp
                )


        # แสดงเฉพาะรอบที่มี Log
        for round_name in [
            f"R{i}"
            for i in range(1, 11)
        ]:

            times = grouped[
                round_name
            ]

            if not times:
                continue


            row_index = (
                summary_table.rowCount()
            )

            summary_table.insertRow(
                row_index
            )


            summary_table.setItem(
                row_index,
                0,
                QTableWidgetItem(
                    round_name
                )
            )


            summary_table.setItem(
                row_index,
                1,
                QTableWidgetItem(
                    f"{len(times):,}"
                )
            )


            # แสดงเวลาทั้งหมดของรอบนั้น
            time_text = "\n".join(
                times
            )


            time_item = QTableWidgetItem(
                time_text
            )


            time_item.setToolTip(
                time_text
            )


            summary_table.setItem(
                row_index,
                2,
                time_item
            )


        # กรณี Log เก่าที่ไม่สามารถระบุรอบได้
        if unknown:

            row_index = (
                summary_table.rowCount()
            )

            summary_table.insertRow(
                row_index
            )


            summary_table.setItem(
                row_index,
                0,
                QTableWidgetItem(
                    "ไม่ทราบรอบ"
                )
            )


            summary_table.setItem(
                row_index,
                1,
                QTableWidgetItem(
                    f"{len(unknown):,}"
                )
            )


            unknown_text = "\n".join(
                unknown
            )


            summary_table.setItem(
                row_index,
                2,
                QTableWidgetItem(
                    unknown_text
                )
            )


        summary_table.setColumnWidth(
            0,
            100
        )

        summary_table.setColumnWidth(
            1,
            100
        )

        summary_table.horizontalHeader().setStretchLastSection(
            True
        )


        layout.addWidget(
            summary_table,
            1
        )


        # -----------------------------------------------------
        # Detailed log
        # -----------------------------------------------------

        detail_title = QLabel(
            "รายละเอียด Log"
        )

        detail_title.setStyleSheet(
            """
            font-size: 14px;
            font-weight: bold;
            margin-top: 6px;
            """
        )

        layout.addWidget(
            detail_title
        )


        detail_table = QTableWidget()

        detail_table.setColumnCount(
            3
        )

        detail_table.setHorizontalHeaderLabels(
            [
                "ครั้งที่",
                "รอบ",
                "วันเวลา"
            ]
        )

        detail_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        detail_table.setAlternatingRowColors(
            True
        )


        # แสดง Log ล่าสุดก่อน
        detail_records = list(
            reversed(records)
        )


        for index, record in enumerate(
            detail_records,
            start=1
        ):

            row_index = (
                detail_table.rowCount()
            )

            detail_table.insertRow(
                row_index
            )


            detail_table.setItem(
                row_index,
                0,
                QTableWidgetItem(
                    str(index)
                )
            )

            detail_table.setItem(
                row_index,
                1,
                QTableWidgetItem(
                    record.get(
                        "round",
                        ""
                    )
                    or "-"
                )
            )

            detail_table.setItem(
                row_index,
                2,
                QTableWidgetItem(
                    record.get(
                        "timestamp",
                        ""
                    )
                )
            )


        detail_table.setColumnWidth(
            0,
            70
        )

        detail_table.setColumnWidth(
            1,
            90
        )

        detail_table.horizontalHeader().setStretchLastSection(
            True
        )


        layout.addWidget(
            detail_table,
            2
        )


        # -----------------------------------------------------
        # Close
        # -----------------------------------------------------

        button_layout = QHBoxLayout()

        button_layout.addStretch()


        close_button = QPushButton(
            "ปิด"
        )

        close_button.clicked.connect(
            dialog.accept
        )


        button_layout.addWidget(
            close_button
        )


        layout.addLayout(
            button_layout
        )


        dialog.exec()


    # ========================================================
    # RESULT SEARCH
    # ========================================================

    def result_search(self):

        if not hasattr(
            self,
            "result_search_edit"
        ):
            return


        keyword = (
            self.result_search_edit
            .text()
            .strip()
            .lower()
        )


        rows = (
            self.load_result_data()
        )


        if keyword:

            filtered = []

            for row in rows:

                searchable = " ".join(
                    [
                        row.get(
                            "std_id",
                            ""
                        ),

                        row.get(
                            "fullname",
                            ""
                        ),

                        row.get(
                            "rfid",
                            ""
                        )
                    ]
                ).lower()


                if keyword in searchable:

                    filtered.append(
                        row
                    )


            self.result_all_rows = (
                filtered
            )

        else:

            self.result_all_rows = rows


        self.result_current_page = 1

        self.result_show_page()


    def result_clear_search(self):

        self.result_search_edit.clear()

        self.result_current_page = 1

        self.result_search()


    # ========================================================
    # RESULT PAGINATION
    # ========================================================

    def result_total_pages(self):

        if not self.result_all_rows:

            return 1


        return (
            len(
                self.result_all_rows
            )
            + self.result_page_size
            - 1
        ) // self.result_page_size


    def result_show_page(self):

        total_pages = (
            self.result_total_pages()
        )


        self.result_current_page = max(
            1,
            min(
                self.result_current_page,
                total_pages
            )
        )


        start = (
            self.result_current_page
            - 1
        ) * self.result_page_size


        page_rows = (
            self.result_all_rows[
                start:
                start + self.result_page_size
            ]
        )


        self.result_table.setRowCount(
            0
        )


        for index, data in enumerate(
            page_rows,
            start=1
        ):

            row = (
                self.result_table.rowCount()
            )


            self.result_table.insertRow(
                row
            )


            values = [
                str(
                    start + index
                ),

                data["std_id"],

                data["fullname"],

                data["rfid"],

                data["faculty"],

                data["major"],

                data["educational"],

                data["round"]
            ]


            for col, value in enumerate(
                values
            ):

                self.result_table.setItem(
                    row,
                    col,
                    QTableWidgetItem(
                        str(value)
                    )
                )


        self.result_page_label.setText(
            f"หน้า {self.result_current_page} / {total_pages}"
        )


        self.result_info_label.setText(
            f"{len(self.result_all_rows):,} รายการ"
        )


        self.result_previous_button.setEnabled(
            self.result_current_page > 1
        )


        self.result_next_button.setEnabled(
            self.result_current_page < total_pages
        )


        self.result_table.resizeColumnsToContents()


    def result_previous_page(self):

        if self.result_current_page > 1:

            self.result_current_page -= 1

            self.result_show_page()


    def result_next_page(self):

        if (
            self.result_current_page
            < self.result_total_pages()
        ):

            self.result_current_page += 1

            self.result_show_page()


    # ========================================================
    # PRINT RESULT
    # ========================================================

    def print_result(self):

        # พิมพ์ผลลัพธ์ที่ค้นหาอยู่ทั้งหมด
        # ไม่ใช่เฉพาะหน้าปัจจุบัน

        rows = self.result_all_rows


        if not rows:
            return


        printer = QPrinter(
            QPrinter.PrinterMode.HighResolution
        )


        dialog = QPrintDialog(
            printer,
            self
        )


        if (
            dialog.exec()
            != QDialog.DialogCode.Accepted
        ):

            return


        self.print_result_pages(
            printer,
            rows
        )


    def print_result_pages(
        self,
        printer,
        rows
    ):

        # 15 รายการ / หน้า
        chunks = [
            rows[i:i + 15]
            for i in range(
                0,
                len(rows),
                15
            )
        ]


        for page_no, chunk in enumerate(
            chunks,
            start=1
        ):

            document = QTextDocument()


            document.setDefaultFont(
                QFont(
                    "Arial",
                    9
                )
            )


            html = f"""
            <html>
            <head>
            <meta charset="utf-8">
            <style>
                body {{
                    font-family: Arial;
                    font-size: 9pt;
                }}

                h2 {{
                    text-align: center;
                }}

                .page {{
                    text-align: center;
                    margin-bottom: 8px;
                }}

                table {{
                    border-collapse: collapse;
                    width: 100%;
                }}

                th, td {{
                    border: 1px solid #000;
                    padding: 4px;
                }}

                th {{
                    background: #eeeeee;
                }}
            </style>
            </head>

            <body>

            <h2>
                รายงานผลการเช็กชื่อ RFID
            </h2>

            <div class="page">
                หน้า {page_no} / {len(chunks)}
            </div>

            <table>

            <tr>
                <th>No.</th>
                <th>รหัสนักศึกษา</th>
                <th>ชื่อ-นามสกุล</th>
                <th>RFID</th>
                <th>คณะ</th>
                <th>สาขาวิชา</th>
                <th>ชื่อปริญญา</th>
                <th>รอบ</th>
            </tr>
            """


            first_number = (
                (page_no - 1)
                * 15
            )


            for i, row in enumerate(
                chunk,
                start=1
            ):

                html += f"""
                <tr>
                    <td>{first_number + i}</td>
                    <td>{row["std_id"]}</td>
                    <td>{row["fullname"]}</td>
                    <td>{row["rfid"]}</td>
                    <td>{row["faculty"]}</td>
                    <td>{row["major"]}</td>
                    <td>{row["educational"]}</td>
                    <td>{row["round"]}</td>
                </tr>
                """


            html += """
            </table>

            </body>
            </html>
            """


            document.setHtml(
                html
            )


            document.print(
                printer
            )


            # ไปหน้าใหม่
            if page_no < len(chunks):

                printer.newPage()


    # ========================================================
    # TAB CHANGED
    # ========================================================

    def tab_changed(
        self,
        index
    ):

        if index == 0:

            self.load_student_data()

            self.populate_dashboard_filters()

            self.refresh_dashboard()


        elif index == 1:

            self.load_student_data()

            self.result_search()


    # ========================================================
    # STATUS
    # ========================================================

    def on_status(
        self,
        text
    ):

        self.status_label.setText(
            text
        )


    def on_raw(
        self,
        text
    ):

        print(
            text
        )


    def on_error(
        self,
        text
    ):

        print(
            "ERROR:",
            text
        )

        self.status_label.setText(
            "Error"
        )


        QMessageBox.warning(
            self,
            "RFID Error",
            text
        )


    # ========================================================
    # READER FINISHED
    # ========================================================

    def on_reader_finished(self):

        self.status_label.setText(
            "Disconnected"
        )


        self.connect_button.setEnabled(
            True
        )

        self.close_button.setEnabled(
            False
        )

        self.query_button.setEnabled(
            False
        )

        self.stop_button.setEnabled(
            False
        )

        self.ip_edit.setEnabled(
            True
        )

        self.port_edit.setEnabled(
            True
        )


        self.worker = None


    # ========================================================
    # CLOSE READER
    # ========================================================

    def close_reader(self):

        if self.worker:

            self.worker.stop_worker()

            self.worker.wait(
                1500
            )

            self.worker = None


        self.status_label.setText(
            "Disconnected"
        )


        self.connect_button.setEnabled(
            True
        )

        self.close_button.setEnabled(
            False
        )

        self.query_button.setEnabled(
            False
        )

        self.stop_button.setEnabled(
            False
        )

        self.ip_edit.setEnabled(
            True
        )

        self.port_edit.setEnabled(
            True
        )


    # ========================================================
    # EXIT
    # ========================================================

    def exit_program(self):

        reply = QMessageBox.question(
            self,
            "Exit",
            "ต้องการปิดโปรแกรมหรือไม่?",
            (
                QMessageBox.StandardButton.Yes
                |
                QMessageBox.StandardButton.No
            )
        )


        if (
            reply
            == QMessageBox.StandardButton.Yes
        ):

            self.close_reader()

            QApplication.quit()


    def closeEvent(
        self,
        event
    ):

        if hasattr(
            self,
            "api_running"
        ) and self.api_running:

            self.stop_api_sender()


        self.close_reader()

        event.accept()


# ============================================================
# MAIN
# ============================================================

def main():

    app = QApplication(
        sys.argv
    )

    app.setStyle(
        "Fusion"
    )


    window = MainWindow()

    window.show()


    sys.exit(
        app.exec()
    )


if __name__ == "__main__":

    main()
