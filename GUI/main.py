import sys, random, socket, json, queue
from PyQt5 import QtWidgets, QtCore, Qt, QtNetwork, uic

from PyQt5.QtNetwork import *
from PyQt5.QtChart import QChart, QChartView, QPieSeries, QLineSeries, QPieSlice
from PyQt5.QtCore import QPointF, QThreadPool, QTimer, Qt, QRunnable
from PyQt5.QtGui import *
from PyQt5.QtWidgets import QFrame, QHeaderView, QMainWindow, QTableWidgetItem, QCheckBox, QDialog

from setting import Setting

na_queue = queue.Queue()

class Server(QtCore.QObject):
    def __init__(self, parent=None):
        QtCore.QObject.__init__(self)
        self.TCP_LISTEN_TO_PORT = 7011
        self.server = QtNetwork.QTcpServer()
        self.server.newConnection.connect(self.on_newConnection)

    def on_newConnection(self):
        while self.server.hasPendingConnections():
            print("Incoming Connection...")
            self.client = Client(self, "Hi! from server", self.TCP_LISTEN_TO_PORT)
            self.client.SetSocket(self.server.nextPendingConnection())

    def StartServer(self):
        if self.server.listen(QtNetwork.QHostAddress.Any, self.TCP_LISTEN_TO_PORT):
            print("Server is listening on port: {}".format(self.TCP_LISTEN_TO_PORT))
        else:
            print("Server couldn't wake up")

class Client(QtCore.QObject):
    def __init__(self, self_arg, msg, server_port):
        super().__init__(self_arg)
        self.msg = msg
        self.server_port = server_port

    def SetSocket(self, socket):
        self.socket = socket
        self.socket.connected.connect(self.on_connected)
        self.socket.disconnected.connect(self.on_connected)
        self.socket.readyRead.connect(self.on_readyRead)
        print("Client Connected from IP %s" % self.socket.peerAddress().toString())

    def on_connected(self):
        print("Client Connected Event")

    def on_disconnected(self):
        print("Client Disconnected")

    def on_readyRead(self):
        msg = self.socket.readAll()
        print(type(msg), msg.count())
        print("Client Message:", msg)

        msg = msg.data().decode()
        msg = json.loads(msg)
        if msg["type"] == "init":
            user = msg["user"]
            if user == "packet_analyzer":
                data = {"type": "analyze_req"}
                self.msg = json.dumps(data)
                self.send()
        elif msg["type"] == "analyze_res":
            print(msg)
            na_queue.put(msg["data"])
        else:
            pass

    def send(self):
        self.socket.write(self.msg.encode())
        print("send", self.msg)
        self.socket.flush()
        # self.socket.disconnectFromHost()

class Ui_MainWindow(object):
    def __init__(self):
        super().__init__()
        self.server = Server()
        self.server.StartServer()

    def display_dummy_table(self):
        x = self.table_widget.rowCount()
        item = [["192.168.12.1", "192.168.12.2", "ICMP", "ACK"], ["192.168.12.2", "192.168.12.1", "ICMP", "RES"], ["192.168.12.3", "192.168.12.1", "HTTPS", "Secure HTTP"], ["192.168.12.4", "192.168.12.1", "FTP", "File"]]
        r = random.randint(0, len(item) - 1)
        for i in range(4):
            self.table_widget.setItem(x, i, QTableWidgetItem(item[r][i]))

    def update_table(self):
        x = self.table_widget.rowCount()
        while not na_queue.empty():
            data = na_queue.get()
            self.table_widget.setRowCount(x + 1)
            data_arr = [data["ip_src"], data["ip_dst"], "ICMP", "None"]
            for i in range(len(data_arr)):
                self.table_widget.setItem(x, i, QTableWidgetItem(data_arr[i]))

    def update_pie_chart(self):
        slices = self.pie_chart_series.slices()
        if len(slices) < 2:
            return

        while True:
            slice = random.choice(slices)
            if slice.label() == "Other":
                continue
            slice.setValue(random.randint(0, 100))
            break

        tmp = []
        for e in slices:
            slice = QPieSlice(e.label(), e.value())
            slice.setBrush(e.brush().color())
            tmp.append(slice)
        sorted_slices = sorted(tmp, key=lambda x: x.value(), reverse=True)

        i = 0
        other_label, other_value, other_color = None, None, None
        for e in sorted_slices:
            label, value, color = e.label(), e.value(), e.brush().color()
            if label == "Other":
                other_label, other_value, other_color = label, value, color
                continue
            self.pie_chart_series.slices()[i].setLabel(label)
            self.pie_chart_series.slices()[i].setValue(value)
            self.pie_chart_series.slices()[i].setBrush(color)
            i += 1

        self.pie_chart_series.slices()[i].setLabel(other_label)
        self.pie_chart_series.slices()[i].setValue(other_value)
        self.pie_chart_series.slices()[i].setBrush(other_color)

    def func5(self, item):
        if self.is_enable_autoscroll and item.column() == 0:
            self.table_widget.scrollToItem(item, QtWidgets.QAbstractItemView.PositionAtBottom)

    def func6(self, state):
        if QtCore.Qt.Checked == state:
            print("Checked")
            self.is_enable_autoscroll = True
        else:
            print("Unchecked")
            self.is_enable_autoscroll = False

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1600, 1000)

        self.central_widget = QtWidgets.QWidget(MainWindow)
        self.central_widget.setObjectName("central_widget")

        self.horizontal_layout_widget = QtWidgets.QWidget(self.central_widget)
        self.horizontal_layout_widget.setGeometry(QtCore.QRect(0, 21, 1600, 800))
        self.horizontal_layout_widget.setObjectName("horizontal_layout_widget")

        self.horizontal_layout_1 = QtWidgets.QHBoxLayout(self.horizontal_layout_widget)
        self.horizontal_layout_1.setContentsMargins(0, 0, 0, 0)
        self.horizontal_layout_1.setObjectName("horizontal_layout_1")

        self.vertical_layout_1 = QtWidgets.QVBoxLayout()
        self.vertical_layout_1.setObjectName("vertical_layout_1")
        self.horizontal_layout_2 = QtWidgets.QHBoxLayout()
        self.horizontal_layout_2.setObjectName("horizontal_layout_2")

        # <--- Table ---> #
        self.table_widget = QtWidgets.QTableWidget(self.horizontal_layout_widget)
        self.table_widget.setObjectName("table_widget")
        self.table_widget.setColumnCount(4)
        self.table_widget.setRowCount(0)
        self.vheader = QHeaderView(QtCore.Qt.Orientation.Vertical)
        self.table_widget.setVerticalHeader(self.vheader)
        self.hheader = QHeaderView(QtCore.Qt.Orientation.Horizontal)
        self.table_widget.setHorizontalHeader(self.hheader)
        self.table_widget.setHorizontalHeaderLabels(['送信元', '送信先', 'プロトコル', '情報'])
        self.table_widget.setColumnWidth(0, 200)
        self.table_widget.setColumnWidth(1, 200)
        self.table_widget.setColumnWidth(2, 200)
        self.table_widget.setColumnWidth(3, 550)
        self.table_widget.itemChanged.connect(self.func5)
        self.table_timer = QTimer()
        self.table_timer.setInterval(600)
        self.table_timer.timeout.connect(self.update_table)
        self.table_timer.start()
        self.chkbox_enable_autoscroll = QCheckBox(self.horizontal_layout_widget)
        self.chkbox_enable_autoscroll.setObjectName("chkbox_enable_autoscroll")
        self.chkbox_enable_autoscroll.stateChanged.connect(self.func6)
        self.chkbox_enable_autoscroll.setCheckState(QtCore.Qt.Checked)
        self.is_enable_autoscroll = True
        # <--- Table ---> #

        self.widget_1 = QtWidgets.QWidget(self.horizontal_layout_widget)
        # self.widget_1.setMinimumSize(QtCore.QSize(400, 200))
        self.widget_1.setObjectName("widget_1")
        self.widget_1.setStyleSheet("background-color:powderblue;")
        self.label_widget_1 = QtWidgets.QTextEdit(self.widget_1)
        self.label_widget_1.setLineWrapMode(QtWidgets.QTextBrowser.NoWrap)
        self.label_widget_1.setMinimumSize(QtCore.QSize(580, 150))
        self.label_widget_1.setAlignment(Qt.AlignLeft)
        self.label_widget_1.setText("00 02 15 37 A2 44 00 AE F3 52 AA D1 08 00 45 00  ...7.D...R....E.\n00 43 00 01 00 00 40 06 78 3C C0 A8 05 15 42 23  .C....@.x<....B#\nFA 97 00 14 00 50 00 00 00 00 00 00 00 00 50 02  .....P........P.\n20 00 BB 39 00 00 47 45 54 20 2F 69 6E 64 65 78   ..9..GET /index\n2E 68 74 6D 6C 20 48 54 54 50 2F 31 2E 30 20 0A  .html HTTP/1.0 .\n0A                                               .\n00 02 15 37 A2 44 00 AE F3 52 AA D1 08 00 45 00  ...7.D...R....E.\n00 43 00 01 00 00 40 06 78 3C C0 A8 05 15 42 23  .C....@.x<....B#\nFA 97 00 14 00 50 00 00 00 00 00 00 00 00 50 02  .....P........P.\n20 00 BB 39 00 00 47 45 54 20 2F 69 6E 64 65 78   ..9..GET /index\n2E 68 74 6D 6C 20 48 54 54 50 2F 31 2E 30 20 0A  .html HTTP/1.0 .\n0A                                               .\n00 02 15 37 A2 44 00 AE F3 52 AA D1 08 00 45 00  ...7.D...R....E.\n00 43 00 01 00 00 40 06 78 3C C0 A8 05 15 42 23  .C....@.x<....B#\nFA 97 00 14 00 50 00 00 00 00 00 00 00 00 50 02  .....P........P.\n20 00 BB 39 00 00 47 45 54 20 2F 69 6E 64 65 78   ..9..GET /index\n2E 68 74 6D 6C 20 48 54 54 50 2F 31 2E 30 20 0A  .html HTTP/1.0 .\n0A                                               .\n00 02 15 37 A2 44 00 AE F3 52 AA D1 08 00 45 00  ...7.D...R....E.\n00 43 00 01 00 00 40 06 78 3C C0 A8 05 15 42 23  .C....@.x<....B#\nFA 97 00 14 00 50 00 00 00 00 00 00 00 00 50 02  .....P........P.\n20 00 BB 39 00 00 47 45 54 20 2F 69 6E 64 65 78   ..9..GET /index\n2E 68 74 6D 6C 20 48 54 54 50 2F 31 2E 30 20 0A  .html HTTP/1.0 .\n0A                                               .\n00 02 15 37 A2 44 00 AE F3 52 AA D1 08 00 45 00  ...7.D...R....E.\n00 43 00 01 00 00 40 06 78 3C C0 A8 05 15 42 23  .C....@.x<....B#\nFA 97 00 14 00 50 00 00 00 00 00 00 00 00 50 02  .....P........P.\n20 00 BB 39 00 00 47 45 54 20 2F 69 6E 64 65 78   ..9..GET /index\n2E 68 74 6D 6C 20 48 54 54 50 2F 31 2E 30 20 0A  .html HTTP/1.0 .\n0A                                               .\n")
        self.label_widget_1.setFont(QFont("MS UI Gothic", 12, QFont.Bold))
        self.label_widget_1.setFrameStyle(QFrame.NoFrame)

        self.widget_2 = QtWidgets.QWidget(self.horizontal_layout_widget)
        self.widget_2.setMinimumSize(QtCore.QSize(400, 200))
        self.widget_2.setObjectName("widget_2")
        # self.widget_2.setStyleSheet("background-color:blue;")
        self.treeWidget = QtWidgets.QTreeWidget(self.widget_2)
        self.treeWidget.setMinimumSize(QtCore.QSize(580, 150))
        # self.treeWidget.setGeometry(QtCore.QRect(320, 240, 256, 192))
        self.treeWidget.setObjectName("treeWidget")
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)

        self.horizontal_layout_2.addWidget(self.widget_1)
        self.horizontal_layout_2.addWidget(self.widget_2)
        self.vertical_layout_1.addWidget(self.table_widget)
        self.vertical_layout_1.addWidget(self.chkbox_enable_autoscroll)
        self.vertical_layout_1.addLayout(self.horizontal_layout_2)
        self.horizontal_layout_1.addLayout(self.vertical_layout_1)

        self.vertical_layout_2 = QtWidgets.QVBoxLayout()
        self.vertical_layout_2.setObjectName("vertical_layout_2")

        # < --- Pie Chart --- > #
        self.pie_chart_series = QPieSeries()
        colors = [QColor("#2085ec"), QColor("#72b4eb"), QColor("#0a417a"), QColor("#8464a0"), QColor("#cea9bc")]
        data = {"HTTPS": (80, colors[0]), "SMTP": (70, colors[1]), "FTP": (50, colors[2]), "NTP": (40, colors[3]), "Other": (30, colors[4])}
        for name, (value, color) in data.items():
            _slice = self.pie_chart_series.append(name, value)
            _slice.setBrush(color)
        self.pie_chart_series.hovered.connect(
            lambda x, y: [
                x.setExploded(y),
                x.setLabelVisible(y),
                x.setPen(QPen(Qt.darkGreen if y else Qt.white, 2)),
                x.setBrush(Qt.green if y else colors[self.pie_chart_series.slices().index(x)])
            ]
        )
        self.pie_chart = QChart()
        self.pie_chart.legend().hide()
        self.pie_chart.addSeries(self.pie_chart_series)
        self.pie_chart.createDefaultAxes()
        self.pie_chart.setAnimationOptions(QChart.SeriesAnimations)
        self.pie_chart.setMaximumSize(QtCore.QSizeF(420, 250))
        self.pie_chart.setBackgroundBrush(QBrush(QColor("#e6cfb2")))

        self.pie_chart.legend().setVisible(True)
        self.pie_chart.legend().setAlignment(Qt.AlignBottom)
        self.pie_chart.legend().setFont(QFont("MS UI Gothic", 11))

        self.pie_chartview = QChartView(self.pie_chart)
        self.pie_chartview.setRenderHint(QPainter.Antialiasing)

        self.table_timer = QTimer()
        self.table_timer.setInterval(600)
        self.table_timer.timeout.connect(self.update_pie_chart)
        self.table_timer.start()
        # < --- Pie Chart --- > #

        # < --- Dummy Line Chart --- > #
        self.line_chart = QChart()
        self.line_chart_series = QLineSeries()
        self.line_chart_series.append(0, 0)
        self.line_chart.addSeries(self.line_chart_series)
        self.line_chart.createDefaultAxes()
        self.line_chart.setMaximumSize(QtCore.QSizeF(420, 250))
        self.line_chart.setAnimationOptions(QChart.AllAnimations)
        self.line_chart.setBackgroundBrush(QBrush(QColor("powderblue")))

        self.line_chart.legend().setVisible(False)

        self.line_chartview = QChartView(self.line_chart)
        self.line_chartview.setRenderHint(QPainter.Antialiasing)

        self.line_chart_time = 0
        self.line_chart_max_y = 0
        self.timer = QTimer()
        self.timer.setInterval(200)
        self.timer.timeout.connect(self.plot_dummy_line_graph)
        self.timer.start()
        # < --- Dummy Line Chart --- > #

        self.widget_3 = QtWidgets.QWidget(self.horizontal_layout_widget)
        self.widget_3.setMinimumSize(QtCore.QSize(420, 250))
        self.widget_3.setObjectName("widget_3")
        self.widget_3.setStyleSheet("background-color:#f2ead7;")

        # < --- Dummy Comm Partner Info --- > #
        self.label_comm_partner_ip_address = QtWidgets.QTextBrowser(self.widget_3)
        self.label_comm_partner_ip_address.setMaximumSize(QtCore.QSize(420, 250))
        self.label_comm_partner_ip_address.setAlignment(Qt.AlignLeft)
        self.label_comm_partner_ip_address.setText("相手ノード情報\n\nIP: 127.0.0.1\nMACアドレス: 00:00:00:00:00:00")
        self.label_comm_partner_ip_address.setFont(QFont("MS UI Gothic", 14, QFont.Bold))
        self.label_comm_partner_ip_address.setFrameStyle(QFrame.NoFrame)
        # < --- Dummy Comm Partner Info --- > #

        self.vertical_layout_2.addWidget(self.pie_chartview)
        self.vertical_layout_2.addWidget(self.line_chartview)
        self.vertical_layout_2.addWidget(self.widget_3)
        self.horizontal_layout_1.addLayout(self.vertical_layout_2)

        MainWindow.setCentralWidget(self.central_widget)

        # < ----- MenuBar ----- > #
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1000, 24))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)

        self.menu_1 = QtWidgets.QMenu(self.menubar)
        self.menu_1.setObjectName("menu_1")
        self.menu_import = QtWidgets.QMenu(self.menu_1)
        self.menu_import.setObjectName("menu_import")
        self.menu_export = QtWidgets.QMenu(self.menu_1)
        self.menu_export.setObjectName("menu_export")
        self.setting = QtWidgets.QAction(self.menu_1)
        self.setting.setObjectName("menu_setting")
        self.setting.triggered.connect(self.open_setting)
        self.import_pcap = QtWidgets.QAction(MainWindow)
        self.import_pcap.setObjectName("import_pcap")
        self.import_json = QtWidgets.QAction(MainWindow)
        self.import_json.setObjectName("import_json")
        self.export_pcap = QtWidgets.QAction(MainWindow)
        self.export_pcap.setObjectName("export_pcap")
        self.export_json = QtWidgets.QAction(MainWindow)
        self.export_json.setObjectName("export_json")
        self.action_quit = QtWidgets.QAction(MainWindow)
        self.action_quit.setObjectName("action_quit")
        self.action_quit.triggered.connect(lambda: sys.exit())
        self.menu_import.addAction(self.import_pcap)
        self.menu_import.addAction(self.import_json)
        self.menu_export.addAction(self.export_pcap)
        self.menu_export.addAction(self.export_json)
        self.menu_1.addAction(self.menu_import.menuAction())
        self.menu_1.addAction(self.menu_export.menuAction())
        self.menu_1.addSeparator()
        self.menu_1.addAction(self.setting)
        self.menu_1.addAction(self.action_quit)

        self.menu_2 = QtWidgets.QMenu(self.menubar)
        self.menu_2.setObjectName("menu_2")
        self.action_analyze_start = QtWidgets.QAction(MainWindow)
        self.action_analyze_start.setObjectName("action_analyze_start")
        self.action_analyze_start.triggered.connect(lambda x: print("aaa"))
        self.action_analyze_finish = QtWidgets.QAction(MainWindow)
        self.action_analyze_finish.setObjectName("action_analyze_finish")
        self.menu_2.addAction(self.action_analyze_start)
        self.menu_2.addAction(self.action_analyze_finish)

        self.menu_3 = QtWidgets.QMenu(self.menubar)
        self.menu_3.setObjectName("menu_3")
        self.action_node_detect = QtWidgets.QAction(MainWindow)
        self.action_node_detect.setObjectName("action_node_detect")
        self.action_node_search = QtWidgets.QAction(MainWindow)
        self.action_node_search.setObjectName("action_node_search")
        self.menu_3.addAction(self.action_node_detect)
        self.menu_3.addAction(self.action_node_search)

        self.menubar.addAction(self.menu_1.menuAction())
        self.menubar.addAction(self.menu_2.menuAction())
        self.menubar.addAction(self.menu_3.menuAction())
        # < ----- MenuBar ----- > #

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def plot_dummy_line_graph(self):
        self.line_chart.setAnimationOptions(QChart.NoAnimation)
        self.line_chart_time += 0.2
        y = random.uniform(0, 10)
        self.line_chart_max_y = max(self.line_chart_max_y, y)
        self.line_chart_series << QPointF(self.line_chart_time, y)
        ax = self.line_chart.axisX(self.line_chart_series)
        if self.line_chart_time / 5 >= 1:
            ax.setMin(self.line_chart_time - 5)
        else:
            ax.setMin(0)
        ax.setMax(self.line_chart_time)
        ay = self.line_chart.axisY(self.line_chart_series)
        ay.setMin(0)
        ay.setMax(self.line_chart_max_y)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Test"))
        self.menu_1.setTitle(_translate("MainWindow", "ファイル"))
        self.menu_import.setTitle(_translate("MainWindow", "インポート"))
        self.import_pcap.setText(_translate("MainWindow", "PCAP"))
        self.import_json.setText(_translate("MainWindow", "JSON"))
        self.menu_export.setTitle(_translate("MainWindow", "エクスポート"))
        self.export_pcap.setText(_translate("MainWindow", "PCAP"))
        self.export_json.setText(_translate("MainWindow", "JSON"))
        self.setting.setText(_translate("MainWindow", "設定"))
        self.action_quit.setText(_translate("MainWindow", "終了"))
        self.menu_2.setTitle(_translate("MainWindow", "解析"))
        self.action_analyze_start.setText(_translate("MainWindow", "開始"))
        self.action_analyze_finish.setText(_translate("MainWindow", "終了"))
        self.menu_3.setTitle(_translate("MainWindow", "ノード"))
        self.action_node_detect.setText(_translate("MainWindow", "検出"))
        self.action_node_search.setText(_translate("MainWindow", "検索"))
        self.chkbox_enable_autoscroll.setText(_translate("MainWindow", "オートスクロール"))
        self.treeWidget.headerItem().setText(0, _translate("MainWindow", "パケット情報"))
        __sortingEnabled = self.treeWidget.isSortingEnabled()
        self.treeWidget.setSortingEnabled(False)
        self.treeWidget.topLevelItem(0).setText(0, _translate("MainWindow", "Ethernet"))
        self.treeWidget.topLevelItem(0).child(0).setText(0, _translate("MainWindow", "Source"))
        self.treeWidget.topLevelItem(0).child(1).setText(0, _translate("MainWindow", "Destination"))
        self.treeWidget.topLevelItem(1).setText(0, _translate("MainWindow", "Internet Layer"))
        self.treeWidget.topLevelItem(1).child(0).setText(0, _translate("MainWindow", "Length"))
        self.treeWidget.topLevelItem(2).setText(0, _translate("MainWindow", "TCP"))
        self.treeWidget.topLevelItem(2).child(0).setText(0, _translate("MainWindow", "Length"))
        self.treeWidget.setSortingEnabled(__sortingEnabled)

    def open_setting(self):
        # self.setting_window = SettingDialog()
        self.setting_window = SettingDialog()
        # self.setting_window.setupUi(QtWidgets.QMainWindow())
        # self.setting_window = Setting()
        # self.setting_window.show()

class SettingDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi("setting.ui", self)
        self.show()

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
