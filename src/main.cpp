#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QFileDialog>
#include <QTextEdit>
#include <QMutex>
#include <QProgressBar>
#include <QProcess> 
#include <fstream>
#include <sstream>
#include <iostream>
#include <set>
#include <atomic>
#include <QRegularExpression>
#include "SSHClient.h"
#include "ThreadPool.h"

#ifdef USE_QXLSX
#include "xlsxdocument.h"
#endif
    
// Глобальные переменные для синхронизации и хранения данных
QMutex fileMutex; 

// Функция пинга с анализом вывода
bool ping_host(const std::string &address) {
    QProcess pingProcess;
    
#ifdef Q_OS_WIN
    pingProcess.start("ping", QStringList() 
        << "-n" << "1" 
        << "-w" << "2000" 
        << QString::fromStdString(address));
#else
    pingProcess.start("ping", QStringList() 
        << "-c" << "1" 
        << "-W" << "2" 
        << QString::fromStdString(address));
#endif

    if (!pingProcess.waitForFinished(3500)) {
        pingProcess.kill();
        return false;
    }

    int exitCode = pingProcess.exitCode();
    QByteArray output = pingProcess.readAllStandardOutput();
    QString strOutput = QString::fromUtf8(output);

#ifdef Q_OS_WIN
    if (strOutput.contains("TTL=") || strOutput.contains("Reply from")) {
        return true;
    }
#else
    if (strOutput.contains("1 received") || strOutput.contains("1 packets received")) {
        return true;
    }
#endif

    if (exitCode == 0) {
        return true;
    }

    return false;
}

// Функция записи результатов в файл
void recording(const std::string &path_file, const std::string &name, const std::string &reason) {
    QMutexLocker locker(&fileMutex);
    
    std::set<std::string> existingNames;
    std::ifstream infile(path_file);
    std::string existingName;
    std::string line = name + " " + reason;

    if (infile.is_open()) {
        while (std::getline(infile, existingName)) {
            existingNames.insert(existingName);
        }
        infile.close();
    }

    if (existingNames.find(line) == existingNames.end()) {
        std::ofstream file(path_file, std::ios::app);
        if (file.is_open()) {
            file << name << " " << reason << std::endl;
        } else {
            std::cerr << "Не удалось открыть файл для записи: " << path_file << std::endl;
        }
    }
}

// Функция записи firewall правил в файл на роутере
bool write_firewall_rules(SSHClient &client, const QString &firewallFilePath) {
    std::ifstream file(firewallFilePath.toStdString());
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    std::vector<std::string> rules;
    
    while (std::getline(file, line)) {
        if (line.empty() || line.find_first_not_of(" \t\r\n") == std::string::npos) {
            continue;
        }
        rules.push_back(line);
    }
    file.close();
    
    if (rules.empty()) {
        return false;
    }
    
    client.executeCommand("> /etc/firewall.user");
    
    for (size_t i = 0; i < rules.size(); i += 5) {
        std::string cmd;
        for (size_t j = i; j < std::min(i + 5, rules.size()); ++j) {
            QString escapedLine = QString::fromStdString(rules[j]);
            escapedLine.replace("'", "'\\''");
            if (j == i) {
                cmd = "echo '" + escapedLine.toStdString() + "' >> /etc/firewall.user";
            } else {
                cmd += " && echo '" + escapedLine.toStdString() + "' >> /etc/firewall.user";
            }
        }
        client.executeCommand(cmd);
    }
    
    
    std::string finalCmd = "sh -c '. /etc/firewall.user; reboot &'";
    
    int rc = client.executeCommand(finalCmd);
    return (rc == SSH_OK);
}

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr) : QMainWindow(parent) {
        QWidget *centralWidget = new QWidget(this);
        QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

        // 1. Список IP
        QHBoxLayout *ipLayout = new QHBoxLayout();
        ipLayout->addWidget(new QLabel("Список IP:"));
        PathListAddresses = new QLineEdit();
        ipLayout->addWidget(PathListAddresses);
        QPushButton *btnBrowseIP = new QPushButton("Обзор...");
        connect(btnBrowseIP, &QPushButton::clicked, this, &MainWindow::onBrowseAddresses);
        ipLayout->addWidget(btnBrowseIP);
        mainLayout->addLayout(ipLayout);

        // 2. Список паролей
        QHBoxLayout *passLayout = new QHBoxLayout();
        passLayout->addWidget(new QLabel("Список паролей:"));
        PathListPassword = new QLineEdit();
        passLayout->addWidget(PathListPassword);
        QPushButton *btnBrowsePass = new QPushButton("Обзор...");
        connect(btnBrowsePass, &QPushButton::clicked, this, &MainWindow::onBrowsePasswords);
        passLayout->addWidget(btnBrowsePass);
        mainLayout->addLayout(passLayout);

        // 3. Файл firewall правил
        QHBoxLayout *firewallLayout = new QHBoxLayout();
        firewallLayout->addWidget(new QLabel("Файл firewall:"));
        PathListFirewall = new QLineEdit();
        firewallLayout->addWidget(PathListFirewall);
        QPushButton *btnBrowseFirewall = new QPushButton("Обзор...");
        connect(btnBrowseFirewall, &QPushButton::clicked, this, &MainWindow::onBrowseFirewall);
        firewallLayout->addWidget(btnBrowseFirewall);
        mainLayout->addLayout(firewallLayout);

        // 4. Файл отчета
        QHBoxLayout *failLayout = new QHBoxLayout();
        failLayout->addWidget(new QLabel("Файл отчета:"));
        ListAddressesUnchangedPasswords = new QLineEdit();
        failLayout->addWidget(ListAddressesUnchangedPasswords);
        QPushButton *btnBrowseFail = new QPushButton("Обзор...");
        connect(btnBrowseFail, &QPushButton::clicked, this, &MainWindow::onBrowseUP);
        failLayout->addWidget(btnBrowseFail);
        mainLayout->addLayout(failLayout);

        // Прогресс
        progres = new QLabel("Готов к работе");
        mainLayout->addWidget(progres);

        // Кнопка запуска
        btnStart = new QPushButton("Начать");
        connect(btnStart, &QPushButton::clicked, this, &MainWindow::onStart);
        mainLayout->addWidget(btnStart);

        // Лог
        logArea = new QTextEdit();
        logArea->setReadOnly(true);
        mainLayout->addWidget(logArea);

        setCentralWidget(centralWidget);
        setWindowTitle("Настройка Firewall на роутерах");
        resize(550, 450);

        pool = new ThreadPool(4);
    }

    ~MainWindow() {
        delete pool;
    }

private slots:
    void onBrowseAddresses() {
        PathAddresses = QFileDialog::getOpenFileName(this, "Выбор списка адресов", "", 
            "Excel Files (*.xlsx);;Text Files (*.txt);;All Files (*.*)");
        if (!PathAddresses.isEmpty()) PathListAddresses->setText(PathAddresses);
    }

    void onBrowsePasswords() {
        PathPasswords = QFileDialog::getOpenFileName(this, "Выбор списка паролей", "", "Text Files (*.txt)");
        if (!PathPasswords.isEmpty()) PathListPassword->setText(PathPasswords);
    }

    void onBrowseUP() {
        PathAddressesUnchangedPasswords = QFileDialog::getOpenFileName(this, 
            "Выбор файла отчета", 
            "", 
            "Text Files (*.txt)");
        if (!PathAddressesUnchangedPasswords.isEmpty()) {
            ListAddressesUnchangedPasswords->setText(PathAddressesUnchangedPasswords);
        }
    }
    
    void onBrowseFirewall() {
        PathFirewall = QFileDialog::getOpenFileName(this, 
            "Выбор файла firewall правил", 
            "", 
            "Text Files (*.txt)");
        if (!PathFirewall.isEmpty()) {
            PathListFirewall->setText(PathFirewall);
        }
    }

    std::vector<std::string> readIPsFromExcel(const QString &filePath) {
        std::vector<std::string> ips;
#ifdef USE_QXLSX
        QXlsx::Document xlsx(filePath);
        if (!xlsx.load()) {
            return ips;
        }
        
        int attrColumn = -1;
        for (int col = 1; col <= xlsx.dimension().columnCount(); ++col) {
            QVariant header = xlsx.read(1, col);
            if (header.toString().trimmed().toLower() == "атрибуты") {
                attrColumn = col;
                break;
            }
        }

        if (attrColumn == -1) {
            return ips;
        }
        
        for (int row = 2; row <= xlsx.dimension().rowCount(); ++row) {
            QVariant cell = xlsx.read(row, attrColumn);
            QString value = cell.toString().trimmed();
            if (!value.isEmpty()) {
                QRegularExpression ipRegex("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
                QRegularExpressionMatch match = ipRegex.match(value);
                if (match.hasMatch()) {
                    ips.push_back(match.captured(1).toStdString());
                }
            }
        }
#endif
        return ips;
    }

    std::vector<std::string> readFailedAddresses(const QString &filePath) {
        std::vector<std::string> addresses;
        std::ifstream infile(filePath.toStdString());
        std::string line;
        
        while (std::getline(infile, line)) {
            QRegularExpression ipRegex("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
            QRegularExpressionMatch match = ipRegex.match(QString::fromStdString(line));
            if (match.hasMatch()) {
                addresses.push_back(match.captured(1).toStdString());
            }
        }

        return addresses;
    }

    void removeAddressFromJournal(const QString &filePath, const std::string &ipToRemove) {
        QMutexLocker locker(&fileMutex);
        
        std::vector<std::string> lines;
        std::ifstream infile(filePath.toStdString());
        std::string line;
        
        while (std::getline(infile, line)) {
            if (line.find(ipToRemove) == std::string::npos) {
                lines.push_back(line);
            }
        }
        infile.close();
        
        std::ofstream outfile(filePath.toStdString());
        for (const auto &l : lines) {
            outfile << l << std::endl;
        }
    }

    void retryFailedAddresses(int passNumber) {
        QString journalPath = ListAddressesUnchangedPasswords->text();
        if (journalPath.isEmpty()) {
            log(QString("Проход %1 по журналу: путь к файлу отчета не указан").arg(passNumber));
            return;
        }

        QFileInfo fileInfo(journalPath);
        if (!fileInfo.exists()) {
            log(QString("Проход %1 по журналу: файл отчета не существует").arg(passNumber));
            return;
        }

        std::vector<std::string> failedAddresses = readFailedAddresses(journalPath);
        
        if (failedAddresses.empty()) {
            log(QString("Проход %1 по журналу: файл отчета пуст").arg(passNumber));
            return;
        }

        log(QString("Проход %1 по журналу: найдено %2 адресов").arg(passNumber).arg(failedAddresses.size()));
        
        int successCount = 0;
        std::vector<std::string> passwords;
        
        std::ifstream passFile(PathPasswords.toStdString());
        std::string pwd;
        while (std::getline(passFile, pwd)) {
            passwords.push_back(pwd);
        }
        
        for (const auto &ip : failedAddresses) {
            if (ping_host(ip)) {
                log(QString("Проход %1: %2 - связь появилась").arg(passNumber).arg(QString::fromStdString(ip)));
                
                SSHClient client(ip, "root");
                bool connected = false;
                std::string successPassword;
                
                for (const auto &password : passwords) {
                    if (client.connect(password, 10)) {
                        connected = true;
                        successPassword = password;
                        
                        if (write_firewall_rules(client, PathFirewall)) {
                            log(QString("Проход %1: %2 - firewall записан").arg(passNumber).arg(QString::fromStdString(ip)));
                            client.disconnect();
                            
                           
                        } else {
                            log(QString("Проход %1: %2 - ошибка записи firewall").arg(passNumber).arg(QString::fromStdString(ip)));
                            client.disconnect();
                        }
                        break;
                    }
                }
                
                if (!connected) {
                    log(QString("Проход %1: %2 - не подошёл ни один пароль").arg(passNumber).arg(QString::fromStdString(ip)));
                }
            }
        }
        
        log(QString("Проход %1 завершён: успешно %2").arg(passNumber).arg(successCount));
    }

    void onStart() {
        if (PathListAddresses->text().isEmpty() || PathListPassword->text().isEmpty() || 
            PathListFirewall->text().isEmpty() || ListAddressesUnchangedPasswords->text().isEmpty()) {
            logArea->append("Ошибка: Заполните все поля!");
            return;
        }

        btnStart->setEnabled(false);
        
        std::vector<std::string> ips;
        std::vector<std::string> passwords;
        
        QString addrPath = PathListAddresses->text();
        if (addrPath.endsWith(".xlsx", Qt::CaseInsensitive)) {
#ifdef USE_QXLSX
            ips = readIPsFromExcel(addrPath);
            log(QString("Прочитано %1 IP из Excel").arg(ips.size()));
#else
            log("Ошибка: QXlsx не подключён.");
            btnStart->setEnabled(true);
            return;
#endif
        } else {
            std::ifstream ifsIP(addrPath.toStdString());
            std::string line;
            while (std::getline(ifsIP, line)) {
                if (!line.empty()) ips.push_back(line);
            }
        }

        std::ifstream ifsPass(PathListPassword->text().toStdString());
        std::string line;
        while (std::getline(ifsPass, line)) {
            if (!line.empty()) passwords.push_back(line);
        }

        std::reverse(passwords.begin(), passwords.end());

        totalTasks = ips.size();
        completedTasks = 0;

        if (totalTasks == 0) {
            logArea->append("Список IP пуст.");
            btnStart->setEnabled(true);
            return;
        }

        for (const auto& ip : ips) {
            pool->enqueue([this, ip, passwords]() {
                processIP(ip, passwords);
            });
        }
    }

    private:
    QLineEdit *PathListAddresses;
    QLineEdit *PathListPassword;
    QLineEdit *ListAddressesUnchangedPasswords;
    QLineEdit *PathListFirewall;
    QPushButton *btnStart;
    QTextEdit *logArea;
    QLabel *progres;
    ThreadPool *pool;

    QString PathAddresses;
    QString PathPasswords;
    QString PathAddressesUnchangedPasswords;
    QString PathFirewall;

    std::atomic<uint> completedTasks{0};
    uint totalTasks = 0;

    void updateProgres(uint completed, uint total) {
        QMetaObject::invokeMethod(this, [this, completed, total]() {
            QString text = QString("Выполнено: %1%").arg(static_cast<int>((static_cast<double>(completed) / total) * 100));
            progres->setText(text);
        });
    }

    void log(const QString &msg) {
        QMetaObject::invokeMethod(logArea, "append", Qt::QueuedConnection, Q_ARG(QString, msg));
    }

    void processIP(const std::string &ip, const std::vector<std::string> &passwords) {
        if (!ping_host(ip)) {
            log(QString("Нет связи: %1 (хост недоступен)").arg(QString::fromStdString(ip)));
            recording(PathAddressesUnchangedPasswords.toStdString(), ip, "нет связи");
            
            completedTasks++;
            updateProgres(completedTasks, totalTasks);
            checkFinish();
            return;
        }

        bool connected = false;
        bool operationSuccess = false;
        std::string successPassword;

        for (const auto& pass : passwords) {
            SSHClient client(ip, "root");
            
            if (client.connect(pass)) {
                log(QString("Подключено к %1. Пароль: %2").arg(QString::fromStdString(ip), QString::fromStdString(pass)));
                connected = true;
                successPassword = pass;

                if (write_firewall_rules(client, PathFirewall)) {
                    log(QString("Успех: firewall записан на %1").arg(QString::fromStdString(ip)));
                    operationSuccess = true;
                } else {
                    log(QString("Ошибка: не удалось записать firewall на %1").arg(QString::fromStdString(ip)));
                    recording(PathAddressesUnchangedPasswords.toStdString(), ip, "FirewallFailed");
                }
                
                client.disconnect();
                break;
            }
        }

       
        if (!connected) {
            log(QString("Не подошли пароли для %1").arg(QString::fromStdString(ip)));
            recording(PathAddressesUnchangedPasswords.toStdString(), ip, "нет пароля");
        }

        completedTasks++;
        updateProgres(completedTasks, totalTasks);
        checkFinish();
    }

    void checkFinish() {
        if (completedTasks == totalTasks) {
            QMetaObject::invokeMethod(this, [this]() {
                log("Основной список завершён. Начинаю проходы по журналу...");
                
                retryFailedAddresses(1);
                retryFailedAddresses(2);
                
                btnStart->setEnabled(true);
                log("Завершено.");
            });
        }
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    MainWindow window;
    window.show();
    return app.exec();
}

#include "main.moc"