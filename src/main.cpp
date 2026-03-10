#include <algorithm>
#include <cctype>

#ifdef QT_VERSION_CHECK
#include <QStringConverter>
#endif
    
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
#include <thread>
#include <mutex>
#include <algorithm>

#ifdef USE_QXLSX
#include "xlsxdocument.h"
#endif
    
// Глобальные переменные для синхронизации и хранения данных
QMutex fileMutex; 

// Global normalizeLine function
std::string normalizeLine(const std::string& line) {
    std::string result = line;
    result.erase(std::remove(result.begin(), result.end(), '\r'), result.end());
    
    size_t start = result.find_first_not_of(" \t");
    if (start == std::string::npos) {
        return "";
    }
    
    size_t end = result.find_last_not_of(" \t");
    return result.substr(start, end - start + 1);
}

// src/main.cpp

void recording(const std::string &filePath, const std::string &ip, const std::string &status) {
    std::ofstream outfile(filePath, std::ios::app);
    if (outfile.is_open()) {
        // Явно используем \n для совместимости
        outfile << ip << " - " << status << "\n";
    }
}

// Функция пинга с анализом вывода
bool ping_host(const std::string &address) {
    QProcess pingProcess;
    
#ifdef Q_OS_WIN
    pingProcess.start("ping", QStringList() 
        << "-n" << "1" 
        << "-w" << "2000" 
        << QString::fromStdString(address));
#else
    // Linux: -q (quiet mode), -c 1 (один пакет), -W 3 (таймаут 3 сек)
    pingProcess.start("ping", QStringList() 
        << "-q" 
        << "-c" << "1" 
        << "-W" << "3" 
        << QString::fromStdString(address));
#endif

    // Увеличим общий таймаут ожидания процесса
    if (!pingProcess.waitForFinished(5000)) {
        pingProcess.kill();
        return false;
    }

    int exitCode = pingProcess.exitCode();
    
    // ping возвращает 0 если хост доступен, != 0 если недоступен
    // Это работает одинаково в Windows и Linux
    return (exitCode == 0);
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

// Служебные функции чтения строк из файла
std::vector<std::string> readLinesFromFile(const QString &filePath) {
    std::vector<std::string> lines;
    QFile file(filePath);
    
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&file);
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        in.setEncoding(QStringConverter::Utf8);
#else
        in.setCodec("UTF-8");
#endif
        
        while (!in.atEnd()) {
            QString line = in.readLine().trimmed();
            if (!line.isEmpty()) {
                lines.push_back(line.toStdString());
            }
        }
        file.close();
    }
    
    return lines;
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

        // Ограничение до 50% ядер
        unsigned int hardwareThreads = std::thread::hardware_concurrency();
        unsigned int poolSize = std::max(1u, hardwareThreads / 2);
        pool = std::make_unique<ThreadPool>(poolSize);
     //   log(QString("Пул потоков: %1 из %2 ядер").arg(poolSize).arg(hardwareThreads));
    }

    ~MainWindow() {
        // unique_ptr handles deletion
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
            // Нормализуем строку перед обработкой
            std::string normalized = normalizeLine(line);
            
            QRegularExpression ipRegex("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
            QRegularExpressionMatch match = ipRegex.match(QString::fromStdString(normalized));
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
            // Используем Qt для чтения (автоматически обрабатывает CRLF)
            QFile file(addrPath);
            if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QTextStream in(&file);
                while (!in.atEnd()) {
                    QString line = in.readLine().trimmed();
                    if (!line.isEmpty()) {
                        ips.push_back(line.toStdString());
                    }
                }
                file.close();
            }
            log(QString("Прочитано %1 IP из файла").arg(ips.size()));
        }

        // Чтение паролей с обработкой CRLF
        QFile passFile(PathListPassword->text());
        if (passFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream in(&passFile);
            while (!in.atEnd()) {
                QString line = in.readLine().trimmed();
                if (!line.isEmpty()) {
                    passwords.push_back(line.toStdString());
                }
            }
            passFile.close();
        }

        std::reverse(passwords.begin(), passwords.end());

        totalTasks = ips.size();
        completedTasks = 0;

        if (totalTasks == 0) {
            logArea->append("Список IP пуст.");
            btnStart->setEnabled(true);
            return;
        }

        auto passwordsCopy = passwords;
        for (const auto& ip : ips) {
            pool->enqueue([this, ip, passwordsCopy]() {
                processIP(ip, passwordsCopy);
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
    std::unique_ptr<ThreadPool> pool;

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
            // Запускаем повторные проходы в фоновом потоке, не блокируя UI
            std::thread([this]() {
                log("Основной список завершён. Начинаю проходы по журналу...");
                
                retryFailedAddresses(1);
                retryFailedAddresses(2);
                
                QMetaObject::invokeMethod(this, [this]() {
                    btnStart->setEnabled(true);
                    log("Завершено.");
                });
            }).detach();
        }
    }

    // New function to initialize thread pool based on hardware concurrency
    void initThreadPool() {
        // Получаем количество аппаратных потоков
        unsigned int hardwareThreads = std::thread::hardware_concurrency();
        
        // Ограничиваем до 50% (минимум 1 поток)
        unsigned int poolSize = std::max(1u, hardwareThreads / 2);
        
        // Создаём пул с ограниченным размером
        pool = std::make_unique<ThreadPool>(poolSize);
        
    //    log(QString("Пул потоков: %1 из %2 ядер").arg(poolSize).arg(hardwareThreads));
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    MainWindow window;
    window.show();
    return app.exec();
}

#include "main.moc"

// src/main.cpp

std::vector<std::string> readIPsFromFile(const QString &filePath) {
    std::vector<std::string> ips;
    QFile file(filePath);
    
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return ips;
    }
    
    QTextStream in(&file);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (!line.isEmpty()) {
            ips.push_back(line.toStdString());
        }
    }
    
    file.close();
    return ips;
}