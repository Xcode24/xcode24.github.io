# updater18-5-5-3_fixed.py
import sys
import os
import json
import hashlib
import requests
import time
import threading
import concurrent.futures
import subprocess
import shutil
import stat
import tempfile
import vdf
winreg = None
try:
    if sys.platform.startswith('win'):
        import winreg as _winreg
        winreg = _winreg
except Exception:
    winreg = None
from requests.auth import HTTPBasicAuth
from urllib.parse import quote
from pathlib import Path
from threading import Semaphore

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QProgressBar, QTextEdit, QFileDialog, QListWidget, QSizePolicy,
    QTabWidget, QGroupBox, QFrame, QMessageBox, QComboBox
)
from PyQt6.QtCore import (
    Qt, QObject, pyqtSignal, QThread, QTimer, QSize, QSettings, QMetaObject, pyqtSlot, Q_ARG
)
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor, QCursor, QFontMetrics


# -------------------------
# Configuration and paths
# -------------------------
JSON_SERVER = "https://nethunter.sytes.net/sky/"
DAV_SERVER = "https://nethunter.sytes.net/cloud/remote.php/dav/files/SkyrimDownloader/1TB/ModOrganizer/"
PATCHER_SERVER = "https://nethunter.sytes.net/cloud/remote.php/dav/files/SkyrimDownloader/1TB/Patcher/"
URL_ICO = JSON_SERVER + "/updater/TESVAE-v1.0beta.ico"

USERNAME = "SkyrimDownloader"
PASSWORD = "IN7YePIP65e3uH0ERyMarV5xv57QaT75"

APPDATA_DIR = Path(os.getenv("APPDATA") or Path.home()) / "updater"
APPDATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = APPDATA_DIR / "config.json"
PROGRESS_FILE = APPDATA_DIR / "progress.json"
LOG_FILE = APPDATA_DIR / "updater.log"
PATCHER_MANIFEST_FILE = APPDATA_DIR / "patcher_manifest.json"

LOCAL_PATH_ICO = APPDATA_DIR / "TESVAE-v1.0beta.ico"

# Оптимизированные константы
def calculate_max_workers():
    cores = os.cpu_count() or 4
    return max(8, min(32, cores * 2))

MAX_WORKERS = calculate_max_workers()
BATCH_SIZE = 500

def format_eta(seconds: float) -> str:
    if seconds < 0:
        seconds = 0
    secs = int(seconds)
    hrs = secs // 3600
    mins = (secs % 3600) // 60
    s = secs % 60
    if hrs > 0:
        return f"{hrs}h{mins:02d}m{s:02d}s"
    elif mins > 0:
        return f"{mins}m{s:02d}s"
    else:
        return f"{s}s"

def normalize_path(path: str) -> str:
    return path.replace("\\", "/")

def ensure_windows_path(path: str) -> str:
    """Гарантирует, что путь использует Windows-разделители"""
    if isinstance(path, Path):
        path = str(path)
    if os.name == 'nt':
        return path.replace("/", "\\")
    return path

def reset_file_attributes(file_path):
    """Сбрасывает атрибуты файла для устранения проблем с доступом"""
    try:
        if os.name == 'nt':
            if os.path.exists(file_path):
                file_attr = os.stat(file_path).st_file_attributes
                if file_attr & stat.FILE_ATTRIBUTE_READONLY:
                    os.chmod(file_path, stat.S_IWRITE)
        return True
    except Exception as e:
        return False

# Скачать файл
try:
    r = requests.get(URL_ICO, timeout=10)
    with open(LOCAL_PATH_ICO, "wb") as f:
        f.write(r.content)
except Exception:
    LOCAL_PATH_ICO.touch(exist_ok=True)

def create_shortcut(
        target_path, 
        shortcut_name="TESVAE-v1.0beta", 
        args="moshortcut://:SKSE", 
        workdir=None, 
        icon_path=LOCAL_PATH_ICO
        ):
    if os.name != "nt":
        return False, "Работает только в Windows"

    try:
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        shortcut_path = os.path.join(desktop, f"{shortcut_name}.lnk")

        target_path = ensure_windows_path(target_path)
        if workdir is None:
            workdir = os.path.dirname(target_path)
        else:
            workdir = ensure_windows_path(workdir)
        if icon_path:
            icon_path = ensure_windows_path(icon_path)

        fd, vbs_path = tempfile.mkstemp(suffix=".vbs")
        os.close(fd)

        with open(vbs_path, "w", encoding="utf-8") as f:
            f.write('Set oWS = WScript.CreateObject("WScript.Shell")\n')
            f.write(f'sLinkFile = "{shortcut_path}"\n')
            f.write('Set oLink = oWS.CreateShortcut(sLinkFile)\n')
            f.write(f'oLink.TargetPath = "{target_path}"\n')
            if args:
                safe_args = args.replace('"', '""')
                f.write(f'oLink.Arguments = """{safe_args}"""\n')
            f.write(f'oLink.WorkingDirectory = "{workdir}"\n')
            if icon_path:
                f.write(f'oLink.IconLocation = "{icon_path}"\n')
            f.write("oLink.Save\n")

        subprocess.run(["cscript", "//nologo", vbs_path], check=True, timeout=30)
        os.remove(vbs_path)

        return True, f"Ярлык создан: {shortcut_path}"

    except Exception as e:
        return False, f"Ошибка: {e}"

class ThreadSafeWorker(QObject):
    """Базовый класс для потокобезопасных работников"""
    finished = pyqtSignal()
    error = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self._stop_event = threading.Event()
        self._is_paused = False
        self._resume_event = threading.Event()
        self._resume_event.set()
    
    def stop(self):
        self._stop_event.set()
        self._resume_event.set()  # Разблокировать если на паузе
    
    def pause(self):
        if not self._is_paused:
            self._resume_event.clear()
            self._is_paused = True
    
    def resume(self):
        if self._is_paused:
            self._resume_event.set()
            self._is_paused = False
    
    def _wait_if_paused(self):
        self._resume_event.wait()
    
    def _should_stop(self):
        return self._stop_event.is_set()

class UIUpdater(QObject):
    """Класс для потокобезопасного обновления UI"""
    update_log_signal = pyqtSignal(str)
    update_progress_signal = pyqtSignal(int, int, str)
    update_progress_simple_signal = pyqtSignal(int, int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        
    def setup_connections(self):
        self.update_log_signal.connect(self.parent._safe_append_log)
        self.update_progress_signal.connect(self.parent._safe_update_progress)
        self.update_progress_simple_signal.connect(self.parent._safe_update_progress_simple)

class SkyrimPatcher(ThreadSafeWorker):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int, str)
    finished_signal = pyqtSignal(bool, str)
    
    def __init__(self):
        super().__init__()
        self.temp_dir = None
        self.patcher_manifest = {}
        self.start_time = None
    
    def _quote_patcher_path(self, f: str) -> str:
        return "/".join(quote(part) for part in f.split("/"))
    
    def _calculate_eta(self, current, total, start_time):
        if current == 0:
            return "оценивается..."
        
        elapsed = time.time() - start_time
        if elapsed <= 0:
            return "оценивается..."
        
        speed = current / elapsed
        remaining = total - current
        if speed > 0:
            eta_seconds = remaining / speed
            return format_eta(eta_seconds)
        else:
            return "оценивается..."
    
    def get_steam_install_paths(self):
        steam_paths = []
        try:
            if winreg is None:
                return steam_paths
            registry_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Valve\Steam")
            ]

            for hive, path in registry_paths:
                try:
                    with winreg.OpenKey(hive, path) as key:
                        install_path, _ = winreg.QueryValueEx(key, "InstallPath")
                        if install_path and os.path.exists(install_path):
                            steam_paths.append(install_path)
                            try:
                                self.log_signal.emit(f"Найден путь Steam в реестре: {install_path}")
                            except Exception:
                                pass
                except FileNotFoundError:
                    continue
                except Exception as e:
                    try:
                        self.log_signal.emit(f"Ошибка чтения реестра: {e}")
                    except Exception:
                        pass
        except Exception as e:
            try:
                self.log_signal.emit(f"Ошибка получения путей Steam: {e}")
            except Exception:
                pass
        return steam_paths
    
    def find_skyrim_steam(self):
        self.log_signal.emit("Поиск Skyrim Special Edition...")
        
        try:
            if self._should_stop():
                self.log_signal.emit("Поиск прерван пользователем")
                return None

            steam_paths_from_registry = self.get_steam_install_paths()
            
            for steam_path in steam_paths_from_registry:
                if self._should_stop():
                    return None
                    
                libraryfolders_path = os.path.join(steam_path, "steamapps", "libraryfolders.vdf")
                if os.path.exists(libraryfolders_path):
                    self.log_signal.emit(f"Найден libraryfolders.vdf: {libraryfolders_path}")
                    
                    try:
                        with open(libraryfolders_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        try:
                            import vdf
                            data = vdf.loads(content)
                            paths = []
                            lib = data.get('libraryfolders', {}) if isinstance(data, dict) else {}
                            for k, v in lib.items():
                                if isinstance(v, dict):
                                    p = v.get('path')
                                    if p:
                                        paths.append(p)
                        except Exception:
                            import re
                            path_pattern = r'"path"\s+"([^\"]+)"'
                            paths = re.findall(path_pattern, content)
                        
                        for library_path in paths:
                            if self._should_stop():
                                return None
                                
                            library_path = library_path.replace('\\\\', '\\')
                            skyrim_path = os.path.join(library_path, "steamapps", "common", "Skyrim Special Edition", "SkyrimSE.exe")
                            if os.path.exists(skyrim_path):
                                self.log_signal.emit(f"✓ Найден Skyrim: {skyrim_path}")
                                return skyrim_path
                                
                    except Exception as e:
                        self.log_signal.emit(f"Ошибка чтения libraryfolders.vdf: {e}")
                        continue

            self.log_signal.emit("Поиск в стандартных расположениях Steam...")
            
            all_possible_steam_paths = []
            all_possible_steam_paths.extend(steam_paths_from_registry)
            
            standard_paths = [
                os.path.expanduser("~") + "\\Steam",
                "C:\\Program Files\\Steam",
                "C:\\Program Files (x86)\\Steam",
                "D:\\Steam", "E:\\Steam", "F:\\Steam", "G:\\Steam", 
                "R:\\Steam", "S:\\Steam", "T:\\Steam"
            ]
            
            for path in standard_paths:
                if path not in all_possible_steam_paths and os.path.exists(path):
                    all_possible_steam_paths.append(path)
            
            for steam_path in all_possible_steam_paths:
                if self._should_stop():
                    return None
                    
                skyrim_path = os.path.join(steam_path, "steamapps", "common", "Skyrim Special Edition", "SkyrimSE.exe")
                if os.path.exists(skyrim_path):
                    self.log_signal.emit(f"✓ Найден Skyrim: {skyrim_path}")
                    return skyrim_path
            
            self.log_signal.emit("Расширенный поиск по всем дискам...")
            
            drives = []
            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    drives.append(drive)
            
            for drive in drives:
                if self._should_stop():
                    return None
                    
                self.log_signal.emit(f"Поиск на диске {drive}...")
                
                try:
                    for root, dirs, files in os.walk(drive, topdown=True):
                        if self._should_stop():
                            return None
                        
                        current_depth = root.replace(drive, '').count(os.sep)
                        if current_depth > 2:
                            continue
                        
                        for dir_name in dirs:
                            if self._should_stop():
                                return None
                                
                            if 'steam' in dir_name.lower():
                                potential_steam_path = os.path.join(root, dir_name)
                                skyrim_path = os.path.join(potential_steam_path, "steamapps", "common", "Skyrim Special Edition", "SkyrimSE.exe")
                                if os.path.exists(skyrim_path):
                                    self.log_signal.emit(f"✓ Найден Skyrim (расширенный поиск): {skyrim_path}")
                                    return skyrim_path
                                    
                except Exception:
                    continue
            
            self.log_signal.emit("❌ Skyrim Special Edition не найден")
            return None
            
        except Exception as e:
            self.log_signal.emit(f"❌ Ошибка при поиске Skyrim: {e}")
            return None
    
    def download_patcher_manifest(self):
        try:
            if self._should_stop():
                self.log_signal.emit("Загрузка манифеста прервана")
                return False
                
            manifest_url = JSON_SERVER + "patcher_manifest.json"
            self.log_signal.emit(f"Скачивание манифеста патчера: {manifest_url}")
            
            response = requests.get(manifest_url, timeout=30)
            response.raise_for_status()
            
            self.patcher_manifest = response.json()
            
            with open(PATCHER_MANIFEST_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.patcher_manifest, f, indent=2)
            
            self.log_signal.emit(f"Манифест патчера сохранен: {PATCHER_MANIFEST_FILE}")
            return True
            
        except Exception as e:
            self.log_signal.emit(f"Ошибка загрузки манифеста патчера: {e}")
            return False
    
    def download_patcher_files(self, game_path):
        try:
            if self._should_stop():
                self.log_signal.emit("Загрузка файлов патчера прервана")
                return False
                
            if not self.patcher_manifest or "files" not in self.patcher_manifest:
                self.log_signal.emit("Манифест патчера не загружен или не содержит файлов")
                return False
            
            files = self.patcher_manifest["files"]
            total_files = len(files)
            
            if total_files == 0:
                self.log_signal.emit("Нет файлов для скачивания в манифесте")
                return True
            
            self.log_signal.emit(f"Найдено {total_files} файлов для скачивания")
            
            game_drive = os.path.splitdrive(game_path)[0] + os.sep
            self.temp_dir = os.path.join(game_drive, "temp", "skyrim_patcher")
            
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
            
            os.makedirs(self.temp_dir, exist_ok=True)
            self.log_signal.emit(f"Временная папка: {self.temp_dir}")
            
            self.start_time = time.time()
            
            success = self._download_files_parallel(files, total_files)
            
            if success:
                self.log_signal.emit("Все файлы патчера успешно скачаны и проверены")
            return success
                
        except Exception as e:
            self.log_signal.emit(f"Ошибка при скачивании патчера: {e}")
            return False

    def _download_files_parallel(self, files_dict, total_files):
        if self._should_stop():
            return False
            
        file_items = list(files_dict.items())
        
        downloaded_count = 0
        lock = threading.Lock()
        
        def download_single_file(file_name, file_hash):
            nonlocal downloaded_count
            if self._should_stop():
                return False
            
            self._wait_if_paused()
            
            expected_hash = file_hash.split(":", 1)[1] if ":" in file_hash else file_hash
            file_url = PATCHER_SERVER + self._quote_patcher_path(file_name)
            local_path = os.path.join(self.temp_dir, *file_name.split("/"))
            local_path = ensure_windows_path(local_path)  # ИСПРАВЛЕНИЕ
            
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            if os.path.exists(local_path):
                actual_hash = self._calculate_file_hash(local_path)
                if actual_hash == expected_hash:
                    with lock:
                        downloaded_count += 1
                        eta = self._calculate_eta(downloaded_count, total_files, self.start_time)
                        self.progress_signal.emit(downloaded_count, total_files, eta)
                    return True
            
            attempt = 0
            while attempt < 3:
                if self._should_stop():
                    return False
                    
                self._wait_if_paused()
                
                try:
                    response = requests.get(file_url, auth=HTTPBasicAuth(USERNAME, PASSWORD), 
                                         stream=True, timeout=(30, 300))
                    response.raise_for_status()
                    
                    with open(local_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=65536):
                            if self._should_stop():
                                return False
                            self._wait_if_paused()
                            if chunk:
                                f.write(chunk)
                    
                    actual_hash = self._calculate_file_hash(local_path)
                    if actual_hash != expected_hash:
                        self.log_signal.emit(f"Ошибка хэша для {file_name}, попытка {attempt+1}")
                        attempt += 1
                        if os.path.exists(local_path):
                            os.remove(local_path)
                        continue
                    
                    with lock:
                        downloaded_count += 1
                        eta = self._calculate_eta(downloaded_count, total_files, self.start_time)
                        self.progress_signal.emit(downloaded_count, total_files, eta)
                    
                    return True
                    
                except Exception as e:
                    self.log_signal.emit(f"Ошибка скачивания {file_name} (попытка {attempt+1}): {e}")
                    attempt += 1
                    time.sleep(1)
                    if os.path.exists(local_path):
                        try:
                            os.remove(local_path)
                        except:
                            pass
            
            return False
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {
                executor.submit(download_single_file, file_name, file_hash): (file_name, file_hash) 
                for file_name, file_hash in file_items
            }
            
            success_count = 0
            for future in concurrent.futures.as_completed(future_to_file):
                if self._should_stop():
                    for f in future_to_file.keys():
                        f.cancel()
                    break
                    
                file_name, file_hash = future_to_file[future]
                try:
                    if future.result():
                        success_count += 1
                except Exception as e:
                    self.log_signal.emit(f"Критическая ошибка для {file_name}: {e}")
            
            if self._should_stop():
                self.log_signal.emit("Загрузка файлов прервана пользователем")
                return False
                
            if success_count == total_files:
                self.log_signal.emit(f"Успешно скачано все {success_count} файлов")
                return True
            else:
                self.log_signal.emit(f"Скачано {success_count}/{total_files} файлов. Есть ошибки.")
                return False
    
    def _calculate_file_hash(self, file_path: str) -> str:
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    if self._should_stop():
                        return ""
                    self._wait_if_paused()
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            self.log_signal.emit(f"Ошибка вычисления хэша {file_path}: {e}")
            return ""
    
    def apply_patch(self, game_path):
        try:
            if self._should_stop():
                self.log_signal.emit("Применение патча прервано")
                return False
                
            if not self.temp_dir or not os.path.exists(self.temp_dir):
                self.log_signal.emit("Файлы патчера не скачаны")
                return False
            
            game_folder = os.path.dirname(game_path)
            self.log_signal.emit(f"Применение патча к: {game_folder}")
            
            copied_files = 0
            total_files = 0
            
            for root, dirs, files in os.walk(self.temp_dir):
                if self._should_stop():
                    return False
                total_files += len(files)
            
            self.start_time = time.time()
            
            for root, dirs, files in os.walk(self.temp_dir):
                for file in files:
                    if self._should_stop():
                        self.log_signal.emit("Копирование файлов прервано")
                        return False
                    
                    self._wait_if_paused()
                    
                    src_path = os.path.join(root, file)
                    rel_path = os.path.relpath(src_path, self.temp_dir)
                    dst_path = os.path.join(game_folder, *rel_path.split("\\"))  # ИСПРАВЛЕНИЕ: используем обратные слеши
                    dst_path = ensure_windows_path(dst_path)  # ИСПРАВЛЕНИЕ
                    
                    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                    
                    try:
                        with open(src_path, 'rb') as f_src, open(dst_path, 'wb') as f_dst:
                            while True:
                                if self._should_stop():
                                    self.log_signal.emit("Копирование прервано пользователем")
                                    return False
                                self._wait_if_paused()
                                chunk = f_src.read(65536)
                                if not chunk:
                                    break
                                f_dst.write(chunk)
                        
                        shutil.copystat(src_path, dst_path)
                        
                        copied_files += 1
                        eta = self._calculate_eta(copied_files, total_files, self.start_time)
                        self.progress_signal.emit(copied_files, total_files, eta)
                        
                    except Exception as e:
                        self.log_signal.emit(f"Ошибка копирования {rel_path}: {e}")
                        return False
            
            self.log_signal.emit(f"Скопировано {copied_files} файлов")
            return True
            
        except Exception as e:
            self.log_signal.emit(f"Ошибка применения патча: {e}")
            return False
    
    def revert_patch(self, game_path):
        try:
            if self._should_stop():
                self.log_signal.emit("Откат патча прерван")
                return False
                
            if not os.path.exists(PATCHER_MANIFEST_FILE):
                self.log_signal.emit("Манифест патчера не найден")
                return False
            
            with open(PATCHER_MANIFEST_FILE, 'r', encoding='utf-8') as f:
                manifest = json.load(f)
            
            if not manifest or "files" not in manifest:
                self.log_signal.emit("Манифест патчера пуст или не содержит файлов")
                return False
            
            files = manifest["files"]
            game_folder = os.path.dirname(game_path)
            self.log_signal.emit(f"Откат патча из: {game_folder}")
            
            removed_files = 0
            total_files = len(files)
            
            self.start_time = time.time()
            
            for file_name in files:
                if self._should_stop():
                    self.log_signal.emit("Откат патча прерван")
                    return False
                
                self._wait_if_paused()
                
                # Исправление: правильное формирование пути
                file_path = os.path.join(game_folder, *file_name.split("/"))
                file_path = ensure_windows_path(file_path)  # ИСПРАВЛЕНИЕ
                    
                if os.path.exists(file_path):
                    success = False
                    
                    for attempt in range(3):
                        if self._should_stop():
                            return False
                        try:
                            reset_file_attributes(file_path)  # ИСПРАВЛЕНИЕ
                            
                            if os.name == 'nt':
                                try:
                                    file_attr = os.stat(file_path).st_file_attributes
                                    if file_attr & stat.FILE_ATTRIBUTE_READONLY:
                                        os.chmod(file_path, stat.S_IWRITE)
                                except:
                                    pass
                            
                            os.remove(file_path)
                            success = True
                            break
                        except PermissionError:
                            time.sleep(1)
                            continue
                        except Exception as e:
                            self.log_signal.emit(f"Ошибка удаления {file_name}: {e}")
                            break
                    
                    if success:
                        removed_files += 1
                        eta = self._calculate_eta(removed_files, total_files, self.start_time)
                        self.progress_signal.emit(removed_files, total_files, eta)
                    else:
                        self.log_signal.emit(f"Не удалось удалить файл (заблокирован): {file_name}")
            
            # Исправление: правильное удаление пустых папок
            try:
                for root, dirs, files in os.walk(game_folder, topdown=False):
                    for dir_name in dirs:
                        if self._should_stop():
                            return False
                        dir_path = os.path.join(root, dir_name)
                        try:
                            if not os.listdir(dir_path):
                                if os.name == 'nt':
                                    try:
                                        os.chmod(dir_path, stat.S_IWRITE)
                                    except:
                                        pass
                                os.rmdir(dir_path)
                                self.log_signal.emit(f"Удалена пустая папка: {os.path.relpath(dir_path, game_folder)}")
                        except:
                            pass
            except Exception as e:
                self.log_signal.emit(f"Ошибка очистки пустых папок: {e}")
            
            try:
                if os.path.exists(PATCHER_MANIFEST_FILE):
                    os.remove(PATCHER_MANIFEST_FILE)
                    self.log_signal.emit("Манифест патчера удален")
            except Exception as e:
                self.log_signal.emit(f"Ошибка удаления манифеста: {e}")
            
            self.log_signal.emit(f"Откат завершен. Удалено {removed_files} файлов")
            return True
            
        except Exception as e:
            self.log_signal.emit(f"Ошибка отката патча: {e}")
            return False
    
    def update_modorganizer_ini(self, mo_folder, game_folder):
        try:
            ini_path = os.path.join(mo_folder, "ModOrganizer.ini")
            ini_path = ensure_windows_path(ini_path)  # ИСПРАВЛЕНИЕ
            if not os.path.exists(ini_path):
                self.log_signal.emit(f"Файл ModOrganizer.ini не найден по пути: {ini_path}")
                return False
            
            self.log_signal.emit("Обновление ModOrganizer.ini...")
            
            un_path_game_folder = normalize_path(game_folder)
            dub_path_game_folder = game_folder.replace("\\", "\\\\")
            
            with open(ini_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            content = content.replace(
                "D:/SteamLibrary/steamapps/common/Skyrim Special Edition", 
                un_path_game_folder
            )
            content = content.replace(
                "D:\\\\SteamLibrary\\\\steamapps\\\\common\\\\Skyrim Special Edition", 
                dub_path_game_folder
            )
            
            with open(ini_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.log_signal.emit("ModOrganizer.ini успешно обновлен")
            return True
            
        except Exception as e:
            self.log_signal.emit(f"Ошибка обновления ModOrganizer.ini: {e}")
            return False
    
    def run_patch(self):
        try:
            game_path = self.find_skyrim_steam()
            if self._should_stop():
                self.finished_signal.emit(False, "")
                return
                
            if not game_path:
                self.log_signal.emit("Skyrim Special Edition не найден")
                self.finished_signal.emit(False, "")
                return
            
            if not self.download_patcher_manifest():
                self.finished_signal.emit(False, game_path)
                return
            
            if not self.download_patcher_files(game_path):
                self.finished_signal.emit(False, game_path)
                return
            
            if not self.apply_patch(game_path):
                self.finished_signal.emit(False, game_path)
                return
            
            if self.temp_dir and os.path.exists(self.temp_dir):
                try:
                    shutil.rmtree(self.temp_dir)
                    self.log_signal.emit("Временные файлы удалены")
                except Exception as e:
                    self.log_signal.emit(f"Ошибка удаления временных файлов: {e}")
            
            self.log_signal.emit("Патчинг завершен успешно!")
            self.finished_signal.emit(True, game_path)
            
        except Exception as e:
            self.log_signal.emit(f"Критическая ошибка: {e}")
            if self.temp_dir and os.path.exists(self.temp_dir):
                try:
                    shutil.rmtree(self.temp_dir)
                except:
                    pass
            self.finished_signal.emit(False, "")
    
    def run_revert(self):
        try:
            game_path = self.find_skyrim_steam()
            if self._should_stop():
                self.finished_signal.emit(False, "")
                return
                
            if not game_path:
                self.log_signal.emit("Skyrim Special Edition не найден")
                self.finished_signal.emit(False, "")
                return
            
            if not self.revert_patch(game_path):
                self.finished_signal.emit(False, game_path)
                return
            
            self.log_signal.emit("Откат патча завершен успешно!")
            self.finished_signal.emit(True, game_path)
            
        except Exception as e:
            self.log_signal.emit(f"Критическая ошибка: {e}")
            self.finished_signal.emit(False, "")

class VersionManager(ThreadSafeWorker):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int)
    finished_signal = pyqtSignal(bool, str)
    versions_loaded_signal = pyqtSignal(list)
    
    def __init__(self, local_dir: str):
        super().__init__()
        self.local_dir = local_dir
        self.versions_cache = {}
        self.data_lock = threading.Lock()
        self.config = {}
        self.progress_data = {}
    
    def load_versions(self):
        try:
            self.log_signal.emit("Загрузка списка версий...")
            
            patch_list_url = JSON_SERVER + "patch-list.json"
            response = requests.get(patch_list_url, timeout=30)
            response.raise_for_status()
            patch_files = response.json()
            
            versions = []
            for patch_file in patch_files:
                try:
                    if self._should_stop():
                        self.log_signal.emit("Загрузка версий прервана")
                        break
                    patch_url = JSON_SERVER + patch_file
                    patch_response = requests.get(patch_url, timeout=30)
                    patch_response.raise_for_status()
                    patch_data = patch_response.json()
                    
                    version = patch_data.get("new_version")
                    if version:
                        with self.data_lock:
                            self.versions_cache[version] = patch_data
                        versions.append(version)
                        self.log_signal.emit(f"Загружена версия: {version}")
                    
                except Exception as e:
                    self.log_signal.emit(f"Ошибка загрузки патча {patch_file}: {e}")
            
            versions.sort(reverse=True)
            self.versions_loaded_signal.emit(versions)
            self.log_signal.emit(f"Загружено {len(versions)} версий")
            return True
            
        except Exception as e:
            self.log_signal.emit(f"Ошибка загрузки списка версий: {e}")
            self.versions_loaded_signal.emit([])
            return False
    
    def get_latest_version(self):
        try:
            latest_url = JSON_SERVER + "patch-latest.json"
            response = requests.get(latest_url, timeout=30)
            response.raise_for_status()
            latest_data = response.json()
            return latest_data.get("new_version")
        except Exception as e:
            self.log_signal.emit(f"Ошибка получения последней версии: {e}")
            return None

class VerifyWorker(ThreadSafeWorker):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int, str)
    finished_signal = pyqtSignal(bool, int, int, int)
    
    def __init__(self, local_dir: str, progress_data: dict):
        super().__init__()
        self.local_dir = local_dir
        self.progress_data = progress_data
        self.start_time = None

    def run(self):
        try:
            QMetaObject.invokeMethod(
                self, "_safe_start_verify",
                Qt.ConnectionType.QueuedConnection
            )
        except Exception as e:
            self.log_signal.emit(f"Ошибка запуска проверки: {e}")
            self.finished_signal.emit(False, 0, 0, 0)

    @pyqtSlot()
    def _safe_start_verify(self):
        """Запуск проверки с сигналом от Qt"""
        self.log_signal.emit("Начинаем проверку файлов...")
        self._verify_implementation()

    def _verify_implementation(self):
        """Основная логика проверки файлов"""
        try:
            self.log_signal.emit("Начинаем проверку файлов...")

            # Скачиваем manifest.json
            try:
                r = requests.get(JSON_SERVER + "manifest.json", timeout=60)
                r.raise_for_status()
                manifest = r.json()
            except Exception as e:
                self.log_signal.emit(f"Ошибка загрузки manifest.json: {e}")
                self.finished_signal.emit(False, 0, 0, 0)
                return

            if "files" not in manifest:
                self.log_signal.emit("Нет файлов в manifest.json")
                self.finished_signal.emit(False, 0, 0, 0)
                return

            server_files = manifest["files"]
            total_files = len(server_files)
            self.log_signal.emit(f"Проверяем {total_files} файлов...")

            files_deleted = 0
            if "downloads" not in self.progress_data:
                self.progress_data["downloads"] = {}

            # Удаляем лишние файлы
            self.log_signal.emit("Поиск лишних файлов...")
            for root, dirs, files in os.walk(self.local_dir):
                if self._should_stop():
                    self.log_signal.emit("Проверка прервана пользователем")
                    self.finished_signal.emit(False, 0, 0, 0)
                    return

                for fname in files:
                    if self._should_stop():
                        self.log_signal.emit("Проверка прервана пользователем")
                        self.finished_signal.emit(False, 0, 0, 0)
                        return

                    self._wait_if_paused()
                    abs_path = os.path.join(root, fname)
                    rel_path = normalize_path(os.path.relpath(abs_path, self.local_dir))

                    if rel_path not in server_files:
                        try:
                            reset_file_attributes(abs_path)
                            if os.name == 'nt':
                                try:
                                    file_attr = os.stat(abs_path).st_file_attributes
                                    if file_attr & stat.FILE_ATTRIBUTE_READONLY:
                                        os.chmod(abs_path, stat.S_IWRITE)
                                except:
                                    pass
                            os.remove(abs_path)
                            files_deleted += 1
                        except Exception as e:
                            self.log_signal.emit(f"Не удалось удалить {rel_path}: {e}")

            # Проверяем существующие файлы по хэшам
            self.log_signal.emit("Многопоточная проверка хэшей файлов...")
            self.start_time = time.time()
            success = self._verify_files_parallel(server_files, total_files)

            if success:
                files_to_download = len(self.progress_data.get("downloads", {}))
                self.log_signal.emit(f"Нужно скачать {files_to_download} файлов.")

                with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
                    json.dump(self.progress_data, f, indent=2)

                self.log_signal.emit("Проверка завершена успешно")
                self.finished_signal.emit(True, files_to_download, 0, files_deleted)
            else:
                self.finished_signal.emit(False, 0, 0, 0)

        except Exception as e:
            self.log_signal.emit(f"Ошибка при проверке файлов: {e}")
            self.finished_signal.emit(False, 0, 0, 0)

    def _verify_files_parallel(self, server_files, total_files):
        """Проверка файлов в несколько потоков"""
        if self._should_stop():
            return False

        checked_count = 0
        lock = threading.Lock()

        def verify_single_file(file_info):
            nonlocal checked_count
            if self._should_stop():
                return

            self._wait_if_paused()
            rel_path, hash_full = file_info
            normalized_rel_path = normalize_path(rel_path)
            local_path = os.path.join(self.local_dir, *normalized_rel_path.split("/"))
            local_path = ensure_windows_path(local_path)

            if not os.path.exists(local_path):
                with lock:
                    self.progress_data.setdefault("downloads", {})[normalized_rel_path] = 0
                    checked_count += 1
                    if checked_count % 100 == 0:
                        eta = self._calculate_eta(checked_count, total_files, self.start_time)
                        self.progress_signal.emit(checked_count, total_files, eta)
                return

            reset_file_attributes(local_path)
            expected_hash = hash_full.split(":", 1)[1] if ":" in hash_full else hash_full
            actual_hash = self._calculate_file_hash(local_path)

            with lock:
                if actual_hash != expected_hash:
                    self.progress_data.setdefault("downloads", {})[normalized_rel_path] = 0
                else:
                    self.progress_data.setdefault("completed", []).append(normalized_rel_path)
                    if "downloads" in self.progress_data and normalized_rel_path in self.progress_data["downloads"]:
                        del self.progress_data["downloads"][normalized_rel_path]

                checked_count += 1
                if checked_count % 100 == 0:
                    eta = self._calculate_eta(checked_count, total_files, self.start_time)
                    self.progress_signal.emit(checked_count, total_files, eta)

        file_items = list(server_files.items())
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            batch_size = BATCH_SIZE
            for i in range(0, len(file_items), batch_size):
                if self._should_stop():
                    break
                batch = file_items[i:i + batch_size]
                list(executor.map(verify_single_file, batch))

        self.progress_signal.emit(total_files, total_files, "00:00")
        return True

    def _calculate_file_hash(self, file_path: str) -> str:
        """Вычисление SHA256-хэша"""
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    if self._should_stop():
                        return ""
                    self._wait_if_paused()
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _calculate_eta(self, current, total, start_time):
        """Вычисление ETA"""
        if current == 0:
            return "оценивается..."
        elapsed = time.time() - start_time
        if elapsed <= 0:
            return "оценивается..."
        speed = current / elapsed
        remaining = total - current
        if speed > 0:
            eta_seconds = remaining / speed
            return format_eta(eta_seconds)
        else:
            return "оценивается..."


class DownloadWorker(ThreadSafeWorker):
    log_signal = pyqtSignal(str)
    progress_total_setmax_signal = pyqtSignal(int)
    progress_total_signal = pyqtSignal(int)
    current_file_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool)

    def __init__(self, task: dict, state_refs: dict):
        super().__init__()
        self.task = task
        self.refs = state_refs
        self._attempt_limit = 7  # Увеличили количество попыток
        self._overall_start_time = None
        
        self.session = requests.Session()
        
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        # Улучшенная стратегия повторных попыток
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,  # Увеличили backoff factor
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"]
        )
        
        adapter = HTTPAdapter(
            pool_connections=MAX_WORKERS,
            pool_maxsize=MAX_WORKERS,
            max_retries=retry_strategy
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Увеличим общие таймауты для сессии
        self.session.timeout = (30, 300)  # connect timeout, read timeout

    def _log(self, msg: str):
        self.log_signal.emit(msg)

    def _save_progress_atomic(self):
        lock = self.refs["data_lock"]
        with lock:
            try:
                with open(PROGRESS_FILE, "w", encoding="utf-8") as pf:
                    json.dump(self.refs["progress_data"], pf, indent=2)
            except Exception as e:
                self._log(f"Ошибка записи прогресса: {e}")

    def _save_config_atomic(self):
        lock = self.refs["data_lock"]
        with lock:
            try:
                with open(CONFIG_FILE, "w", encoding="utf-8") as cf:
                    json.dump(self.refs["config"], cf, indent=2)
            except Exception as e:
                self._log(f"Ошибка сохранения конфигурации: {e}")

    def _file_hash(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                if self._should_stop():
                    return ""
                self._wait_if_paused()
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _quote_path(self, f: str) -> str:
        return "/".join(quote(part) for part in f.split("/"))

    def _calculate_optimal_threads(self):
        try:
            result = subprocess.run(
                ['ping', '-n', '1', 'nethunter.sytes.net'] if os.name == 'nt' else ['ping', '-c', '1', 'nethunter.sytes.net'],
                capture_output=True, text=True, timeout=5
            )
            if 'time=' in result.stdout or 'time<' in result.stdout:
                base_threads = 4  # Уменьшили базое количество потоков
                if any(x in result.stdout for x in ['time=100', 'time=200']):
                    base_threads = min(8, base_threads + 2)  # Уменьшили максимальное количество
                return base_threads
        except:
            pass
        return min(MAX_WORKERS, 8)  # Ограничиваем максимальное количество потоков

    def _download_file(self, f_rel: str, url: str, local_path: str, hash_full: str, idx: int, total_files: int, auth=None):
        if self._should_stop():
            return False
            
        refs = self.refs
        local_dir = refs.get("local_dir") or (refs.get("config") or {}).get("local_dir")
        if not local_dir:
            self._log("Локальная папка не указана (local_dir). Отмена.")
            self.finished_signal.emit(False)
            return
        
        # Создаем директорию если нужно
        try:
            dir_path = os.path.dirname(local_path)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
                # Устанавливаем правильные права для новой директории
                if os.name == 'nt':
                    try:
                        os.chmod(dir_path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
                    except:
                        pass
        except Exception as e:
            self._log(f"Ошибка создания директории {os.path.dirname(local_path)}: {e}")
            return False

        with refs["data_lock"]:
            downloaded = int(refs["progress_data"].get("downloads", {}).get(f_rel, 0) or 0)

        headers = {}
        mode = 'wb'
        if downloaded > 0 and os.path.exists(local_path):
            # Проверяем, не поврежден ли частично загруженный файл
            try:
                current_size = os.path.getsize(local_path)
                if current_size > 0:
                    headers['Range'] = f'bytes={downloaded}-'
                    mode = 'ab'
                else:
                    # Файл нулевого размера - перезаписываем
                    downloaded = 0
                    mode = 'wb'
            except:
                downloaded = 0
                mode = 'wb'
        else:
            downloaded = 0
            mode = 'wb'

        attempt = 0
        last_save_time = time.time()
        success = False
        
        # Определяем таймауты в зависимости от попытки
        def get_timeout(attempt_num):
            base_timeout = (30, 60)  # connect, read
            if attempt_num > 2:
                return (30, 120)  # Увеличиваем read timeout для повторных попыток
            return base_timeout
        
        while attempt < self._attempt_limit:
            attempt += 1
            self._wait_if_paused()
            if self._should_stop():
                with refs["data_lock"]:
                    refs["progress_data"].setdefault("downloads", {})[f_rel] = downloaded
                self._save_progress_atomic()
                return False
                
            try:
                timeout_config = get_timeout(attempt)
                
                if auth is not None:
                    resp = self.session.get(url, auth=auth, headers=headers, stream=True, timeout=timeout_config)
                else:
                    resp = self.session.get(url, headers=headers, stream=True, timeout=timeout_config)

                if 'Range' in headers and resp.status_code == 200:
                    self._log(f"Сервер не поддерживает Range для {f_rel} — перезапись с нуля.")
                    downloaded = 0
                    headers.pop('Range', None)
                    mode = 'wb'

                # Проверяем статус ответа
                if resp.status_code not in [200, 206]:
                    self._log(f"Сервер вернул статус {resp.status_code} для {f_rel}")
                    if attempt >= self._attempt_limit:
                        break
                    time.sleep(min(10, 3 ** attempt))  # Экспоненциальная задержка с ограничением
                    continue

                content_length = resp.headers.get("Content-Length")
                try:
                    remaining = int(content_length) if content_length is not None else 0
                except Exception:
                    remaining = 0
                
                # Если мы возобновляем загрузку, корректируем оставшийся размер
                if 'Range' in headers and resp.status_code == 206:
                    total_size = remaining + downloaded
                else:
                    total_size = remaining if remaining > 0 else 0

                chunk_start_time = time.time()
                downloaded_since_start = 0
                last_progress_update = time.time()
                
                with open(local_path, mode) as out:
                    for chunk in resp.iter_content(chunk_size=8192):
                        self._wait_if_paused()
                        if self._should_stop():
                            with refs["data_lock"]:
                                refs["progress_data"].setdefault("downloads", {})[f_rel] = downloaded
                            self._save_progress_atomic()
                            return False
                        if not chunk:
                            continue
                        out.write(chunk)
                        out.flush()  # Принудительно записываем на диск
                        
                        chunk_size = len(chunk)
                        downloaded += chunk_size
                        downloaded_since_start += chunk_size

                        # Сохраняем прогресс каждые 2 секунды или 1MB
                        current_time = time.time()
                        if current_time - last_save_time > 2 or downloaded_since_start > 1024*1024:
                            with refs["data_lock"]:
                                refs["progress_data"].setdefault("downloads", {})[f_rel] = downloaded
                            self._save_progress_atomic()
                            last_save_time = current_time
                            downloaded_since_start = 0

                        # Обновляем прогресс в UI не чаще чем раз в 0.5 секунды
                        if current_time - last_progress_update > 0.5:
                            elapsed = time.time() - chunk_start_time
                            download_speed = downloaded_since_start / elapsed / 1024 / 1024 if elapsed > 0 else 0

                            overall_start = getattr(self, "_overall_start_time", None)
                            elapsed_total = time.time() - overall_start if overall_start else 0

                            done_files = idx - 1
                            avg_per_file = elapsed_total / done_files if done_files > 0 else elapsed_total
                            files_left = max(0, total_files - idx)

                            if total_size > 0 and download_speed > 0:
                                download_speed_bps = download_speed * 1024 * 1024
                                time_left_current = max(0.0, (total_size - downloaded) / download_speed_bps)
                            else:
                                time_left_current = 0.0

                            eta_seconds = int(time_left_current + avg_per_file * files_left)
                            eta_seconds = max(0, eta_seconds)
                            eta_str = format_eta(eta_seconds)

                            if total_files > 0:
                                if total_size > 0:
        # знаем размер файла → считаем долю файла
                                    fraction = downloaded / total_size
                                else:
        # сервер не сообщил размер файла → учитываем только номер файла
                                    fraction = 0.0
                                overall_percent = int(((idx - 1) + fraction) / total_files * 100)
                                overall_percent = max(0, min(100, overall_percent))
                            else:
                                overall_percent = 0

                            progress_str = f"{overall_percent}% - TF: {idx}/{total_files} файлов - DS: {download_speed:.2f}MB/s ETA: {eta_str}"
                            self.current_file_signal.emit(progress_str)
                            last_progress_update = current_time

                # Проверяем хэш файла
                expected_hash = hash_full.split(":", 1)[1] if ":" in hash_full else hash_full
                try:
                    actual_hash = self._file_hash(local_path)
                except Exception as e:
                    self._log(f"Ошибка вычисления хэша для {f_rel}: {e}")
                    actual_hash = None
                
                if actual_hash != expected_hash:
                    self._log(f"Ошибка хэша: {f_rel}, ожидалось {expected_hash}, получено {actual_hash}.")
                    
                    # Сбрасываем атрибуты файла перед удалением
                    reset_file_attributes(local_path)
                    
                    if attempt >= self._attempt_limit:
                        self._log(f"Достигнут лимит попыток для {f_rel}. Пропускаем.")
                        with refs["data_lock"]:
                            refs["progress_data"].setdefault("downloads", {})[f_rel] = 0
                        self._save_progress_atomic()
                        break
                    else:
                        try:
                            # Удаляем файл с повторными попытками
                            for delete_attempt in range(3):
                                try:
                                    if os.path.exists(local_path):
                                        reset_file_attributes(local_path)
                                        os.remove(local_path)
                                    break
                                except PermissionError:
                                    if delete_attempt < 2:
                                        time.sleep(1)
                                        continue
                                    else:
                                        self._log(f"Не удалось удалить файл {f_rel} (заблокирован)")
                                        raise
                        except Exception as e:
                            self._log(f"Ошибка удаления {f_rel}: {e}")
                        
                        with refs["data_lock"]:
                            refs["progress_data"].setdefault("downloads", {})[f_rel] = 0
                        headers.pop('Range', None)
                        downloaded = 0
                        mode = 'wb'
                        self._log(f"Повторная попытка {attempt}/{self._attempt_limit} для {f_rel}")
                        time.sleep(min(10, 3 ** attempt))  # Экспоненциальная задержка с ограничением
                        continue

                # Файл успешно загружен и проверен
                with refs["data_lock"]:
                    refs["progress_data"].setdefault("completed", []).append(f_rel)
                    if f_rel in refs["progress_data"].get("downloads", {}):
                        del refs["progress_data"]["downloads"][f_rel]
                self._save_progress_atomic()
                self.progress_total_signal.emit(idx)
                success = True
                break

            except requests.exceptions.Timeout as e:
                self._log(f"Таймаут при загрузке {f_rel} (попытка {attempt}): {e}")
                if attempt >= self._attempt_limit:
                    self._log(f"Достигнут лимит попыток для {f_rel} из-за таймаутов. Пропускаем.")
                    with refs["data_lock"]:
                        refs["progress_data"].setdefault("downloads", {})[f_rel] = downloaded
                    self._save_progress_atomic()
                    break
                else:
                    time.sleep(min(10, 3 ** attempt))  # Экспоненциальная задержка с ограничением
                    continue
                    
            except requests.exceptions.ConnectionError as e:
                self._log(f"Ошибка соединения для {f_rel} (попытка {attempt}): {e}")
                if attempt >= self._attempt_limit:
                    self._log(f"Достигнут лимит попыток для {f_rel} из-за ошибок соединения. Пропускаем.")
                    with refs["data_lock"]:
                        refs["progress_data"].setdefault("downloads", {})[f_rel] = downloaded
                    self._save_progress_atomic()
                    break
                else:
                    time.sleep(min(10, 3 ** attempt))  # Экспоненциальная задержка с ограничением
                    continue
                    
            except Exception as e:
                self._log(f"Ошибка загрузки {f_rel} (попытка {attempt}): {e}")
                if attempt >= self._attempt_limit:
                    self._log(f"Достигнут лимит попыток для {f_rel}. Пропускаем.")
                    with refs["data_lock"]:
                        refs["progress_data"].setdefault("downloads", {})[f_rel] = downloaded
                    self._save_progress_atomic()
                    break
                else:
                    time.sleep(min(10, 3 ** attempt))  # Экспоненциальная задержка с ограничением
                    continue

        return success

    def run(self):
        try:
            self._overall_start_time = time.time()
            refs = self.refs
            local_dir = refs.get("local_dir") or refs.get("config", {}).get("local_dir")

            if not local_dir:
                self._log("Ошибка: локальная папка не указана")
                self.finished_signal.emit(False)
                return

            manifest_url = JSON_SERVER + "manifest.json"
            auth = HTTPBasicAuth(USERNAME, PASSWORD) if self.task.get("use_dav", False) else None


            self._log(f"Загружаем манифест: {manifest_url}")
            
            # Загрузка манифеста с повторными попытками
            manifest = None
            for attempt in range(3):
                try:
                    r = self.session.get(manifest_url, auth=auth, timeout=60)
                    r.raise_for_status()
                    manifest = r.json()
                    break
                except Exception as e:
                    self._log(f"Ошибка загрузки манифеста (попытка {attempt+1}): {e}")
                    if attempt < 2:
                        time.sleep(2)
                    else:
                        self._log("Не удалось загрузить манифест после 3 попыток")
                        self.finished_signal.emit(False)
                        return

            if "files" not in manifest:
                self._log("Нет файлов в манифесте.")
                self.finished_signal.emit(False)
                return

            server_files = manifest["files"]
            #total_files = len(server_files)
            #self.progress_total_setmax_signal.emit(total_files)

            files_to_download = []
            
            downloads_from_progress = refs["progress_data"].get("downloads", {})
            if downloads_from_progress:
                self._log(f"Найдено {len(downloads_from_progress)} файлов для загрузки из данных проверки")
                for f_rel in downloads_from_progress.keys():
                    if f_rel in server_files:
                        hash_full = server_files[f_rel]
                        local_path = os.path.join(local_dir, *f_rel.split("/"))
                        local_path = ensure_windows_path(local_path)  # ИСПРАВЛЕНИЕ
                        files_to_download.append((f_rel, hash_full, local_path))
            else:
                for f_rel, hash_full in server_files.items():
                    if self._should_stop():
                        self._log("Загрузка прервана пользователем")
                        self.finished_signal.emit(False)
                        return
                    local_path = os.path.join(local_dir, *f_rel.split("/"))
                    local_path = ensure_windows_path(local_path)  # ИСПРАВЛЕНИЕ
                    if f_rel not in refs["progress_data"].get("completed", []):
                        files_to_download.append((f_rel, hash_full, local_path))

            if not files_to_download:
                # Устанавливаем реальное количество файлов для загрузки
                total_files = len(files_to_download)
                self.progress_total_setmax_signal.emit(total_files)
                self._log(f"Файлов для загрузки: {total_files}")
                self._log("Все файлы уже загружены.")
                self.finished_signal.emit(True)
                return

            #self._log(f"Файлов для загрузки: {len(files_to_download)}")

            # Уменьшаем количество потоков для стабильности
            optimal_threads = min(4, self._calculate_optimal_threads())
            self._log(f"Оптимальное количество потоков: {optimal_threads}")

            # Сортируем файлы по размеру (сначала маленькие)
            def estimate_file_size(f_rel):
                # Эвристика: пути с текстурами и мешами обычно большие
                if any(x in f_rel.lower() for x in ['textures', 'meshes', 'dyndolod']):
                    return 2  # Большие файлы
                return 1  # Маленькие файлы
            
            files_to_download.sort(key=lambda x: estimate_file_size(x[0]))

            total_files = len(files_to_download)
            self.progress_total_setmax_signal.emit(total_files)
            self._log(f"Файлов для загрузки: {total_files}")

            semaphore = Semaphore(optimal_threads)
            failed_files = []
            lock = threading.Lock()

            def process_file(f_rel, hash_full, local_path, idx):
                if self._should_stop():
                    return False
                with semaphore:
                    if self._should_stop():
                        return False
                    url = self.task.get("base_url", DAV_SERVER if self.task.get("use_dav", False) else JSON_SERVER)
                    if self.task.get("use_dav", False):
                        url += self._quote_path(f_rel)
                    else:
                        url += f_rel
                    result = self._download_file(f_rel, url, local_path, hash_full, idx, total_files, auth=auth)
                    if not result:
                        with lock:
                            failed_files.append(f_rel)
                    return result

            with concurrent.futures.ThreadPoolExecutor(max_workers=optimal_threads) as executor:
                futures = {
                    executor.submit(process_file, f_rel, hash_full, local_path, idx): (f_rel, idx)
                    for idx, (f_rel, hash_full, local_path) in enumerate(files_to_download, 1)
                }
                for future in concurrent.futures.as_completed(futures):
                    if self._should_stop():
                        for f in futures.keys():
                            f.cancel()
                        self._log("Загрузка прервана пользователем")
                        break
                    f_rel, idx = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        self._log(f"Ошибка при загрузке {f_rel}: {e}")
                        with lock:
                            failed_files.append(f_rel)

            if self._should_stop():
                self._log("Загрузка прервана пользователем")
                self.finished_signal.emit(False)
                return

            if failed_files:
                self._log(f"Не удалось загрузить {len(failed_files)} файлов:")
                # Показываем только первые 10 файлов чтобы не засорять лог
                for f in failed_files[:10]:
                    self._log(f"  {f}")
                if len(failed_files) > 10:
                    self._log(f"  ... и еще {len(failed_files) - 10} файлов")
                self.finished_signal.emit(False)
            else:
                self._log("Все файлы успешно загружены.")
                with refs["data_lock"]:
                    if "downloads" in refs["progress_data"]:
                        refs["progress_data"]["downloads"] = {}
                self._save_progress_atomic()
                
                self._log("Настройка ModOrganizer.ini...")
                ini_success = self._configure_modorganizer_ini(local_dir)
                if ini_success:
                    self._log("ModOrganizer.ini успешно настроен")
                else:
                    self._log("Не удалось настроить ModOrganizer.ini")
                
                self.finished_signal.emit(True)

        except Exception as e:
            self._log(f"Ошибка в процессе загрузки: {e}")
            self.finished_signal.emit(False)
    
    def _configure_modorganizer_ini(self, local_dir):
        try:
            self._log("Поиск Skyrim Special Edition...")
            game_path = self._find_skyrim_steam()
            if not game_path:
                self._log("Skyrim не найден, пропускаем настройку INI")
                return False
            
            game_folder = os.path.dirname(game_path)
            ini_path = os.path.join(local_dir, "ModOrganizer.ini")
            ini_path = ensure_windows_path(ini_path)  # ИСПРАВЛЕНИЕ
            
            if not os.path.exists(ini_path):
                self._log(f"ModOrganizer.ini не найден по пути: {ini_path}")
                return False
            
            self._log("Обновление путей в ModOrganizer.ini...")
            
            un_path_game_folder = normalize_path(game_folder)
            dub_path_game_folder = game_folder.replace("\\", "\\\\")
            
            with open(ini_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            content = content.replace(
                "D:/SteamLibrary/steamapps/common/Skyrim Special Edition", 
                un_path_game_folder
            )
            content = content.replace(
                "D:\\\\SteamLibrary\\\\steamapps\\\\common\\\\Skyrim Special Edition", 
                dub_path_game_folder
            )
            
            with open(ini_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return True
            
        except Exception as e:
            self._log(f"Ошибка настройки ModOrganizer.ini: {e}")
            return False

    def get_steam_install_paths(self):
        steam_paths = []
        try:
            if winreg is None:
                return steam_paths
            registry_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Valve\Steam")
            ]

            for hive, path in registry_paths:
                try:
                    with winreg.OpenKey(hive, path) as key:
                        install_path, _ = winreg.QueryValueEx(key, "InstallPath")
                        if install_path and os.path.exists(install_path):
                            steam_paths.append(install_path)
                except FileNotFoundError:
                    continue
                except Exception as e:
                    pass
        except Exception as e:
            pass
        return steam_paths

    def _find_skyrim_steam(self):
        try:
            if self._should_stop():
                return None

            steam_paths_from_registry = self.get_steam_install_paths()
            
            for steam_path in steam_paths_from_registry:
                if self._should_stop():
                    return None
                    
                libraryfolders_path = os.path.join(steam_path, "steamapps", "libraryfolders.vdf")
                if os.path.exists(libraryfolders_path):
                    try:
                        with open(libraryfolders_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        try:
                            import vdf
                            data = vdf.loads(content)
                            paths = []
                            lib = data.get('libraryfolders', {}) if isinstance(data, dict) else {}
                            for k, v in lib.items():
                                if isinstance(v, dict):
                                    p = v.get('path')
                                    if p:
                                        paths.append(p)
                        except Exception:
                            import re
                            path_pattern = r'"path"\s+"([^\"]+)"'
                            paths = re.findall(path_pattern, content)
                        
                        for library_path in paths:
                            if self._should_stop():
                                return None
                                
                            library_path = library_path.replace('\\\\', '\\')
                            skyrim_path = os.path.join(library_path, "steamapps", "common", "Skyrim Special Edition", "SkyrimSE.exe")
                            if os.path.exists(skyrim_path):
                                return skyrim_path
                                
                    except Exception:
                        continue

            all_possible_steam_paths = []
            all_possible_steam_paths.extend(steam_paths_from_registry)
            
            standard_paths = [
                os.path.expanduser("~") + "\\Steam",
                "C:\\Program Files\\Steam",
                "C:\\Program Files (x86)\\Steam",
                "D:\\Steam", "E:\\Steam", "F:\\Steam", "G:\\Steam", 
                "R:\\Steam", "S:\\Steam", "T:\\Steam"
            ]
            
            for path in standard_paths:
                if path not in all_possible_steam_paths and os.path.exists(path):
                    all_possible_steam_paths.append(path)
            
            for steam_path in all_possible_steam_paths:
                if self._should_stop():
                    return None
                    
                skyrim_path = os.path.join(steam_path, "steamapps", "common", "Skyrim Special Edition", "SkyrimSE.exe")
                if os.path.exists(skyrim_path):
                    return skyrim_path
            
            drives = []
            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    drives.append(drive)
            
            for drive in drives:
                if self._should_stop():
                    return None
                    
                try:
                    for root, dirs, files in os.walk(drive, topdown=True):
                        if self._should_stop():
                            return None
                        
                        current_depth = root.replace(drive, '').count(os.sep)
                        if current_depth > 2:
                            continue
                        
                        for dir_name in dirs:
                            if self._should_stop():
                                return None
                                
                            if 'steam' in dir_name.lower():
                                potential_steam_path = os.path.join(root, dir_name)
                                skyrim_path = os.path.join(potential_steam_path, "steamapps", "common", "Skyrim Special Edition", "SkyrimSE.exe")
                                if os.path.exists(skyrim_path):
                                    return skyrim_path
                                    
                except Exception:
                    continue
            
            return None
            
        except Exception:
            return None

class UpdaterUI(QWidget):
    def _append_log(self, message):
        try:
            if message is None:
                message = ""
            # Используем invokeMethod для потокобезопасного обновления UI
            QMetaObject.invokeMethod(self.log, "append", Qt.ConnectionType.QueuedConnection, Q_ARG(str, str(message)))
        except Exception as e:
            print(f"Ошибка добавления в лог: {e}")

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Skyrim MO2 Updater + Patcher 18.5.5.3")  # Обновили версию
        self.resize(760, 420)

        # flags
        self.is_installing = False
        self.is_verifying = False
        self.is_patching = False
        self._full_local_path = "Не выбрана"
        self._full_version_text = "не установлена"
        self._is_closing = False  # Флаг закрытия приложения

         # иконка
        icon_path_app = getattr(sys, '_MEIPASS', os.path.dirname(__file__))
        try:
            self.setWindowIcon(QIcon(os.path.join(icon_path_app, "icon.ico")))
        except Exception:
            pass

        # theme
        self.current_theme = "light"

        # State management
        self.data_lock = threading.Lock()
        self.config = {}
        self.progress_data = {}
        self.patch_cache = {}

        # UI Updater для потокобезопасного обновления
        self.ui_updater = UIUpdater(self)

        # Workers
        self.worker = None
        self.worker_thread = None
        self.verify_worker = None
        self.verify_thread = None
        self.patcher_worker = None
        self.patcher_thread = None

        self._build_ui()
        self._connect_signals()
        
        # Настройка UI Updater после создания всех виджетов
        self.ui_updater.setup_connections()

        # Load saved config
        self.load_config_and_progress()

        # Auto-detect Windows theme
        system_theme = self.detect_system_theme()
        if system_theme == "dark":
            self.apply_dark_theme()
        else:
            self.apply_light_theme()

        # Start version manager
        self.setup_version_manager()

        QTimer.singleShot(50, self._update_folder_label)

    def _build_ui(self):
        main_v = QVBoxLayout(self)
        main_v.setContentsMargins(10, 10, 10, 10)
        main_v.setSpacing(10)

        # Top row: folder label + create shortcut + version + theme button
        top_h = QHBoxLayout()
        top_h.setContentsMargins(0, 0, 0, 0)

        # Папка установки
        self.label_choose_folder = QLabel("📁 Выбрать папку")
        self.label_choose_folder.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.label_choose_folder.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        
        # Создать ярлык (в стиле label)
        self.label_create_shortcut = QLabel("🏷️ Создать ярлык (FIX PATH in INI)")
        self.label_create_shortcut.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.label_create_shortcut.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        # Перезапустить Explorer (в стиле label рядом с ярлыком)
        self.label_reset_explorer = QLabel("🔄 Перезапустить Explorer")
        self.label_reset_explorer.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.label_reset_explorer.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        
        right_frame = QFrame()
        right_layout = QHBoxLayout(right_frame)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.label_current_version = QLabel("Текущая версия: не установлена")
        self.label_current_version.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        self.btn_theme = QPushButton("🌙")
        self.btn_theme.setFixedSize(QSize(32, 32))
        self.btn_theme.clicked.connect(self.toggle_theme)

        right_layout.addWidget(self.label_current_version)
        right_layout.addWidget(self.btn_theme)

        top_h.addWidget(self.label_choose_folder)
        top_h.addSpacing(15)  # Отступ между элементами
        top_h.addWidget(self.label_create_shortcut)
        top_h.addSpacing(8)
        top_h.addWidget(self.label_reset_explorer)
        top_h.addStretch(1)
        top_h.addWidget(right_frame)
        main_v.addLayout(top_h)

        content_h = QHBoxLayout()
        content_h.setSpacing(12)

        left_panel = QFrame()
        left_panel.setFixedWidth(260)
        lv = QVBoxLayout(left_panel)
        
        # Убрали кнопку создания ярлыка из левой панели, так как она теперь вверху
        self.btn_patch = QPushButton("🔨 Пропатчить Skyrim")
        self.btn_verify = QPushButton("🛠 Проверить файлы")
        self.btn_revert = QPushButton("♻️ Очистить Skyrim")
        
        for b in (self.btn_patch, self.btn_verify, self.btn_revert):
            b.setFixedHeight(36)
            lv.addWidget(b)
        
        lv.addStretch(1)
        
        content_h.addWidget(left_panel)

        center_panel = QFrame()
        center_panel.setFixedWidth(220)
        cv = QVBoxLayout(center_panel)
        
        cv.addStretch(1)
        
        self.btn_install = QPushButton("📥 Установить")
        self.btn_install.setFixedHeight(36)
        cv.addWidget(self.btn_install, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # Добавляем кнопку "Запустить TESVAE" под кнопкой "Установить"
        self.btn_launch_game = QPushButton(" TESVAE")
        self.btn_launch_game.setIcon(self.windowIcon())
        self.btn_launch_game.setFixedHeight(36)
        cv.addWidget(self.btn_launch_game, alignment=Qt.AlignmentFlag.AlignCenter)
        
        cv.addStretch(1)
        
        content_h.addWidget(center_panel)

        right_panel = QFrame()
        right_panel.setFixedWidth(240)
        rv = QVBoxLayout(right_panel)
        rv.addWidget(QLabel("Выберите версию:"))
        self.combo_versions = QComboBox()
        self.combo_versions.addItem("Загрузка...")
        self.combo_versions.setFixedHeight(36)
        rv.addWidget(self.combo_versions)
        self.btn_latest = QPushButton("🆕 Последняя")
        self.btn_update = QPushButton("🔼 Обновить")
        self.btn_rollback = QPushButton("↩️ Откат")
        for b in (self.btn_latest, self.btn_update, self.btn_rollback):
            b.setFixedHeight(36)
            rv.addWidget(b)
        rv.addStretch(1)
        content_h.addWidget(right_panel)

        main_v.addLayout(content_h)

        bottom_h = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setFixedHeight(22)
        self.progress.setValue(0)
        self.progress.setFormat("")
        
        self.progress.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        bottom_h.addWidget(self.progress, 1)
        self.btn_start_stop = QPushButton("⏸ Пауза")
        self.btn_start_stop.setFixedSize(QSize(100, 36))
        self.btn_start_stop.setEnabled(False)
        bottom_h.addWidget(self.btn_start_stop)
        main_v.addLayout(bottom_h)

        log_v = QVBoxLayout()
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(200)
        log_v.addWidget(self.log, 1)

        self.clear_label = QLabel("Очистить лог")
        self.clear_label.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.clear_label.mousePressEvent = lambda e: self.log.clear()
        log_v.addWidget(self.clear_label, alignment=Qt.AlignmentFlag.AlignRight)

        main_v.addLayout(log_v)

    def _connect_signals(self):
        self.label_choose_folder.mousePressEvent = self._on_choose_folder_clicked
        self.label_create_shortcut.mousePressEvent = lambda e: self.create_shortcut_fix_ini()
        self.label_reset_explorer.mousePressEvent = self._on_reset_explorer_clicked
        self.btn_install.clicked.connect(self.install_game)
        self.btn_launch_game.clicked.connect(self.launch_game)  # Подключаем новую кнопку
        self.btn_patch.clicked.connect(self.patch_skyrim)
        self.btn_verify.clicked.connect(self.verify_files)
        self.btn_revert.clicked.connect(self.revert_skyrim)
        self.btn_latest.clicked.connect(self.update_to_latest)
        self.btn_update.clicked.connect(self.update_to_selected)
        self.btn_rollback.clicked.connect(self.rollback_to_selected)
        self.btn_start_stop.clicked.connect(self.toggle_worker)

    def _on_choose_folder_clicked(self, event):
        self.choose_folder()

    def _update_folder_label(self):
        try:
            if not self._full_local_path or self._full_local_path == "Не выбрана":
                self.label_choose_folder.setText("📁 Выбрать папку")
                return
                
            fm = QFontMetrics(self.label_choose_folder.font())
            max_width = 300
            
            if ":" in self._full_local_path:
                drive, path = os.path.splitdrive(self._full_local_path)
                display_path = f"{drive}{path}"
            else:
                display_path = self._full_local_path
                
            elided_text = fm.elidedText(f"📁 {display_path}", Qt.TextElideMode.ElideMiddle, max_width)
            self.label_choose_folder.setText(elided_text)
            self.label_choose_folder.setToolTip(f"Текущая папка: {self._full_local_path}\nНажмите для смены папки")
        except Exception as e:
            self.label_choose_folder.setText("📁 Выбрать папку")

    def is_mo2_installed_in_folder(self, folder_path):
        folder_path = ensure_windows_path(folder_path)  # ИСПРАВЛЕНИЕ
        if not folder_path or not os.path.exists(folder_path):
            return False
        
        mo2_files = [
            "ModOrganizer.exe",
            "modorganizer2.ini",
            "nxmhandler.exe",
            "usvfs_proxy_x64.exe",
            "usvfs_proxy_x86.exe"
        ]
        
        mo2_dirs = [
            "profiles",
            "mods", 
            "downloads",
            "overwrite"
        ]
        
        for file in mo2_files:
            file_path = os.path.join(folder_path, file)
            file_path = ensure_windows_path(file_path)  # ИСПРАВЛЕНИЕ
            if os.path.exists(file_path):
                return True
        
        for dir_name in mo2_dirs:
            dir_path = os.path.join(folder_path, dir_name)
            dir_path = ensure_windows_path(dir_path)  # ИСПРАВЛЕНИЕ
            if os.path.exists(dir_path):
                return True
        
        return False

    def _show_mo2_exists_dialog(self, folder_path):
        if self._is_closing:
            return
            
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Mod Organizer 2 уже установлен")
        dialog.setIcon(QMessageBox.Icon.Warning)
        
        dialog.setText(
            f"В выбранной папке уже установлен Mod Organizer 2:\n\n"
            f"{folder_path}\n\n"
            "Установка в эту папку невозможна для защиты ваших данных."
        )
        
        verify_btn = dialog.addButton("🔍 Проверить файлы", QMessageBox.ButtonRole.AcceptRole)
        clean_btn = dialog.addButton("🧹 Очистить папку", QMessageBox.ButtonRole.ActionRole)
        choose_btn = dialog.addButton("📁 Выбрать другую папку", QMessageBox.ButtonRole.YesRole)
        cancel_btn = dialog.addButton("❌ Отмена", QMessageBox.ButtonRole.RejectRole)
        
        dialog.setDefaultButton(verify_btn)
        
        dialog.exec()
        
        clicked_btn = dialog.clickedButton()
        
        if clicked_btn == verify_btn:
            self._full_local_path = folder_path
            self.config["local_dir"] = folder_path
            self.save_config()
            self._update_folder_label()
            self._append_log("Запуск проверки файлов существующей установки...")
            self.verify_files()
        elif clicked_btn == clean_btn:
            self._show_clean_folder_warning(folder_path)
        elif clicked_btn == choose_btn:
            self.choose_folder()

    def _show_clean_folder_warning(self, folder_path):
        if self._is_closing:
            return
            
        warning = QMessageBox(self)
        warning.setWindowTitle("⚠️ Внимание! Очистка папки")
        warning.setIcon(QMessageBox.Icon.Warning)
        
        warning.setText(
            "ВЫ СОБИРАЕТЕСЬ ПОЛНОСТЬЮ ОЧИСТИТЬ ПАПКУ!\n\n"
            f"Папка: {folder_path}\n\n"
            "Это действие:\n"
            "• Удалит ВСЕ файлы Mod Organizer 2\n"
            "• Удалит ВСЕ моды и настройки\n"
            "• Удалит ВСЕ профили и сохранения\n"
            "• Действие НЕОБРАТИМО!\n\n"
            "Вы уверены, что хотите продолжить?"
        )
        
        clean_btn = warning.addButton("🗑️ ДА, ОЧИСТИТЬ ПАПКУ", QMessageBox.ButtonRole.DestructiveRole)
        cancel_btn = warning.addButton("❌ Отмена", QMessageBox.ButtonRole.RejectRole)
        
        warning.setDefaultButton(cancel_btn)
        
        warning.exec()
        
        if warning.clickedButton() == clean_btn:
            self._clean_mo2_folder(folder_path)

    def _clean_mo2_folder(self, folder_path):
        try:
            folder_path = ensure_windows_path(folder_path)  # ИСПРАВЛЕНИЕ
            self._append_log(f"Начинаем очистку папки: {folder_path}")
            
            if not os.path.exists(folder_path):
                self._append_log("Папка не существует")
                return False
            
            items_to_remove = []
            
            for item in os.listdir(folder_path):
                item_path = os.path.join(folder_path, item)
                item_path = ensure_windows_path(item_path)  # ИСПРАВЛЕНИЕ
                items_to_remove.append(item_path)
            
            files = [item for item in items_to_remove if os.path.isfile(item)]
            dirs = [item for item in items_to_remove if os.path.isdir(item)]
            
            deleted_count = 0
            
            for file_path in files:
                try:
                    reset_file_attributes(file_path)  # ИСПРАВЛЕНИЕ
                    if os.name == 'nt':
                        try:
                            os.chmod(file_path, 0o777)
                        except:
                            pass
                    os.remove(file_path)
                    deleted_count += 1
                    self._append_log(f"Удален файл: {os.path.basename(file_path)}")
                except Exception as e:
                    self._append_log(f"Ошибка удаления файла {file_path}: {e}")
            
            for dir_path in dirs:
                try:
                    shutil.rmtree(dir_path)
                    deleted_count += 1
                    self._append_log(f"Удалена папка: {os.path.basename(dir_path)}")
                except Exception as e:
                    self._append_log(f"Ошибка удаления папки {dir_path}: {e}")
            
            self._append_log(f"Очистка завершена. Удалено элементов: {deleted_count}")
            
            self._full_local_path = folder_path
            self.config["local_dir"] = folder_path
            self.save_config()
            self._update_folder_label()
            
            return True
            
        except Exception as e:
            self._append_log(f"Критическая ошибка при очистке папки: {e}")
            return False

    def load_config_and_progress(self):
        try:
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    self.config = json.load(f)
                folder = self.config.get("local_dir")
                if folder and os.path.exists(folder):
                    self._full_local_path = ensure_windows_path(folder)  # ИСПРАВЛЕНИЕ
                    self._update_folder_label()
                    self._append_log(f"Загружена папка из конфига: {folder}")
                    # проверка, если есть незавершённые загрузки/операции
                    self._check_pending_operations()
                else:
                    self._append_log("В конфиге папка не найдена или не существует.")
            else:
                self._append_log("Файл config.json отсутствует, выберите папку вручную.")
        except Exception as e:
            self._append_log(f"Ошибка чтения config.json: {e}")

        try:
            if PROGRESS_FILE.exists():
                with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
                    self.progress_data = json.load(f)
                self._append_log("Файл прогресса загружен.")
            else:
                self._append_log("Файл progress.json отсутствует.")
        except Exception as e:
            self._append_log(f"Ошибка чтения progress.json: {e}")

    def _check_pending_operations(self):
        pending_op = self.load_operation_state()
        if pending_op:
            op_type = pending_op.get("type")
            timestamp = pending_op.get("timestamp", 0)
            
            if time.time() - timestamp > 24 * 3600:
                self._append_log("Обнаружена устаревшая незавершенная операция. Очистка...")
                self.clear_operation_state()
                return
                
            self._append_log(f"Обнаружена незавершенная операция: {op_type}")
            
            if not self._is_closing:
                reply = QMessageBox.question(self, "Продолжить операцию?", 
                                           f"Обнаружена незавершенная операция: {op_type}. Продолжить?",
                                           QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    if op_type == "install":
                        self._resume_install_operation(pending_op["data"])
                    elif op_type == "verify":
                        self._resume_verify_operation(pending_op["data"])
                    elif op_type == "patch":
                        self._append_log("Патчинг не может быть продолжен после перезапуска. Запустите заново.")
                        self.clear_operation_state()
                    elif op_type == "revert":
                        self._append_log("Откат не может быть продолжен после перезапуска. Запустите заново.")
                        self.clear_operation_state()
                else:
                    self.clear_operation_state()
                    self.progress_data = {}
                    self.save_progress()

    
    def _on_reset_explorer_clicked(self, event):
        if not sys.platform.startswith('win'):
            QMessageBox.information(self, "Недоступно", "Перезапуск Explorer доступен только в Windows.")
            return

        reply = QMessageBox.question(
            self, "Перезапустить Explorer?", 
            "Это остановит и запустит процесс explorer.exe. Все проводники и панели задач перезапустятся. Продолжить?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._append_log("Попытка перезапуска explorer.exe...")
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command",
                "Get-Process explorer | Stop-Process -Force; Start-Process explorer"
            ]
            subprocess.run(cmd, check=True, timeout=20)
            self._append_log("Explorer успешно перезапущен.")
            QMessageBox.information(self, "Готово", "Explorer успешно перезапущен.")
        except subprocess.CalledProcessError as e:
            self._append_log(f"Ошибка при перезапуске Explorer: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось перезапустить Explorer: {e}")
        except Exception as e:
            self._append_log(f"Исключение при перезапуске Explorer: {e}")
            QMessageBox.critical(self, "Ошибка", f"Неожиданная ошибка: {e}")

    def save_operation_state(self, operation_type, state_data):
        try:
            operation_state = {
                "type": operation_type,
                "data": state_data,
                "timestamp": time.time()
            }
            self.config["pending_operation"] = operation_state
            self.save_config()
        except Exception as e:
            self._append_log(f"Ошибка сохранения состояния операции: {e}")

    def load_operation_state(self):
        try:
            if "pending_operation" in self.config:
                return self.config["pending_operation"]
        except Exception as e:
            self._append_log(f"Ошибка загрузки состояния операции: {e}")
        return None

    def clear_operation_state(self):
        try:
            if "pending_operation" in self.config:
                del self.config["pending_operation"]
                self.save_config()
        except Exception as e:
            self._append_log(f"Ошибка очистки состояния операции: {e}")

    def save_config(self):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            self._append_log(f"Ошибка сохранения конфига: {e}")

    def save_progress(self):
        try:
            with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.progress_data, f, indent=2)
        except Exception as e:
            self._append_log(f"Ошибка сохранения прогресса: {e}")

    def setup_version_manager(self):
        try:
            self.version_manager = VersionManager(local_dir=str(APPDATA_DIR))
            self.version_thread = QThread()
            self.version_manager.moveToThread(self.version_thread)
            self.version_manager.log_signal.connect(self._append_log)
            self.version_manager.versions_loaded_signal.connect(self._populate_versions)
            self.version_thread.started.connect(self.version_manager.load_versions)
            self.version_thread.start()
        except Exception as e:
            self._append_log(f"Ошибка запуска VersionManager: {e}")

    # ---------------- UI Update Methods ---------------- 
    def _safe_append_log(self, text: str):
        try:
            if self._is_closing or not hasattr(self, 'log') or not self.log:
                return
            
            # Проверяем, не находится ли виджет в процессе обновления
            if self.log.updatesEnabled():
                self.log.append(str(text))
        except Exception as e:
            print(f"Safe log error: {e}")

    def _safe_update_progress(self, current, total, eta_str):
        try:
            if self._is_closing or not hasattr(self, 'progress') or not self.progress:
                return
                
            if not self.progress.updatesEnabled():
                return
                
            percent = int((current / total) * 100) if total > 0 else 0
            self.progress.setMaximum(total)
            self.progress.setValue(current)
            self.progress.setFormat(f"{percent}% — {current}/{total} — ETA: {eta_str}")
        except Exception as e:
            print(f"Safe progress error: {e}")

    def _safe_update_progress_simple(self, current, total):
        try:
            if self._is_closing or not hasattr(self, 'progress') or not self.progress:
                return
                
            if not self.progress.updatesEnabled():
                return
                
            percent = int((current / total) * 100) if total > 0 else 0
            self.progress.setMaximum(total)
            self.progress.setValue(current)
            self.progress.setFormat(f"{percent}% — {current}/{total}")
        except Exception as e:
            print(f"Safe progress error: {e}")

    # ---------------- themes ----------------
    def apply_light_theme(self):
        self.setStyleSheet("""
            QWidget { background: #f6f7fb; color: #222; font-family: "Segoe UI"; }
            QPushButton { background: #fff; border: 1px solid #d6dbe8; border-radius: 6px; padding: 6px; }
            QPushButton:hover { background: #eef5ff; }
            QProgressBar { 
                border-radius: 6px; 
                background: #e9eefb; 
                height: 18px; 
                text-align: center;
                qproperty-alignment: 'AlignCenter';
            }
            QProgressBar::chunk { border-radius: 6px; background: #4ade80; }
            QTextEdit { background: #fff; border: 1px solid #e1e6f2; border-radius: 6px; }
        """)
        self.btn_theme.setText("🌙")
        self.current_theme = "light"
        self.clear_label.setStyleSheet("QLabel { color: black; }")

    def apply_dark_theme(self):
        self.setStyleSheet("""
            QWidget { background: #2b2b2b; color: #ddd; font-family: "Segoe UI"; }
            QPushButton { background: #3a3a3a; border: 1px solid #555; border-radius: 6px; padding: 6px; color: #eee; }
            QPushButton:hover { background: #505050; }
            QProgressBar { 
                border-radius: 6px; 
                background: #444; 
                height: 18px; 
                color: white; 
                text-align: center;
                qproperty-alignment: 'AlignCenter';
            }
            QProgressBar::chunk { border-radius: 6px; background: #16a34a; }
            QTextEdit { background: #1e1e1e; border: 1px solid #555; border-radius: 6px; color: #ddd; }
        """)
        self.btn_theme.setText("☀️")
        self.current_theme = "dark"
        self.clear_label.setStyleSheet("QLabel { color: white; }")

    def toggle_theme(self):
        if self.current_theme == "light":
            self.apply_dark_theme()
        else:
            self.apply_light_theme()

    def detect_system_theme(self):
        try:
            settings = QSettings(
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                QSettings.Format.NativeFormat
            )
            use_light = settings.value("AppsUseLightTheme", 1, type=int)
            return "light" if use_light == 1 else "dark"
        except Exception:
            return "light"

    # ---------------- UI helpers ----------------
    def _populate_versions(self, versions: list):
        try:
            self.combo_versions.clear()
            if versions:
                self.combo_versions.addItems(versions)
                try:
                    self._full_version_text = versions[0]
                except Exception:
                    self._full_version_text = versions[0] if versions else "не установлена"
                self.label_current_version.setText(f"Текущая версия: {self._full_version_text}")
                self._append_log(f"Загружено {len(versions)} версий")
            else:
                self.combo_versions.addItem("Нет доступных версий")
                self._append_log("Не удалось загрузить список версий")
        except Exception as e:
            self._append_log(f"Ошибка при заполнении версий: {e}")

    # ---------------- Core functionality ----------------
    def choose_folder(self):
        try:
            folder = QFileDialog.getExistingDirectory(
                self, "Выберите папку установки MO2", options=QFileDialog.Option.ShowDirsOnly
            )
            if not folder:
                self._append_log("Папка не выбрана")
                return False

            self._full_local_path = ensure_windows_path(folder)  # ИСПРАВЛЕНИЕ
            self.config["local_dir"] = folder
            self.save_config()

            self._update_folder_label()
            self._append_log(f"Выбрана папка: {folder}")
            return True
        except Exception as e:
            self._append_log(f"Ошибка выбора папки: {e}")
            return False

    def install_game(self):
        if not self._full_local_path or self._full_local_path == "Не выбрана":
            self._append_log("Папка не выбрана, запуск выбора папки...")
            if not self.choose_folder():
                self._append_log("Установка отменена: папка не выбрана")
                return
        
        if self.is_mo2_installed_in_folder(self._full_local_path):
            self._append_log("⚠️ Обнаружен существующий MO2 в папке, показ диалога...")
            self._show_mo2_exists_dialog(self._full_local_path)
            return
        
        pending_op = self.load_operation_state()
        if pending_op and pending_op.get("type") == "install":
            if not self._is_closing:
                reply = QMessageBox.question(self, "Продолжить установку", 
                                           "Обнаружена незавершенная установка. Продолжить?",
                                           QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    self._resume_install_operation(pending_op["data"])
                    return
                else:
                    self.clear_operation_state()

        if self.is_installing:
            self._append_log("Запрос на остановку установки...")
            self._stop_worker()
            self.is_installing = False
            self.btn_install.setText("📥 Установить")
            self._enable_buttons()
            self.btn_start_stop.setEnabled(False)
            self.clear_operation_state()
            return

        self.is_installing = True
        self.btn_install.setText("Отменить")
        self._disable_buttons(exclude=[self.btn_install])

        self.save_operation_state("install", {
            "local_dir": self._full_local_path,
            "use_dav": True,
            "manifest_url": DAV_SERVER + "manifest.json",
            "base_url": DAV_SERVER,
            "step": "download"
        })

        self._start_enhanced_installation()

    def _start_enhanced_installation(self):
        try:
            self._append_log("=== НАЧАЛО УСТАНОВКИ ===")
            self._append_log("Шаг 1: Проверка папки установки...")
            
            if not os.path.exists(self._full_local_path):
                try:
                    os.makedirs(self._full_local_path, exist_ok=True)
                    self._append_log(f"Создана папка: {self._full_local_path}")
                except Exception as e:
                    self._append_log(f"Ошибка создания папки: {e}")
                    self._installation_failed()
                    return
            
            self._append_log("✓ Папка установки готова")
            self._append_log("Шаг 2: Загрузка файлов...")
            
            task = {
                "type": "install",
                "use_dav": True,
                "manifest_url": DAV_SERVER + "manifest.json",
                "base_url": DAV_SERVER
            }
            self._start_worker(task)
            
        except Exception as e:
            self._append_log(f"Ошибка запуска установки: {e}")
            self._installation_failed()

    def _resume_install_operation(self, state_data):
        self.is_installing = True
        self.btn_install.setText("Отменить")
        self._disable_buttons(exclude=[self.btn_install])

        task = {
            "type": "install",
            "use_dav": state_data.get("use_dav", True),
            "manifest_url": state_data.get("manifest_url", DAV_SERVER + "manifest.json"),
            "base_url": state_data.get("base_url", DAV_SERVER)
        }
        self._start_worker(task)
        
        self._append_log("Продолжение установки...")

    def _on_worker_finished(self, success):
        try:
            # Проверяем флаг закрытия
            if self._is_closing:
                return
                
            if self.worker_thread:
                self.worker_thread.quit()
                self.worker_thread.wait(1000)

            self.worker = None
            self.worker_thread = None
            self._worker_paused = False
            self.btn_start_stop.setText("▶ Старт")
            self.btn_start_stop.setEnabled(False)

            if self.is_installing:
                if success:
                    self._append_log("✓ Загрузка файлов завершена успешно")
                    self._append_log("Шаг 3: Настройка конфигурации...")
                    # Используем отложенный вызов
                    QTimer.singleShot(100, self._configure_after_install)
                else:
                    self._append_log("✗ Загрузка файлов завершена с ошибками")
                    QTimer.singleShot(100, self._installation_failed)
            else:
                # ВАЖНОЕ ИСПРАВЛЕНИЕ: Сбрасываем состояние установки для других типов задач
                self.is_installing = False
                self.btn_install.setText("📥 Установить")
                self._enable_buttons()

                self.progress.setValue(0)
                self.progress.setMaximum(100)
                self.progress.setFormat("")

                if success:
                    self.clear_operation_state()
                    self._append_log("Задача завершена успешно")
                else:
                    self._append_log("Задача завершена с ошибками")

                self.save_progress()
                self.save_config()
        except Exception as e:
            self._append_log(f"Ошибка при завершении работы: {e}")

    def _configure_after_install(self):
        try:
            self.save_operation_state("install", {
                "local_dir": self._full_local_path,
                "step": "configuration"
            })
            
            self.patcher_worker = SkyrimPatcher()
            self.patcher_thread = QThread()
            self.patcher_worker.moveToThread(self.patcher_thread)

            def on_config_finished(config_success, game_path):
                try:
                    self.patcher_thread.quit()
                    self.patcher_thread.wait(1000)
                    
                    if config_success:
                        self._append_log("✓ Конфигурация INI завершена успешно")
                        self._append_log("Шаг 4: Создание ярлыка...")
                        # Используем отложенный вызов
                        QTimer.singleShot(100, self._create_shortcut_after_config)
                    else:
                        self._append_log("✗ Ошибка конфигурации INI")
                        self._append_log("Продолжаем установку...")
                        QTimer.singleShot(100, self._create_shortcut_after_config)
                except Exception as e:
                    self._append_log(f"Ошибка при завершении конфигурации: {e}")
                    QTimer.singleShot(100, self._create_shortcut_after_config)

            self.patcher_worker.finished_signal.connect(on_config_finished)
            self.patcher_worker.log_signal.connect(self._append_log)

            def start_config():
                try:
                    game_path = self.patcher_worker.find_skyrim_steam()
                    if game_path:
                        game_folder = os.path.dirname(game_path)
                        success = self.patcher_worker.update_modorganizer_ini(self._full_local_path, game_folder)
                        self.patcher_worker.finished_signal.emit(success, game_path)
                    else:
                        self._append_log("Skyrim Special Edition не найден, используется стандартная конфигурация")
                        self.patcher_worker.finished_signal.emit(True, "")
                except Exception as e:
                    self._append_log(f"Ошибка при настройке конфигурации: {e}")
                    self.patcher_worker.finished_signal.emit(False, "")

            self.patcher_thread.started.connect(start_config)
            self.patcher_thread.start()
            
        except Exception as e:
            self._append_log(f"Ошибка настройки конфигурации: {e}")
            QTimer.singleShot(100, self._create_shortcut_after_config)

    def _create_shortcut_after_config(self):
        try:
            self.save_operation_state("install", {
                "local_dir": self._full_local_path,
                "step": "shortcut"
            })
            
            self._append_log("Создание ярлыка на рабочем столе...")
            
            mo_exe = os.path.join(self._full_local_path, "ModOrganizer.exe")
            mo_exe = ensure_windows_path(mo_exe)
            if not os.path.exists(mo_exe):
                self._append_log("✗ ModOrganizer.exe не найден в выбранной папке")
                # Используем QTimer для отложенного вызова в главном потоке
                QTimer.singleShot(100, lambda: self._installation_complete(False))
                return
            
            def create_shortcut_thread():
                try:
                    success, message = create_shortcut(mo_exe)
                    # Используем потокобезопасное обновление UI
                    if not self._is_closing:
                        self.ui_updater.update_log_signal.emit(message)
                        # Отложенный вызов завершения установки
                        QTimer.singleShot(100, lambda: self._installation_complete(success))
                except Exception as e:
                    if not self._is_closing:
                        error_msg = f"✗ Ошибка при создании ярлыка: {e}"
                        self.ui_updater.update_log_signal.emit(error_msg)
                        QTimer.singleShot(100, lambda: self._installation_complete(False))
            
            # Запускаем в отдельном потоке с небольшой задержкой
            QTimer.singleShot(50, lambda: threading.Thread(target=create_shortcut_thread, daemon=True).start())
            
        except Exception as e:
            self._append_log(f"Ошибка при создании ярлыка: {e}")
            QTimer.singleShot(100, lambda: self._installation_complete(False))

    def _installation_complete(self, success):
        try:
            # Проверяем флаг закрытия перед любыми обновлениями UI
            if self._is_closing:
                return

            # Используем QTimer для отложенного обновления UI
            QTimer.singleShot(100, lambda: self._safe_finish_installation(success))
            
        except Exception as e:
            print(f"Error in installation complete: {e}")

    @pyqtSlot(bool)
    def _safe_finish_installation(self, success):
        """Потокобезопасное завершение установки"""
        try:
            if self._is_closing:
                return
                
            # ВАЖНОЕ ИСПРАВЛЕНИЕ: Явно сбрасываем состояние установки
            self.is_installing = False
            self.btn_install.setText("📥 Установить")
            self._enable_buttons()

            self.progress.setValue(0)
            self.progress.setMaximum(100)
            self.progress.setFormat("")

            if success:
                self.clear_operation_state()
                # Используем отложенный вывод в лог
                QTimer.singleShot(50, lambda: self._append_log("=== УСТАНОВКА ЗАВЕРШЕНА УСПЕШНО ==="))
                QTimer.singleShot(100, lambda: self._append_log("Все шаги выполнены:"))
                QTimer.singleShot(150, lambda: self._append_log("✓ Проверка папки установки"))
                QTimer.singleShot(200, lambda: self._append_log("✓ Загрузка файлов"))
                QTimer.singleShot(250, lambda: self._append_log("✓ Настройка конфигурации INI"))
                QTimer.singleShot(300, lambda: self._append_log("✓ Создание ярлыка"))
            else:
                QTimer.singleShot(50, lambda: self._append_log("=== УСТАНОВКА ЗАВЕРШЕНА С ОШИБКАМИ ==="))

            self.save_progress()
            self.save_config()
            
        except Exception as e:
            print(f"Error in safe finish installation: {e}")

    def _installation_failed(self):
        try:
            # ВАЖНОЕ ИСПРАВЛЕНИЕ: Явно сбрасываем состояние установки
            self.is_installing = False
            self.btn_install.setText("📥 Установить")
            self._enable_buttons()
            self.btn_start_stop.setEnabled(False)

            self.progress.setValue(0)
            self.progress.setMaximum(100)
            self.progress.setFormat("")

            self._append_log("=== УСТАНОВКА ПРЕРВАНА ===")

            self.save_progress()
            self.save_config()
        except Exception as e:
            self._append_log(f"Ошибка при обработке неудачной установки: {e}")

    def create_shortcut_fix_ini(self):
        if not self._full_local_path or self._full_local_path == "Не выбрана":
            self._append_log("Сначала выберите папку MO2.")
            return

        try:
            patcher = SkyrimPatcher()
            patcher_thread = QThread()
            patcher.moveToThread(patcher_thread)
            
            def on_finished(success, game_path):
                try:
                    patcher_thread.quit()
                    patcher_thread.wait(1000)
                    if success:
                        self._append_log("ModOrganizer.ini успешно обновлен")
                        
                        mo_exe = os.path.join(self._full_local_path, "ModOrganizer.exe")
                        mo_exe = ensure_windows_path(mo_exe)  # ИСПРАВЛЕНИЕ
                        if not os.path.exists(mo_exe):
                            self._append_log("ModOrganizer.exe не найден в выбранной папке")
                            return
                        
                        def create_shortcut_thread():
                            success, message = create_shortcut(mo_exe)
                            self._append_log(message)
                        
                        threading.Thread(target=create_shortcut_thread, daemon=True).start()
                    else:
                        self._append_log("Не удалось обновить ModOrganizer.ini")
                except Exception as e:
                    self._append_log(f"Ошибка при завершении создания ярлыка: {e}")
            
            patcher.finished_signal.connect(on_finished)
            patcher.log_signal.connect(self._append_log)
            
            def start_process():
                try:
                    game_path = patcher.find_skyrim_steam()
                    if game_path:
                        game_folder = os.path.dirname(game_path)
                        success = patcher.update_modorganizer_ini(self._full_local_path, game_folder)
                        patcher.finished_signal.emit(success, game_path)
                    else:
                        self._append_log("Skyrim Special Edition не найден")
                        patcher.finished_signal.emit(False, "")
                except Exception as e:
                    self._append_log(f"Ошибка при настройке INI: {e}")
                    patcher.finished_signal.emit(False, "")
            
            patcher_thread.started.connect(start_process)
            patcher_thread.start()
            
        except Exception as e:
            self._append_log(f"Ошибка создания ярлыка и настройки INI: {e}")

    def launch_game(self):
        """Запуск игры через ModOrganizer.exe с аргументом SKSE"""
        if not self._full_local_path or self._full_local_path == "Не выбрана":
            self._append_log("Сначала выберите папку MO2.")
            return

        try:
            mo_exe_path = os.path.join(self._full_local_path, "ModOrganizer.exe")
            mo_exe_path = ensure_windows_path(mo_exe_path)  # ИСПРАВЛЕНИЕ
            if not os.path.exists(mo_exe_path):
                self._append_log(f"ModOrganizer.exe не найден по пути: {mo_exe_path}")
                return

            self._append_log("Запуск игры через ModOrganizer...")
            
            # Запускаем ModOrganizer.exe с аргументом для запуска SKSE
            subprocess.Popen([mo_exe_path, "moshortcut://:SKSE"], 
                           cwd=self._full_local_path,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            
            self._append_log("Выполняется запуск TESVAE это займёт примерно 10-80 секунд, убедительная просьба вовремя запуска игры пока не появится меню, ничего НЕ нажимать! Я серьёзно!")
            
        except Exception as e:
            self._append_log(f"Ошибка при запуске игры: {e}")

    def patch_skyrim(self):
        if self.is_patching:
            self._append_log("Запрос на остановку патчинга...")
            self._stop_patcher()
            self.btn_patch.setText("🔨 Пропатчить Skyrim")
            self.clear_operation_state()
            return

        self.is_patching = True
        self.btn_patch.setText("Отменить")
        self._disable_buttons(exclude=[self.btn_patch])
        self.btn_start_stop.setEnabled(True)
        self.btn_start_stop.setText("⏸ Пауза")

        self.save_operation_state("patch", {
            "start_time": time.time()
        })

        self.patcher_worker = SkyrimPatcher()
        self.patcher_thread = QThread()
        self.patcher_worker.moveToThread(self.patcher_thread)

        self.patcher_worker.log_signal.connect(self._append_log)
        self.patcher_worker.progress_signal.connect(self._on_patcher_progress)
        self.patcher_worker.finished_signal.connect(self._on_patcher_finished)

        self.patcher_thread.started.connect(self.patcher_worker.run_patch)
        self.patcher_thread.start()

        self._append_log("Запуск патчинга Skyrim...")

    def verify_files(self):
        if not self._full_local_path or self._full_local_path == "Не выбрана":
            self._append_log("Сначала выберите папку установки.")
            return

        pending_op = self.load_operation_state()
        if pending_op and pending_op.get("type") == "verify":
            if not self._is_closing:
                reply = QMessageBox.question(self, "Продолжить проверку", 
                                           "Обнаружена незавершенная проверка файлов. Продолжить?",
                                           QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    self._resume_verify_operation(pending_op["data"])
                    return
                else:
                    self.clear_operation_state()

        if self.is_verifying:
            self._append_log("Запрос на остановку проверки...")
            self._stop_verify()
            self.btn_verify.setText("🛠 Проверить файлы")
            self.clear_operation_state()
            return

        self.is_verifying = True
        self.btn_verify.setText("Отменить")
        self._disable_buttons(exclude=[self.btn_verify])
        self.btn_start_stop.setEnabled(True)
        self.btn_start_stop.setText("⏸ Пауза")

        self.save_operation_state("verify", {
            "local_dir": self._full_local_path,
            "start_time": time.time()
        })

        self.verify_worker = VerifyWorker(self._full_local_path, self.progress_data)
        self.verify_thread = QThread()
        self.verify_worker.moveToThread(self.verify_thread)

        self.verify_worker.log_signal.connect(self._append_log)
        self.verify_worker.progress_signal.connect(self._on_verify_progress)
        self.verify_worker.finished_signal.connect(self._on_verify_finished)

        self.verify_thread.started.connect(self.verify_worker.run)
        self.verify_thread.start()

        self._append_log("Запуск проверки файлов...")

    def _resume_verify_operation(self, state_data):
        self.is_verifying = True
        self.btn_verify.setText("Отменить")
        self._disable_buttons(exclude=[self.btn_verify])
        self.btn_start_stop.setEnabled(True)
        self.btn_start_stop.setText("⏸ Пауза")

        self.verify_worker = VerifyWorker(self._full_local_path, self.progress_data)
        self.verify_thread = QThread()
        self.verify_worker.moveToThread(self.verify_thread)

        self.verify_worker.log_signal.connect(self._append_log)
        self.verify_worker.progress_signal.connect(self._on_verify_progress)
        self.verify_worker.finished_signal.connect(self._on_verify_finished)

        self.verify_thread.started.connect(self.verify_worker.run)
        self.verify_thread.start()

        self._append_log("Продолжение проверки файлов...")

    def revert_skyrim(self):
        if self.is_patching:
            self._append_log("Запрос на остановку отката...")
            self._stop_patcher()
            self.btn_revert.setText("♻️ Очистить Skyrim")
            self.clear_operation_state()
            return

        self.is_patching = True
        self.btn_revert.setText("Отменить")
        self._disable_buttons(exclude=[self.btn_revert])
        self.btn_start_stop.setEnabled(True)
        self.btn_start_stop.setText("⏸ Пауза")

        self.save_operation_state("revert", {
            "start_time": time.time()
        })

        self.patcher_worker = SkyrimPatcher()
        self.patcher_thread = QThread()
        self.patcher_worker.moveToThread(self.patcher_thread)

        self.patcher_worker.log_signal.connect(self._append_log)
        self.patcher_worker.progress_signal.connect(self._on_patcher_progress)
        self.patcher_worker.finished_signal.connect(self._on_revert_finished)

        self.patcher_thread.started.connect(self.patcher_worker.run_revert)
        self.patcher_thread.start()

        self._append_log("Запуск отката патча Skyrim...")

    def update_to_latest(self):
        latest = self.version_manager.get_latest_version()
        if not latest:
            self._append_log("Не удалось получить последнюю версию.")
            return

        if latest not in self.version_manager.versions_cache:
            self._append_log(f"Версия {latest} не найдена в кэше")
            return

        self._apply_version(latest)

    def update_to_selected(self):
        selected = self.combo_versions.currentText()
        if not selected or selected == "Загрузка..." or selected == "Нет доступных версий":
            self._append_log("Выберите версию для обновления")
            return

        self._apply_version(selected)

    def rollback_to_selected(self):
        selected = self.combo_versions.currentText()
        if not selected or selected == "Загрузка..." or selected == "Нет доступных версий":
            self._append_log("Выберите версию для отката")
            return

        self._rollback_version(selected)

    def _apply_version(self, version):
        task = {
            "type": "apply_patch",
            "version": version,
            "use_dav": True
        }
        self._start_worker(task)

    def _rollback_version(self, version):
        self._append_log(f"Откат до версии {version}...")
        self._apply_version(version)

    # ---------------- Worker management ----------------
    def _start_worker(self, task):
        if self.worker:
            self._append_log("Рабочий процесс уже запущен")
            return

        refs = {
            "local_dir": self._full_local_path,
            "json_server": JSON_SERVER,
            "dav_server": DAV_SERVER,
            "username": USERNAME,
            "password": PASSWORD,
            "progress_data": self.progress_data,
            "config": self.config,
            "data_lock": self.data_lock
        }

        refs["config"]["local_dir"] = self._full_local_path
        
        # Создаем воркер БЕЗ родителя (не передаем self)
        self.worker = DownloadWorker(task, refs)
        self.worker_thread = QThread()
        
        # Перемещаем воркер в поток
        self.worker.moveToThread(self.worker_thread)

        # Подключаем сигналы
        self.worker.log_signal.connect(self._append_log)
        self.worker.progress_total_setmax_signal.connect(self.progress.setMaximum)
        self.worker.progress_total_signal.connect(self.progress.setValue)
        self.worker.current_file_signal.connect(lambda s: self.progress.setFormat(f"{s}"))
        self.worker.finished_signal.connect(self._on_worker_finished)

        # Подключаем завершение потока при завершении воркера
        self.worker.finished_signal.connect(self.worker_thread.quit)
        self.worker.finished_signal.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)

        self.worker_thread.started.connect(self.worker.run)
        self.worker_thread.start()

        self.btn_start_stop.setText("⏸ Пауза")
        self.btn_start_stop.setEnabled(True)
        self._worker_paused = False
        self._disable_buttons(exclude=[self.btn_start_stop, self.btn_install])

    def toggle_worker(self):
        if self.worker:
            if getattr(self, "_worker_paused", False):
                try:
                    self.worker.resume()
                    self._worker_paused = False
                    self.btn_start_stop.setText("⏸ Пауза")
                    self._append_log("Возобновление загрузки...")
                except Exception as e:
                    self._append_log(f"Ошибка при возобновлении: {e}")
            else:
                try:
                    self.worker.pause()
                    self._worker_paused = True
                    self.btn_start_stop.setText("▶ Продолжить")
                    self._append_log("Загрузка приостановлена.")
                    
                    if self.is_installing:
                        self.save_operation_state("install", {
                            "local_dir": self._full_local_path,
                            "paused_time": time.time(),
                            "use_dav": True
                        })
                except Exception as e:
                    self._append_log(f"Ошибка при паузе: {e}")
        elif self.verify_worker:
            if getattr(self, "_worker_paused", False):
                try:
                    self.verify_worker.resume()
                    self._worker_paused = False
                    self.btn_start_stop.setText("⏸ Пауза")
                    self._append_log("Возобновление проверки...")
                except Exception as e:
                    self._append_log(f"Ошибка при возобновлении: {e}")
            else:
                try:
                    self.verify_worker.pause()
                    self._worker_paused = True
                    self.btn_start_stop.setText("▶ Продолжить")
                    self._append_log("Проверка приостановлена.")
                    
                    if self.is_verifying:
                        self.save_operation_state("verify", {
                            "local_dir": self._full_local_path,
                            "paused_time": time.time()
                        })
                except Exception as e:
                    self._append_log(f"Ошибка при паузе: {e}")
        elif self.patcher_worker:
            if getattr(self, "_worker_paused", False):
                try:
                    self.patcher_worker.resume()
                    self._worker_paused = False
                    self.btn_start_stop.setText("⏸ Пауза")
                    self._append_log("Возобновление патчинга...")
                except Exception as e:
                    self._append_log(f"Ошибка при возобновлении: {e}")
            else:
                try:
                    self.patcher_worker.pause()
                    self._worker_paused = True
                    self.btn_start_stop.setText("▶ Продолжить")
                    self._append_log("Патчинг приостановлен.")
                    
                    if self.is_patching:
                        operation_type = "patch" if self.btn_patch.text() == "Отменить" else "revert"
                        self.save_operation_state(operation_type, {
                            "paused_time": time.time()
                        })
                except Exception as e:
                    self._append_log(f"Ошибка при паузе: {e}")
        else:
            pending = self.config.get("pending_task")
            if pending:
                self._start_worker(pending)
            else:
                self._append_log("Нет активной задачи для продолжения")

    def _stop_worker(self):
        if self.worker:
            self._append_log("Остановка рабочего процесса...")
            self.worker.stop()
            if self.worker_thread and self.worker_thread.isRunning():
                self.worker_thread.quit()
                if not self.worker_thread.wait(2000):
                    self.worker_thread.terminate()
                    self.worker_thread.wait()

    # ---------------- Verify worker management ----------------
    def _stop_verify(self):
        if self.verify_worker:
            self._append_log("Остановка проверки...")
            self.verify_worker.stop()
            if self.verify_thread and self.verify_thread.isRunning():
                self.verify_thread.quit()
                if not self.verify_thread.wait(2000):
                    self.verify_thread.terminate()
                    self.verify_thread.wait()

    def _on_verify_progress(self, current, total, eta_str):
        percent = int((current / total) * 100) if total > 0 else 0
        self.progress.setMaximum(total)
        self.progress.setValue(current)
        self.progress.setFormat(f"{percent}% — {current}/{total} — ETA: {eta_str}")

    def _on_verify_finished(self, success, to_download, to_redownload, deleted):
        try:
            if self.verify_thread:
                self.verify_thread.quit()
                if not self.verify_thread.wait(3000):  # Ждем до 3 секунд
                    self.verify_thread.terminate()
                    self.verify_thread.wait()

            # Очищаем указатели в главном потоке
            self.verify_worker = None
            self.verify_thread = None
            self.is_verifying = False
            
            # Обновляем UI в главном потоке
            QMetaObject.invokeMethod(self, "_safe_finish_verify", 
                                   Qt.ConnectionType.QueuedConnection,
                                   Q_ARG(bool, success),
                                   Q_ARG(int, to_download),
                                   Q_ARG(int, to_redownload),
                                   Q_ARG(int, deleted))
                               
        except Exception as e:
            print(f"Ошибка при завершении проверки: {e}")

    @pyqtSlot(bool, int, int, int)
    def _safe_finish_verify(self, success, to_download, to_redownload, deleted):
        """Потокобезопасное завершение проверки"""
        try:
            self.btn_verify.setText("🛠 Проверить файлы")
            self._worker_paused = False
            self.btn_start_stop.setText("▶ Старт")
            self.btn_start_stop.setEnabled(False)
            self._enable_buttons()

            self.progress.setValue(0)
            self.progress.setMaximum(100)
            self.progress.setFormat("")

            if success:
                self.clear_operation_state()
                self._append_log(f"Проверка завершена. К скачиванию: {to_download}, к перекачиванию: {to_redownload}, удалено: {deleted}")
                
                total_to_download = to_download + to_redownload
                if total_to_download > 0:
                    self._append_log(f"Найдено {total_to_download} файлов для загрузки. Запускаем загрузку...")
                    # Используем QTimer для безопасного запуска в главном потоке
                    QTimer.singleShot(100, self._start_download_after_verify)
                else:
                    self._append_log("Все файлы в порядке, загрузка не требуется.")
            else:
                self._append_log("Проверка прервана")

            self.save_progress()
        except Exception as e:
            self._append_log(f"Ошибка при завершении проверки: {e}")

    def _start_download_after_verify(self):
        """Запуск загрузки после проверки (вызывается в главном потоке)"""
        try:
            if not self._full_local_path or self._full_local_path == "Не выбрана":
                self._append_log("Ошибка: папка не выбрана")
                return
                
            if self.is_installing:
                self._append_log("Загрузка уже выполняется")
                return
                
            self.is_installing = True
            self.btn_install.setText("Отменить")
            self._disable_buttons(exclude=[self.btn_install])

            self.save_operation_state("install", {
                "local_dir": self._full_local_path,
                "use_dav": True,
                "manifest_url": DAV_SERVER + "manifest.json",
                "base_url": DAV_SERVER
            })

            task = {
                "type": "install",
                "use_dav": True,
                "manifest_url": DAV_SERVER + "manifest.json",
                "base_url": DAV_SERVER
            }
            self._start_worker(task)
            
        except Exception as e:
            self._append_log(f"Ошибка при запуске загрузки: {e}")
            self._installation_failed()

    # ---------------- Patcher worker management ----------------
    def _stop_patcher(self):
        if hasattr(self, 'patcher_worker') and self.patcher_worker:
            self._append_log("Остановка патчера...")
            self.patcher_worker.stop()
            if self.patcher_thread and self.patcher_thread.isRunning():
                self.patcher_thread.quit()
                if not self.patcher_thread.wait(2000):
                    self.patcher_thread.terminate()
                    self.patcher_thread.wait()
        else:
            self._append_log("Патчер не запущен или недоступен для остановки")

    def _on_patcher_progress(self, current, total, eta_str):
        percent = int((current / total) * 100) if total > 0 else 0
        self.progress.setMaximum(total)
        self.progress.setValue(current)
        self.progress.setFormat(f"{percent}% — {current}/{total} — ETA: {eta_str}")

    def _on_patcher_finished(self, success, game_path):
        try:
            if hasattr(self, 'patcher_thread') and self.patcher_thread:
                self.patcher_thread.quit()
                self.patcher_thread.wait(1000)

            self.patcher_worker = None
            self.patcher_thread = None
            self.is_patching = False
            self.btn_patch.setText("🔨 Пропатчить Skyrim")
            self._worker_paused = False
            self.btn_start_stop.setText("▶ Старт")
            self.btn_start_stop.setEnabled(False)
            self._enable_buttons()

            self.progress.setValue(0)
            self.progress.setMaximum(100)
            self.progress.setFormat("")

            if success:
                self.clear_operation_state()
                self._append_log("Патчинг завершен успешно!")
            else:
                self._append_log("Патчинг прерван или завершился с ошибками")

            self.save_progress()
        except Exception as e:
            self._append_log(f"Ошибка при завершении патчинга: {e}")

    def _on_revert_finished(self, success, game_path):
        try:
            if hasattr(self, 'patcher_thread') and self.patcher_thread:
                self.patcher_thread.quit()
                self.patcher_thread.wait(1000)

            self.patcher_worker = None
            self.patcher_thread = None
            self.is_patching = False
            self.btn_revert.setText("♻️ Очистить Skyrim")
            self._worker_paused = False
            self.btn_start_stop.setText("▶ Старт")
            self.btn_start_stop.setEnabled(False)
            self._enable_buttons()

            self.progress.setValue(0)
            self.progress.setMaximum(100)
            self.progress.setFormat("")

            if success:
                self.clear_operation_state()
                self._append_log("Откат патча завершен успешно!")
            else:
                self._append_log("Откат патча прерван или завершился с ошибками")

            self.save_progress()
        except Exception as e:
            self._append_log(f"Ошибка при завершении отката: {e}")

    def _disable_buttons(self, exclude=None):
        if exclude is None:
            exclude = []
        for btn in [
            self.btn_install, self.btn_launch_game, self.btn_patch, 
            self.btn_verify, self.btn_revert, self.btn_latest, self.btn_update, 
            self.btn_rollback
        ]:
            if btn not in exclude:
                btn.setEnabled(False)

    def _enable_buttons(self):
        for btn in [
            self.btn_install, self.btn_launch_game, self.btn_patch, 
            self.btn_verify, self.btn_revert, self.btn_latest, self.btn_update, 
            self.btn_rollback
        ]:
            btn.setEnabled(True)

    def closeEvent(self, event):
        self._is_closing = True  # Устанавливаем флаг закрытия
        
        # Блокируем обновления виджетов
        if hasattr(self, 'log') and self.log:
            self.log.setUpdatesEnabled(False)
        if hasattr(self, 'progress') and self.progress:
            self.progress.setUpdatesEnabled(False)
        
        # Отключаем все сигналы UI Updater
        try:
            if hasattr(self, 'ui_updater'):
                self.ui_updater.update_log_signal.disconnect()
                self.ui_updater.update_progress_signal.disconnect()
                self.ui_updater.update_progress_simple_signal.disconnect()
        except:
            pass

        # Останавливаем все рабочие потоки
        workers_to_stop = []
        if hasattr(self, 'worker') and self.worker:
            workers_to_stop.append(self.worker)
        if hasattr(self, 'verify_worker') and self.verify_worker:
            workers_to_stop.append(self.verify_worker)
        if hasattr(self, 'patcher_worker') and self.patcher_worker:
            workers_to_stop.append(self.patcher_worker)

        for worker in workers_to_stop:
            try:
                worker.stop()
            except:
                pass

        # Останавливаем все потоки QThread
        threads_to_stop = []
        if hasattr(self, 'worker_thread') and self.worker_thread and self.worker_thread.isRunning():
            threads_to_stop.append(self.worker_thread)
        if hasattr(self, 'verify_thread') and self.verify_thread and self.verify_thread.isRunning():
            threads_to_stop.append(self.verify_thread)
        if hasattr(self, 'patcher_thread') and self.patcher_thread and self.patcher_thread.isRunning():
            threads_to_stop.append(self.patcher_thread)
        if hasattr(self, 'version_thread') and self.version_thread and self.version_thread.isRunning():
            threads_to_stop.append(self.version_thread)

        for thread in threads_to_stop:
            thread.quit()
            if not thread.wait(500):  # Уменьшили время ожидания
                thread.terminate()
                thread.wait()
        
        # Сохраняем данные
        try:
            if hasattr(self, 'config') and self.config:
                self.save_config()
            if hasattr(self, 'progress_data') and self.progress_data:
                self.save_progress()
        except:
            pass

        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = UpdaterUI()
    window.show()
    sys.exit(app.exec())