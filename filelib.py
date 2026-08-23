#!/usr/bin/env python3
"""
filelib — CLI-библиотека файлов с папками и подпапками.

  root@filelib:~$ _

Возможности:
  - организация файлов в дерево папок/подпапок (как обычная файловая система)
  - добавление, перемещение, поиск, открытие файлов из терминала
  - локальный веб-сервер в "хакерском" стиле (чёрный фон, зелёный моноширинный
    текст, матричный дождь) для просмотра / скачивания / загрузки файлов
    из браузера — в том числе с телефона в той же сети

Команды:
  filelib add <файл> [--to ПУТЬ] [--name ИМЯ] [--tag ТЕГ ...] [--move]
  filelib mkdir <путь>
  filelib ls [путь]
  filelib tree [путь]
  filelib find <запрос>
  filelib mv <источник> <папка_назначения>
  filelib info <путь_или_имя_или_id>
  filelib open <путь_или_имя_или_id>
  filelib rm <путь_или_имя_или_id> [--recursive] [--yes]
  filelib serve [--port 8765] [--host 0.0.0.0] [--no-browser]

Никаких сторонних зависимостей — только стандартная библиотека Python 3.
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import html
import io
import json
import mimetypes
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import uuid
import webbrowser
import zipfile
from datetime import datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse, parse_qs, quote

# ==========================================================================
# Хранилище
# ==========================================================================

CONFIG_DIR = Path(os.environ.get("FILELIB_HOME", str(Path.home() / ".filelib")))
FILES_DIR = CONFIG_DIR / "files"
TRASH_DIR = CONFIG_DIR / "trash"
INDEX_PATH = CONFIG_DIR / "library.json"
SECRET_PATH = CONFIG_DIR / "secret.key"

AUTH_ACTIONS = ("view", "download", "delete")
UNLOCK_TTL_SECONDS = 12 * 3600  # how long an unlocked cookie stays valid

# Удалённые файлы/папки не стираются физически сразу — они переезжают в
# .trash и хранятся там N дней (можно восстановить), после чего чистятся
# автоматически при следующей загрузке индекса.
TRASH_RETENTION_DAYS = int(os.environ.get("FILELIB_TRASH_DAYS", "30"))

# --------------------------------------------------------------------------
# Аккаунты (login/password) — создаются и управляются ТОЛЬКО из терминала.
# По умолчанию (без входа в аккаунт) разрешены только view/download
# незапароленных объектов; upload/mkdir/delete/security требуют аккаунт
# с соответствующим правом.
# --------------------------------------------------------------------------
USER_PERMISSIONS = ("upload", "mkdir", "delete", "security", "admin")
SESSION_TTL_SECONDS = 12 * 3600


def get_secret() -> bytes:
    """Persistent random secret used to sign unlock cookies (stateless sessions)."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not SECRET_PATH.exists():
        SECRET_PATH.write_bytes(secrets.token_bytes(32))
    return SECRET_PATH.read_bytes()


def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    _, digest_hex = hash_password(password, salt)
    return hmac.compare_digest(digest_hex, hash_hex)


def make_unlock_token(action: str, ttl_seconds: int = UNLOCK_TTL_SECONDS) -> str:
    secret = get_secret()
    expiry = int(time.time()) + ttl_seconds
    msg = f"{action}:{expiry}".encode()
    sig = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    raw = f"{action}:{expiry}:{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def verify_unlock_token(token: str, action: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        # rsplit, не split: `action` для файловых токенов имеет вид
        # "file:<file_id>" и сам содержит двоеточие, поэтому split(":", 2)
        # резал строку не в том месте и разблокировка всегда проваливалась.
        act, expiry_s, sig = raw.rsplit(":", 2)
        if act != action:
            return False
        secret = get_secret()
        msg = f"{act}:{expiry_s}".encode()
        expected = hmac.new(secret, msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return False
        return int(expiry_s) >= int(time.time())
    except Exception:
        return False


def make_session_token(login: str, ttl_seconds: int = SESSION_TTL_SECONDS) -> str:
    """Подписанный токен сессии: несёт только логин, права всегда проверяются
    заново по актуальным данным в library.json (чтобы отзыв прав/удаление
    аккаунта срабатывали мгновенно, даже если старая кука ещё жива)."""
    secret = get_secret()
    expiry = int(time.time()) + ttl_seconds
    msg = f"{login}:{expiry}".encode()
    sig = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    raw = f"{login}:{expiry}:{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def verify_session_token(token: str):
    """Возвращает логин, если токен валиден и не истёк, иначе None."""
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        login, expiry_s, sig = raw.rsplit(":", 2)
        secret = get_secret()
        msg = f"{login}:{expiry_s}".encode()
        expected = hmac.new(secret, msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        if int(expiry_s) < int(time.time()):
            return None
        return login
    except Exception:
        return None


def find_user(data, login: str):
    if not login:
        return None
    login_low = login.lower()
    return next((u for u in data.get("users", []) if u["login"].lower() == login_low), None)


def user_has_permission(user, perm: str) -> bool:
    if not user:
        return False
    perms = user.get("permissions", [])
    return "admin" in perms or perm in perms


def file_is_protected(item) -> bool:
    return item.get("password") is not None


def user_can_bypass_file_password(user, item) -> bool:
    """True, если аккаунту не нужен пароль конкретного файла: он либо
    имеет право 'security'/'admin', либо ему выдан персональный доступ
    к этому файлу без пароля."""
    if not file_is_protected(item):
        return True
    if user_has_permission(user, "security"):
        return True
    if user and item["id"] in user.get("unlocked_files", []):
        return True
    return False


def ensure_storage():
    FILES_DIR.mkdir(parents=True, exist_ok=True)
    TRASH_DIR.mkdir(parents=True, exist_ok=True)
    if not INDEX_PATH.exists():
        INDEX_PATH.write_text(json.dumps({"folders": [], "files": [], "users": [], "trash": []}, ensure_ascii=False), encoding="utf-8")


def load_index():
    ensure_storage()
    try:
        raw = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        raw = {}

    # Миграция со старого формата (версия без папок хранила просто список файлов).
    if isinstance(raw, list):
        data = {"folders": [], "files": raw}
        migrated = True
    elif isinstance(raw, dict):
        data = raw
        migrated = False
    else:
        data = {}
        migrated = False

    data.setdefault("folders", [])
    data.setdefault("files", [])
    if not isinstance(data["folders"], list):
        data["folders"] = []
    if not isinstance(data["files"], list):
        data["files"] = []

    # Гарантируем, что у каждого файла есть поле "folder" (старые записи его не имели),
    # и поле "password" — индивидуальный пароль файла (None = не защищён).
    for it in data["files"]:
        if "folder" not in it:
            it["folder"] = ""
            migrated = True
        if "password" not in it:
            it["password"] = None
            migrated = True

    auth = data.get("auth")
    if not isinstance(auth, dict):
        auth = {}
        migrated = True
    for act in AUTH_ACTIONS:
        if act not in auth:
            auth[act] = None
            migrated = True
    data["auth"] = auth

    if not isinstance(data.get("users"), list):
        data["users"] = []
        migrated = True

    # Гарантируем, что у каждого аккаунта есть "unlocked_files" — список id
    # файлов, которые этому аккаунту разрешено смотреть/скачивать без ввода
    # индивидуального пароля файла (выдаётся вручную владельцем/security).
    for u in data["users"]:
        if "unlocked_files" not in u or not isinstance(u.get("unlocked_files"), list):
            u["unlocked_files"] = []
            migrated = True

    if not isinstance(data.get("trash"), list):
        data["trash"] = []
        migrated = True

    if purge_expired_trash(data):
        migrated = True

    if migrated:
        save_index(data)

    return data


def save_index(data):
    INDEX_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def human_size(n):
    n = float(n)
    for unit in ["Б", "КБ", "МБ", "ГБ", "ТБ"]:
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ПБ"


# --------------------------------------------------------------------------
# Работа с путями/деревом папок
# --------------------------------------------------------------------------

def norm_path(p: str) -> str:
    """Нормализует логический путь в библиотеке: 'a/b/c', без ведущих/конечных слэшей."""
    if not p:
        return ""
    parts = [seg for seg in p.replace("\\", "/").split("/") if seg not in ("", ".")]
    return "/".join(parts)


def parent_of(path: str) -> str:
    path = norm_path(path)
    if "/" not in path:
        return ""
    return path.rsplit("/", 1)[0]


def basename_of(path: str) -> str:
    path = norm_path(path)
    return path.rsplit("/", 1)[-1] if path else ""


def join_path(parent: str, name: str) -> str:
    parent = norm_path(parent)
    name = name.strip("/")
    return f"{parent}/{name}" if parent else name


def all_folder_paths(data) -> set:
    """Все существующие папки: явно созданные + предки папок файлов."""
    paths = set(data.get("folders", []))
    for it in data["files"]:
        folder = it.get("folder", "")
        p = folder
        while p:
            paths.add(p)
            p = parent_of(p)
    paths.add("")
    return paths


def ensure_folder_chain(data, path: str):
    """mkdir -p: гарантирует, что путь и все родители зарегистрированы как папки."""
    path = norm_path(path)
    p = path
    chain = []
    while p:
        chain.append(p)
        p = parent_of(p)
    for folder in reversed(chain):
        if folder not in data["folders"]:
            data["folders"].append(folder)


def list_children(data, path: str, folder_paths: set = None):
    """Возвращает (подпапки, файлы) в указанной папке (не рекурсивно).

    `folder_paths`, если передан (например, заранее посчитанный
    all_folder_paths(data)), используется вместо пересчёта — это важно
    для рекурсивных обходов (см. _tree_lines), где пересчёт всех папок
    на каждом узле дерева давал бы O(n²) на больших библиотеках."""
    path = norm_path(path)
    if folder_paths is None:
        folder_paths = all_folder_paths(data)
    subfolders = set()
    for f in folder_paths:
        if f == "" or f == path:
            continue
        if parent_of(f) == path:
            subfolders.add(basename_of(f))
    files = [it for it in data["files"] if norm_path(it.get("folder", "")) == path]
    files.sort(key=lambda it: it["name"].lower())
    return sorted(subfolders), files


def full_file_path(entry) -> str:
    folder = norm_path(entry.get("folder", ""))
    return join_path(folder, entry["name"])


def resolve_file(data, key: str):
    """Найти файл по точному логическому пути, иначе по имени/id где-угодно в дереве."""
    key_norm = norm_path(key)
    for it in data["files"]:
        if full_file_path(it).lower() == key_norm.lower():
            return it
    key_low = key.lower()
    by_id = [it for it in data["files"] if it["id"].startswith(key_low)]
    if len(by_id) == 1:
        return by_id[0]
    exact_name = [it for it in data["files"] if it["name"].lower() == key_low]
    if len(exact_name) == 1:
        return exact_name[0]
    partial = [it for it in data["files"] if key_low in it["name"].lower()]
    if len(partial) == 1:
        return partial[0]
    candidates = by_id or exact_name or partial
    if len(candidates) > 1:
        err(f"Неоднозначный запрос '{key}' — подходит несколько файлов:")
        for it in candidates:
            sys.stderr.write(f"    {it['id'][:8]}  {full_file_path(it)}\n")
        sys.exit(1)
    return None


def resolve_folder(data, key: str):
    """Найти папку по точному пути, иначе по совпадению последнего сегмента."""
    key_norm = norm_path(key)
    folders = all_folder_paths(data)
    if key_norm in folders:
        return key_norm
    key_low = key_norm.lower()
    matches = [f for f in folders if f and basename_of(f).lower() == key_low]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        err(f"Неоднозначный путь к папке '{key}':")
        for f in matches:
            sys.stderr.write(f"    /{f}\n")
        sys.exit(1)
    return None


def delete_folder_recursive(data, folder_path: str):
    """Удаляет папку `folder_path` и всё её содержимое (файлы + подпапки)
    из `data` (in-place, без save_index). Файлы не стираются физически —
    они переезжают в корзину (см. move_to_trash), откуда их можно
    восстановить. Возвращает список удалённых файловых записей (уже в
    виде записей корзины). Не проверяет права — вызывающий код отвечает
    за авторизацию."""
    folder_path = norm_path(folder_path)
    sub_files = [it for it in data["files"]
                 if norm_path(it.get("folder", "")) == folder_path
                 or norm_path(it.get("folder", "")).startswith(folder_path + "/")]
    sub_folders = [f for f in all_folder_paths(data)
                    if f == folder_path or f.startswith(folder_path + "/")]
    trashed = []
    for it in sub_files:
        trashed.append(move_to_trash(data, it))
    data["folders"] = [f for f in data["folders"] if f not in sub_folders]
    return trashed


# --------------------------------------------------------------------------
# Корзина (.trash) — вместо немедленного физического удаления файл переезжает
# в TRASH_DIR и хранится там TRASH_RETENTION_DAYS дней с возможностью
# восстановления. Это единственная операция, у которой раньше не было отката.
# --------------------------------------------------------------------------

def move_to_trash(data, item):
    """Переносит запись файла `item` (уже удалена или удаляется из
    data["files"] вызывающим кодом) физически в TRASH_DIR и добавляет
    запись в data["trash"]. Возвращает добавленную запись корзины.
    Не вызывает save_index — это обязанность вызывающего кода."""
    data["files"] = [x for x in data["files"] if x["id"] != item["id"]]
    src = FILES_DIR / item["stored_filename"]
    trashed_filename = f"trash_{item['id']}_{item['stored_filename']}"
    dst = TRASH_DIR / trashed_filename
    if src.exists():
        shutil.move(str(src), str(dst))
    entry = dict(item)
    entry["trashed_stored_filename"] = trashed_filename
    entry["deleted_at"] = datetime.now().isoformat(timespec="seconds")
    data.setdefault("trash", []).append(entry)
    return entry


def purge_trash_entry(data, entry):
    """Стирает одну запись корзины физически и из data (без save_index)."""
    p = TRASH_DIR / entry.get("trashed_stored_filename", "")
    if p.exists():
        p.unlink()
    data["trash"] = [x for x in data.get("trash", []) if x["id"] != entry["id"]]


def purge_expired_trash(data) -> bool:
    """Стирает физически всё в корзине старше TRASH_RETENTION_DAYS.
    Возвращает True, если что-то было удалено (нужно save_index)."""
    cutoff = time.time() - TRASH_RETENTION_DAYS * 86400
    expired = []
    for entry in data.get("trash", []):
        try:
            deleted_ts = datetime.fromisoformat(entry["deleted_at"]).timestamp()
        except Exception:
            deleted_ts = 0
        if deleted_ts < cutoff:
            expired.append(entry)
    for entry in expired:
        purge_trash_entry(data, entry)
    return bool(expired)


def restore_from_trash(data, trash_id: str):
    """Восстанавливает файл из корзины по id. Возвращает восстановленную
    запись файла или None, если не найдена. Не вызывает save_index."""
    entry = next((x for x in data.get("trash", []) if x["id"] == trash_id), None)
    if entry is None:
        return None
    src = TRASH_DIR / entry.get("trashed_stored_filename", "")
    dst = FILES_DIR / entry["stored_filename"]
    if src.exists():
        # На случай коллизии имени с уже существующим файлом в FILES_DIR.
        if dst.exists():
            dst = FILES_DIR / f"{uuid.uuid4().hex}_{entry['stored_filename']}"
            entry["stored_filename"] = dst.name
        shutil.move(str(src), str(dst))
    if entry.get("folder"):
        ensure_folder_chain(data, entry["folder"])
    restored = {k: v for k, v in entry.items() if k not in ("trashed_stored_filename", "deleted_at")}
    data["trash"] = [x for x in data.get("trash", []) if x["id"] != trash_id]
    data.setdefault("files", []).append(restored)
    return restored


def _move_folder(data, src_folder: str, dest_folder: str) -> bool:
    """Перемещает папку `src_folder` (и всё содержимое) внутрь `dest_folder`
    (in-place, без save_index). Возвращает True при успехе, False если
    путь некорректен (папка не существует или перемещается сама в себя)."""
    src_folder = norm_path(src_folder)
    dest_folder = norm_path(dest_folder)
    if not src_folder or src_folder not in all_folder_paths(data):
        return False
    new_path = join_path(dest_folder, basename_of(src_folder))
    if new_path == src_folder or new_path.startswith(src_folder + "/"):
        return False
    ensure_folder_chain(data, new_path)
    for i, f in enumerate(data["folders"]):
        if f == src_folder:
            data["folders"][i] = new_path
        elif f.startswith(src_folder + "/"):
            data["folders"][i] = new_path + f[len(src_folder):]
    for it in data["files"]:
        fld = norm_path(it.get("folder", ""))
        if fld == src_folder:
            it["folder"] = new_path
        elif fld.startswith(src_folder + "/"):
            it["folder"] = new_path + fld[len(src_folder):]
    return True


def _folder_files_recursive(data, folder_path: str):
    """Все файловые записи внутри `folder_path`, включая подпапки."""
    folder_path = norm_path(folder_path)
    return [
        it for it in data["files"]
        if norm_path(it.get("folder", "")) == folder_path
        or norm_path(it.get("folder", "")).startswith(folder_path + "/")
    ]


# ==========================================================================
# "Хакерский" вывод в терминал
# ==========================================================================

_USE_COLOR = sys.stdout.isatty()

_C = {
    "green": "\033[92m",
    "bgreen": "\033[1;92m",
    "cyan": "\033[96m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def c(text, color):
    if not _USE_COLOR:
        return text
    return f"{_C[color]}{text}{_C['reset']}"


def ok(msg):
    print(c("[+] ", "bgreen") + msg)


def info_msg(msg):
    print(c("[*] ", "cyan") + msg)


def err(msg):
    sys.stderr.write(c("[!] ", "red") + msg + "\n")


BANNER = r"""
░██████████░██░██            ░██         ░██░██        
░██           ░██            ░██            ░██        
░██        ░██░██  ░███████  ░██         ░██░████████  
░█████████ ░██░██ ░██    ░██ ░██         ░██░██    ░██ 
░██        ░██░██ ░█████████ ░██         ░██░██    ░██ 
░██        ░██░██ ░██        ░██         ░██░███   ░██ 
░██        ░██░██  ░███████  ░██████████ ░██░██░█████  
                                                       
                                                       
                                                       
""".rstrip("\n")


def print_banner():
    print(c(BANNER, "green"))
    print(c("     [ CLI file library // hacker edition ]", "dim"))
    print()


# ==========================================================================
# Команды CLI
# ==========================================================================

def cmd_add(args):
    data = load_index()
    src = Path(args.path).expanduser().resolve()
    if not src.exists() or not src.is_file():
        err(f"файл не найден: {src}")
        sys.exit(1)

    target_folder = norm_path(args.to or "")
    if target_folder:
        ensure_folder_chain(data, target_folder)

    file_id = uuid.uuid4().hex
    name = args.name or src.name
    dest = FILES_DIR / f"{file_id}_{src.name}"

    if args.move:
        shutil.move(str(src), str(dest))
    else:
        shutil.copy2(str(src), str(dest))

    entry = {
        "id": file_id,
        "name": name,
        "stored_filename": dest.name,
        "size": dest.stat().st_size,
        "added": datetime.now().isoformat(timespec="seconds"),
        "tags": args.tag or [],
        "folder": target_folder,
        "password": None,
    }
    data["files"].append(entry)
    save_index(data)
    display_path = join_path(target_folder, name)
    ok(f"загружено в библиотеку: {c('/' + display_path, 'green')}  ({human_size(entry['size'])})  id={file_id[:8]}")


def cmd_mkdir(args):
    data = load_index()
    path = norm_path(args.path)
    if not path:
        err("нельзя создать корень")
        sys.exit(1)
    existed = path in all_folder_paths(data)
    ensure_folder_chain(data, path)
    save_index(data)
    if existed:
        info_msg(f"папка уже существует: /{path}")
    else:
        ok(f"создана папка: /{path}")


def cmd_ls(args):
    data = load_index()
    folder_paths = all_folder_paths(data)
    path = norm_path(args.path or "")
    if path and path not in folder_paths:
        err(f"папка не найдена: /{path}")
        sys.exit(1)
    subfolders, files = list_children(data, path, folder_paths)

    header = f"/{path}" if path else "/"
    print(c(f"root@filelib", "bgreen") + c(":", "dim") + c(header, "cyan") + c("$ ls -la", "dim"))
    print(c("-" * 78, "dim"))

    if not subfolders and not files:
        print(c("    (пусто)", "dim"))
        return

    for sf in subfolders:
        print(f"  {c('d', 'yellow')}  {c(sf + '/', 'bgreen')}")
    for it in files:
        tags = ",".join(it.get("tags", []))
        tag_str = c(f"  #{tags}", "dim") if tags else ""
        print(f"  {c('-', 'dim')}  {it['name']:35} {human_size(it['size']):>10}  "
              f"{c(it['added'], 'dim')}  {c(it['id'][:8], 'dim')}{tag_str}")

    print(c("-" * 78, "dim"))
    print(c(f"    {len(subfolders)} папок, {len(files)} файлов", "dim"))


def _tree_lines(data, path, folder_paths, prefix=""):
    lines = []
    subfolders, files = list_children(data, path, folder_paths)
    entries = [(True, sf) for sf in subfolders] + [(False, it) for it in files]
    for i, (is_folder, item) in enumerate(entries):
        last = i == len(entries) - 1
        connector = "└── " if last else "├── "
        if is_folder:
            lines.append(prefix + c(connector, "dim") + c(item + "/", "bgreen"))
            ext_prefix = prefix + ("    " if last else c("│   ", "dim"))
            lines.extend(_tree_lines(data, join_path(path, item), folder_paths, ext_prefix))
        else:
            size = human_size(item["size"])
            lines.append(prefix + c(connector, "dim") + f"{item['name']}  {c(size, 'dim')}")
    return lines


def cmd_tree(args):
    data = load_index()
    folder_paths = all_folder_paths(data)
    root = norm_path(args.path or "")
    if root and root not in folder_paths:
        err(f"папка не найдена: /{root}")
        sys.exit(1)
    print(c(f"/{root}" if root else "/ (root)", "cyan"))
    for line in _tree_lines(data, root, folder_paths):
        print(line)


def cmd_find(args):
    data = load_index()
    q = args.query.lower()
    matches = [
        it for it in data["files"]
        if q in it["name"].lower() or q in [t.lower() for t in it.get("tags", [])]
    ]
    if not matches:
        info_msg(f"ничего не найдено по запросу '{args.query}'")
        return
    print(c(f"[grep] совпадений: {len(matches)}", "cyan"))
    for it in matches:
        print(f"  {c(it['id'][:8], 'dim')}  /{full_file_path(it)}  {c(human_size(it['size']), 'dim')}")


def cmd_mv(args):
    data = load_index()
    src_key = norm_path(args.source)
    dest_key = norm_path(args.dest)

    # Сначала пробуем как файл
    file_entry = resolve_file(data, args.source)
    if file_entry is not None and full_file_path(file_entry).lower() == src_key.lower():
        dest_folder = resolve_folder(data, dest_key) if dest_key else ""
        if dest_key and dest_folder is None:
            ensure_folder_chain(data, dest_key)
            dest_folder = dest_key
        file_entry["folder"] = dest_folder
        save_index(data)
        ok(f"перемещено: /{full_file_path(file_entry)}")
        return

    # Иначе пробуем как папку
    src_folder = resolve_folder(data, args.source)
    if src_folder is not None and src_folder != "":
        dest_folder = resolve_folder(data, dest_key) if dest_key else ""
        if dest_key and dest_folder is None:
            ensure_folder_chain(data, dest_key)
            dest_folder = dest_key
        new_path = join_path(dest_folder, basename_of(src_folder))
        if new_path == src_folder or new_path.startswith(src_folder + "/"):
            err("нельзя переместить папку внутрь самой себя")
            sys.exit(1)
        ensure_folder_chain(data, new_path)
        for i, f in enumerate(data["folders"]):
            if f == src_folder:
                data["folders"][i] = new_path
            elif f.startswith(src_folder + "/"):
                data["folders"][i] = new_path + f[len(src_folder):]
        for it in data["files"]:
            fld = norm_path(it.get("folder", ""))
            if fld == src_folder:
                it["folder"] = new_path
            elif fld.startswith(src_folder + "/"):
                it["folder"] = new_path + fld[len(src_folder):]
        save_index(data)
        ok(f"перемещена папка: /{src_folder} -> /{new_path}")
        return

    err(f"не найдено: {args.source}")
    sys.exit(1)


def cmd_info(args):
    data = load_index()
    it = resolve_file(data, args.key)
    if not it:
        err(f"файл не найден: {args.key}")
        sys.exit(1)
    path = FILES_DIR / it["stored_filename"]
    print(c("--- file info ---", "cyan"))
    print(f"  Путь:     /{full_file_path(it)}")
    print(f"  ID:       {it['id']}")
    print(f"  Размер:   {human_size(it['size'])}")
    print(f"  Добавлен: {it['added']}")
    print(f"  Теги:     {', '.join(it.get('tags', [])) or '—'}")
    print(f"  Диск:     {path}")


def _open_with_system(path: Path):
    if sys.platform.startswith("darwin"):
        subprocess.run(["open", str(path)], check=False)
    elif sys.platform.startswith("win"):
        os.startfile(str(path))  # type: ignore[attr-defined]
    else:
        subprocess.run(["xdg-open", str(path)], check=False)


def cmd_open(args):
    data = load_index()
    it = resolve_file(data, args.key)
    if not it:
        err(f"файл не найден: {args.key}")
        sys.exit(1)
    path = FILES_DIR / it["stored_filename"]
    info_msg(f"открываю /{full_file_path(it)} ...")
    _open_with_system(path)


def cmd_rm(args):
    data = load_index()

    file_entry = resolve_file(data, args.key)
    exact_file = file_entry and full_file_path(file_entry).lower() == norm_path(args.key).lower()
    folder_match = resolve_folder(data, args.key) if not exact_file else None

    if file_entry and (exact_file or folder_match is None):
        if not args.yes:
            answer = input(c(f"[?] удалить файл '{full_file_path(file_entry)}'? [y/N] ", "yellow")).strip().lower()
            if answer not in ("y", "yes", "д", "да"):
                info_msg("отменено")
                return
        move_to_trash(data, file_entry)
        save_index(data)
        ok(f"удалено (в корзину, restore: filelib trash restore {file_entry['id'][:8]}): /{full_file_path(file_entry)}")
        return

    if folder_match is not None:
        sub_files = [it for it in data["files"]
                     if norm_path(it.get("folder", "")) == folder_match
                     or norm_path(it.get("folder", "")).startswith(folder_match + "/")]
        sub_folders = [f for f in all_folder_paths(data)
                        if f == folder_match or f.startswith(folder_match + "/")]
        if (sub_files or len(sub_folders) > 1) and not args.recursive:
            err(f"папка /{folder_match} не пуста — используйте --recursive")
            sys.exit(1)
        if not args.yes:
            answer = input(c(
                f"[?] удалить папку /{folder_match} и {len(sub_files)} файл(ов) в ней? [y/N] ", "yellow"
            )).strip().lower()
            if answer not in ("y", "yes", "д", "да"):
                info_msg("отменено")
                return
        deleted = delete_folder_recursive(data, folder_match)
        save_index(data)
        ok(f"удалена папка /{folder_match} ({len(deleted)} файлов перенесено в корзину)")
        return

    err(f"не найдено: {args.key}")
    sys.exit(1)


def cmd_trash_ls(args):
    data = load_index()
    trash = data.get("trash", [])
    print(c("root@filelib", "bgreen") + c(":~$ ", "dim") + c("ls .trash", "dim"))
    print(c("-" * 78, "dim"))
    if not trash:
        print(c(f"    (корзина пуста, автоочистка через {TRASH_RETENTION_DAYS} дн.)", "dim"))
        return
    for it in trash:
        print(f"  {c(it['id'][:8], 'dim')}  /{full_file_path(it)}  {human_size(it['size']):>10}  "
              f"{c('удалён: ' + it.get('deleted_at', '—'), 'dim')}")
    print(c("-" * 78, "dim"))
    print(c(f"    {len(trash)} объект(ов), хранение {TRASH_RETENTION_DAYS} дн.", "dim"))


def cmd_trash_restore(args):
    data = load_index()
    key_low = args.key.lower()
    matches = [it for it in data.get("trash", []) if it["id"].startswith(key_low)]
    if not matches:
        matches = [it for it in data.get("trash", []) if key_low in it["name"].lower()]
    if not matches:
        err(f"в корзине не найдено: {args.key}")
        sys.exit(1)
    if len(matches) > 1:
        err(f"неоднозначный запрос '{args.key}':")
        for it in matches:
            sys.stderr.write(f"    {it['id'][:8]}  /{full_file_path(it)}\n")
        sys.exit(1)
    restored = restore_from_trash(data, matches[0]["id"])
    save_index(data)
    ok(f"восстановлено: /{full_file_path(restored)}")


def cmd_trash_empty(args):
    data = load_index()
    trash = data.get("trash", [])
    if not trash:
        info_msg("корзина уже пуста")
        return
    if not args.yes:
        answer = input(c(f"[?] окончательно стереть {len(trash)} объект(ов) из корзины? [y/N] ", "yellow")).strip().lower()
        if answer not in ("y", "yes", "д", "да"):
            info_msg("отменено")
            return
    for entry in list(trash):
        purge_trash_entry(data, entry)
    save_index(data)
    ok("корзина очищена")


# ==========================================================================
# Аккаунты (login/password) — только из терминала
# ==========================================================================

def _prompt_new_password(login: str) -> str:
    while True:
        p1 = getpass.getpass(f"Пароль для '{login}': ")
        if not p1:
            err("пароль не может быть пустым")
            continue
        p2 = getpass.getpass("Повторите пароль: ")
        if p1 != p2:
            err("пароли не совпадают, попробуйте ещё раз")
            continue
        return p1


def cmd_user_add(args):
    data = load_index()
    login = args.login.strip()
    if not login:
        err("логин не может быть пустым")
        sys.exit(1)
    if find_user(data, login):
        err(f"аккаунт уже существует: {login}")
        sys.exit(1)

    password = args.password or _prompt_new_password(login)
    perms = set(args.permission or [])
    if args.admin:
        perms.add("admin")
    unknown = perms - set(USER_PERMISSIONS)
    if unknown:
        err(f"неизвестные права: {', '.join(sorted(unknown))} (доступны: {', '.join(USER_PERMISSIONS)})")
        sys.exit(1)

    salt_hex, hash_hex = hash_password(password)
    data.setdefault("users", []).append({
        "login": login,
        "salt": salt_hex,
        "hash": hash_hex,
        "permissions": sorted(perms),
        "unlocked_files": [],
        "created": datetime.now().isoformat(timespec="seconds"),
    })
    save_index(data)
    perms_str = ", ".join(sorted(perms)) or "(нет — только view/download незапароленного, как у всех)"
    ok(f"аккаунт создан: {c(login, 'bgreen')}  права: {perms_str}")


def cmd_user_passwd(args):
    data = load_index()
    user = find_user(data, args.login)
    if not user:
        err(f"аккаунт не найден: {args.login}")
        sys.exit(1)
    password = args.password or _prompt_new_password(user["login"])
    salt_hex, hash_hex = hash_password(password)
    user["salt"], user["hash"] = salt_hex, hash_hex
    save_index(data)
    ok(f"пароль обновлён для аккаунта: {c(user['login'], 'bgreen')}")


def cmd_user_rm(args):
    data = load_index()
    user = find_user(data, args.login)
    if not user:
        err(f"аккаунт не найден: {args.login}")
        sys.exit(1)
    if not args.yes:
        answer = input(c(f"[?] удалить аккаунт '{user['login']}'? [y/N] ", "yellow")).strip().lower()
        if answer not in ("y", "yes", "д", "да"):
            info_msg("отменено")
            return
    data["users"] = [u for u in data["users"] if u["login"].lower() != user["login"].lower()]
    save_index(data)
    ok(f"аккаунт удалён: {user['login']}")


def cmd_user_grant(args):
    data = load_index()
    user = find_user(data, args.login)
    if not user:
        err(f"аккаунт не найден: {args.login}")
        sys.exit(1)
    if args.permission not in USER_PERMISSIONS:
        err(f"неизвестное право: {args.permission} (доступны: {', '.join(USER_PERMISSIONS)})")
        sys.exit(1)
    perms = set(user.get("permissions", []))
    if args.permission in perms:
        info_msg(f"у '{user['login']}' уже есть право '{args.permission}'")
        return
    perms.add(args.permission)
    user["permissions"] = sorted(perms)
    save_index(data)
    ok(f"выдано право '{args.permission}' аккаунту {c(user['login'], 'bgreen')}")


def cmd_user_revoke(args):
    data = load_index()
    user = find_user(data, args.login)
    if not user:
        err(f"аккаунт не найден: {args.login}")
        sys.exit(1)
    perms = set(user.get("permissions", []))
    if args.permission not in perms:
        info_msg(f"у '{user['login']}' и так нет права '{args.permission}'")
        return
    perms.discard(args.permission)
    user["permissions"] = sorted(perms)
    save_index(data)
    ok(f"право '{args.permission}' отозвано у аккаунта {c(user['login'], 'bgreen')}")


def cmd_user_ls(args):
    data = load_index()
    users = data.get("users", [])
    print(c("root@filelib", "bgreen") + c(":~$ ", "dim") + c("cat /etc/passwd", "dim"))
    print(c("-" * 78, "dim"))
    if not users:
        print(c("    (аккаунтов ещё нет — filelib user add <логин>)", "dim"))
        return
    for u in users:
        perms = ", ".join(u.get("permissions", [])) or c("(только просмотр/скачивание, как у всех)", "dim")
        print(f"  {c(u['login'], 'bgreen'):25} {perms}")
        print(f"      {c('создан: ' + u.get('created', '—'), 'dim')}")
    print(c("-" * 78, "dim"))
    print(c(f"    {len(users)} аккаунт(ов)", "dim"))


# ==========================================================================
# Веб-сервер — хакерская тема
# ==========================================================================

DEFAULT_LANG = "en"

TRANSLATIONS = {
    "en": {
        "upload_title": "&gt; upload / inject file",
        "upload_button": "[ UPLOAD ]",
        "mkdir_title": "&gt; mkdir",
        "mkdir_placeholder": "new_folder_name",
        "mkdir_button": "[ CREATE ]",
        "search_placeholder": "grep -i ...",
        "col_name": "Name",
        "col_size": "Size",
        "col_added": "Added",
        "empty": "// empty. upload a file or create a folder above //",
        "dir_label": "&lt;DIR&gt;",
        "view_btn": "VIEW",
        "get_btn": "GET",
        "del_btn": "DEL",
        "confirm_delete": "delete {name}?",
        "del_folder_btn": "DEL DIR",
        "confirm_delete_folder": "delete folder {name} and everything inside it? this cannot be undone.",
        "footer": "filelib :: local hacker-edition file server :: {count} objects in this directory",
        "security_title": "&gt; access control",
        "security_hint": "set a password to require it for VIEW / GET / DEL. leave blank + submit to lock with no way back in from the UI (clear it from the CLI/JSON if needed).",
        "action_view": "View",
        "action_download": "Download",
        "action_delete": "Delete",
        "status_protected": "PROTECTED",
        "status_open": "OPEN",
        "password_placeholder": "new password",
        "set_btn": "[ SET ]",
        "clear_btn": "[ CLEAR ]",
        "confirm_clear": "remove password protection for {action}?",
        "unlock_title": "&gt; protected — enter password",
        "unlock_hint": "this action is password-protected.",
        "unlock_placeholder": "password",
        "unlock_btn": "[ UNLOCK ]",
        "unlock_error": "wrong password. try again.",
        "back_link": "&larr; back",
        "login_title": "&gt; account login",
        "login_hint": "accounts are created from the terminal (filelib user add).",
        "login_user_placeholder": "login",
        "login_pass_placeholder": "password",
        "login_btn": "[ LOGIN ]",
        "login_error": "wrong login or password.",
        "logged_in_as": "logged in: {login}",
        "logout_btn": "[ logout ]",
        "login_link": "[ login ]",
        "no_permission_upload": "// log in with an 'upload' account to add files //",
        "no_permission_mkdir": "// log in with an 'mkdir' account to create folders //",
        "no_permission_security": "// log in with a 'security'/'admin' account to change access control //",
        "accounts_link": "[ accounts ]",
        "admin_title": "&gt; accounts",
        "admin_hint": "create accounts, set passwords, grant/revoke permissions, delete accounts — right here.",
        "add_user_title": "&gt; new account",
        "add_user_btn": "[ CREATE ACCOUNT ]",
        "existing_title": "&gt; existing accounts",
        "col_login": "Login",
        "col_permissions": "Permissions",
        "col_created": "Created",
        "col_new_password": "New password",
        "save_perms_btn": "[ SAVE ]",
        "set_password_btn": "[ SET ]",
        "delete_account_btn": "[ DELETE ]",
        "confirm_delete_account": "delete account {login}?",
        "no_accounts_yet": "// no accounts yet — create one below //",
        "col_access": "Access",
        "grant_btn": "[ GRANT ]",
        "grant_select_placeholder": "grant to account...",
        "file_unlock_title": "&gt; protected file",
        "file_unlock_hint": "'{name}' requires its own password.",
        "register_title": "&gt; create account",
        "register_hint": "an account with no extra rights can still view/download anything unprotected. ask an admin for more access.",
        "register_confirm_placeholder": "confirm password",
        "register_btn": "[ CREATE ACCOUNT ]",
        "register_error_empty": "login and password are required.",
        "register_error_mismatch": "passwords don't match.",
        "register_error_taken": "that login is already taken.",
        "register_link": "[ create account ]",
        "have_account_link": "[ already have an account? log in ]",
        "trash_link": "[ trash ]",
        "trash_title": "&gt; trash",
        "trash_hint": "deleted files land here and are wiped automatically after {days} days. restore or purge them for good.",
        "trash_empty_note": "// trash is empty //",
        "col_deleted": "Deleted",
        "restore_btn": "[ RESTORE ]",
        "purge_btn": "[ PURGE ]",
        "confirm_purge": "permanently delete {name}? this cannot be undone.",
        "empty_trash_btn": "[ EMPTY TRASH ]",
        "confirm_empty_trash": "permanently delete everything in trash? this cannot be undone.",
        "select_all": "select all",
        "bulk_delete_btn": "[ DELETE SELECTED ]",
        "bulk_move_btn": "[ MOVE SELECTED ]",
        "confirm_bulk_delete": "delete the selected items? they will go to trash.",
        "bulk_move_prompt": "move selected items to which folder? (blank = root)",
        "zip_btn": "[ ZIP FOLDER ]",
        "preview_btn": "PREVIEW",
        "preview_unavailable": "no inline preview for this file type.",
        "drag_hint": "tip: drag a row onto a folder to move it",
        "nothing_selected": "nothing selected",
        "uploading_label": "uploading... {percent}% ({loaded} / {total})",
        "upload_done_label": "upload complete, refreshing...",
        "upload_error_label": "upload failed. try again.",
    },
    "ru": {
        "upload_title": "&gt; загрузка / инъекция файла",
        "upload_button": "[ ЗАГРУЗИТЬ ]",
        "mkdir_title": "&gt; mkdir",
        "mkdir_placeholder": "имя_папки",
        "mkdir_button": "[ СОЗДАТЬ ]",
        "search_placeholder": "grep -i ...",
        "col_name": "Имя",
        "col_size": "Размер",
        "col_added": "Добавлен",
        "empty": "// пусто. загрузите файл или создайте папку выше //",
        "dir_label": "&lt;ПАПКА&gt;",
        "view_btn": "СМОТР",
        "get_btn": "СКАЧАТЬ",
        "del_btn": "УДАЛ",
        "confirm_delete": "удалить {name}?",
        "del_folder_btn": "УДАЛ ПАПКУ",
        "confirm_delete_folder": "удалить папку {name} со всем содержимым? отменить будет нельзя.",
        "footer": "filelib :: локальный файловый сервер (hacker edition) :: {count} объект(ов) в этой папке",
        "security_title": "&gt; контроль доступа",
        "security_hint": "установите пароль, чтобы потребовать его для СМОТРА / СКАЧИВАНИЯ / УДАЛЕНИЯ. очистить пароль можно только здесь же кнопкой СНЯТЬ.",
        "action_view": "Просмотр",
        "action_download": "Скачивание",
        "action_delete": "Удаление",
        "status_protected": "ЗАЩИЩЕНО",
        "status_open": "ОТКРЫТО",
        "password_placeholder": "новый пароль",
        "set_btn": "[ УСТАНОВИТЬ ]",
        "clear_btn": "[ СНЯТЬ ]",
        "confirm_clear": "снять защиту паролем для «{action}»?",
        "unlock_title": "&gt; защищено — введите пароль",
        "unlock_hint": "это действие защищено паролем.",
        "unlock_placeholder": "пароль",
        "unlock_btn": "[ РАЗБЛОКИРОВАТЬ ]",
        "unlock_error": "неверный пароль. попробуйте ещё раз.",
        "back_link": "&larr; назад",
        "login_title": "&gt; вход в аккаунт",
        "login_hint": "аккаунты создаются только из терминала (filelib user add).",
        "login_user_placeholder": "логин",
        "login_pass_placeholder": "пароль",
        "login_btn": "[ ВОЙТИ ]",
        "login_error": "неверный логин или пароль.",
        "logged_in_as": "вы вошли как: {login}",
        "logout_btn": "[ выйти ]",
        "login_link": "[ войти ]",
        "no_permission_upload": "// войдите в аккаунт с правом 'upload', чтобы загружать файлы //",
        "no_permission_mkdir": "// войдите в аккаунт с правом 'mkdir', чтобы создавать папки //",
        "no_permission_security": "// войдите в аккаунт с правом 'security'/'admin', чтобы менять контроль доступа //",
        "accounts_link": "[ аккаунты ]",
        "admin_title": "&gt; аккаунты",
        "admin_hint": "создание аккаунтов, смена пароля, выдача/отзыв прав, удаление аккаунтов — прямо здесь.",
        "add_user_title": "&gt; новый аккаунт",
        "add_user_btn": "[ СОЗДАТЬ АККАУНТ ]",
        "existing_title": "&gt; существующие аккаунты",
        "col_login": "Логин",
        "col_permissions": "Права",
        "col_created": "Создан",
        "col_new_password": "Новый пароль",
        "save_perms_btn": "[ СОХРАНИТЬ ]",
        "set_password_btn": "[ УСТАНОВИТЬ ]",
        "delete_account_btn": "[ УДАЛИТЬ ]",
        "confirm_delete_account": "удалить аккаунт {login}?",
        "no_accounts_yet": "// аккаунтов ещё нет — создайте ниже //",
        "col_access": "Доступ",
        "grant_btn": "[ ВЫДАТЬ ]",
        "grant_select_placeholder": "выдать аккаунту...",
        "file_unlock_title": "&gt; защищённый файл",
        "file_unlock_hint": "файл «{name}» защищён собственным паролем.",
        "register_title": "&gt; создать аккаунт",
        "register_hint": "аккаунт без прав всё равно может смотреть/скачивать всё незапароленное. за дополнительными правами — к администратору.",
        "register_confirm_placeholder": "повторите пароль",
        "register_btn": "[ СОЗДАТЬ АККАУНТ ]",
        "register_error_empty": "укажите логин и пароль.",
        "register_error_mismatch": "пароли не совпадают.",
        "register_error_taken": "такой логин уже занят.",
        "register_link": "[ создать аккаунт ]",
        "have_account_link": "[ уже есть аккаунт? войти ]",
        "trash_link": "[ корзина ]",
        "trash_title": "&gt; корзина",
        "trash_hint": "удалённые файлы попадают сюда и стираются автоматически через {days} дн. восстановите их или сотрите насовсем.",
        "trash_empty_note": "// корзина пуста //",
        "col_deleted": "Удалён",
        "restore_btn": "[ ВОССТАНОВИТЬ ]",
        "purge_btn": "[ СТЕРЕТЬ ]",
        "confirm_purge": "стереть «{name}» навсегда? отменить будет нельзя.",
        "empty_trash_btn": "[ ОЧИСТИТЬ КОРЗИНУ ]",
        "confirm_empty_trash": "стереть всё содержимое корзины навсегда? отменить будет нельзя.",
        "select_all": "выбрать всё",
        "bulk_delete_btn": "[ УДАЛИТЬ ВЫБРАННОЕ ]",
        "bulk_move_btn": "[ ПЕРЕМЕСТИТЬ ВЫБРАННОЕ ]",
        "confirm_bulk_delete": "удалить выбранное? файлы попадут в корзину.",
        "bulk_move_prompt": "переместить выбранное в какую папку? (пусто = корень)",
        "zip_btn": "[ СКАЧАТЬ ZIP ]",
        "preview_btn": "ПРЕВЬЮ",
        "preview_unavailable": "предпросмотр недоступен для этого типа файла.",
        "drag_hint": "подсказка: перетащите строку на папку, чтобы переместить",
        "nothing_selected": "ничего не выбрано",
        "uploading_label": "загрузка... {percent}% ({loaded} / {total})",
        "upload_done_label": "загрузка завершена, обновляю страницу...",
        "upload_error_label": "ошибка загрузки. попробуйте ещё раз.",
    },
}


def t(lang: str, key: str, **kwargs) -> str:
    lang = lang if lang in TRANSLATIONS else DEFAULT_LANG
    text = TRANSLATIONS[lang].get(key, TRANSLATIONS[DEFAULT_LANG].get(key, key))
    return text.format(**kwargs) if kwargs else text


PAGE_TEMPLATE = """<!doctype html>
<html lang="{html_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>filelib :: {path_title}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
  :root {{
    --bg: #060a06;
    --fg: #33ff66;
    --fg-dim: #1c8f3c;
    --fg-bright: #a6ffb0;
    --panel: #0b120b;
    --border: #1f5c2f;
    --accent: #00ffcc;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ background: var(--bg); margin: 0; padding: 0; }}
  body {{
    font-family: 'Share Tech Mono', 'Fira Code', Consolas, monospace;
    color: var(--fg);
    max-width: 960px;
    margin: 0 auto;
    padding: 1.5rem 1rem 4rem;
    position: relative;
    z-index: 1;
  }}
  #matrix {{
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    z-index: 0; opacity: .18; pointer-events: none;
  }}
  .scanlines {{
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: repeating-linear-gradient(
      to bottom, rgba(0,0,0,0) 0px, rgba(0,0,0,0) 2px, rgba(0,0,0,.25) 3px
    );
    z-index: 2; pointer-events: none; mix-blend-mode: overlay;
  }}
  pre.logo {{
    color: var(--fg-bright);
    text-shadow: 0 0 6px var(--fg), 0 0 14px var(--fg-dim);
    font-size: .62rem; line-height: 1.1; margin: 0 0 .2rem 0; overflow-x: auto;
  }}
  .subtitle {{ color: var(--fg-dim); margin: 0 0 1.2rem 0; }}
  .subtitle .cursor {{ animation: blink 1s steps(1) infinite; }}
  @keyframes blink {{ 50% {{ opacity: 0; }} }}

  .breadcrumb {{ margin-bottom: 1rem; color: var(--fg-dim); }}
  .breadcrumb a {{ color: var(--fg); text-decoration: none; }}
  .breadcrumb a:hover {{ color: var(--accent); text-shadow: 0 0 6px var(--accent); }}

  .panel {{
    border: 1px solid var(--border); background: var(--panel);
    border-radius: 4px; padding: 1rem; margin-bottom: 1.2rem;
    box-shadow: 0 0 20px rgba(51,255,102,0.05) inset;
  }}
  .panel h2 {{
    margin: 0 0 .8rem 0; font-size: .95rem; color: var(--fg-bright);
    text-transform: uppercase; letter-spacing: .08em;
  }}
  .row {{ display: flex; gap: .6rem; flex-wrap: wrap; align-items: center; }}
  input[type=text], input[type=file], input[type=password] {{
    background: #010401; border: 1px solid var(--border); color: var(--fg);
    padding: .5rem .6rem; font-family: inherit; font-size: .9rem; border-radius: 3px;
  }}
  input[type=text], input[type=password] {{ flex: 1; min-width: 140px; }}
  input[type=text]:focus, input[type=password]:focus {{ outline: none; border-color: var(--accent); box-shadow: 0 0 8px rgba(0,255,204,.4); }}
  .lang-switch {{ position: absolute; top: 1.2rem; right: 1rem; display: flex; gap: .4rem; z-index: 3; }}
  .lang-switch a {{
    border: 1px solid var(--fg-dim); color: var(--fg-dim); padding: .2rem .5rem;
    font-size: .72rem; text-decoration: none; border-radius: 3px; letter-spacing: .05em;
  }}
  .lang-switch a.active {{ border-color: var(--accent); color: var(--accent); box-shadow: 0 0 8px rgba(0,255,204,.35); }}
  .account-bar {{
    display: flex; justify-content: flex-end; align-items: center; gap: .6rem;
    margin: 0 0 .6rem 0; font-size: .78rem; color: var(--fg-dim);
  }}
  .account-bar a {{ color: var(--fg-dim); text-decoration: none; }}
  .account-bar a:hover {{ color: var(--accent); }}
  .locked-note {{ color: var(--fg-dim); font-size: .82rem; }}
  .sec-row {{ display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; padding: .6rem 0; border-bottom: 1px solid #123018; }}
  .sec-row:last-child {{ border-bottom: none; }}
  .sec-label {{ min-width: 110px; color: var(--fg-bright); }}
  .badge {{ font-size: .7rem; padding: .15rem .5rem; border-radius: 3px; letter-spacing: .05em; }}
  .badge.protected {{ color: #ff9d3d; border: 1px solid #ff9d3d; }}
  .badge.open {{ color: var(--fg-dim); border: 1px solid var(--fg-dim); }}
  .lock-mark {{ font-size: .8rem; }}
  button, .btn {{
    background: transparent; color: var(--fg); border: 1px solid var(--fg-dim);
    padding: .4rem .8rem; font-family: inherit; font-size: .8rem; cursor: pointer;
    border-radius: 3px; text-decoration: none; display: inline-block;
    transition: all .15s ease;
  }}
  button:hover, .btn:hover {{
    border-color: var(--accent); color: var(--accent); box-shadow: 0 0 10px rgba(0,255,204,.35);
  }}
  .btn.danger:hover {{ border-color: #ff4444; color: #ff4444; box-shadow: 0 0 10px rgba(255,68,68,.35); }}

  table {{ width: 100%; border-collapse: collapse; font-size: .88rem; }}
  th {{ text-align: left; color: var(--fg-dim); font-weight: normal; border-bottom: 1px solid var(--border);
        padding: .4rem; text-transform: uppercase; font-size: .72rem; letter-spacing: .06em; }}
  td {{ padding: .5rem .4rem; border-bottom: 1px solid #123018; vertical-align: middle; }}
  tr:hover td {{ background: rgba(51,255,102,.04); }}
  .folder-link {{ color: var(--fg-bright); text-decoration: none; font-weight: bold; }}
  .folder-link:hover {{ text-shadow: 0 0 8px var(--fg); }}
  .meta {{ color: var(--fg-dim); font-size: .78rem; }}
  .empty {{ color: var(--fg-dim); text-align: center; padding: 1.5rem; }}
  .actions form {{ display: inline; }}
  .file-sec {{ min-width: 200px; }}
  .file-sec select {{
    background: #010401; border: 1px solid var(--border); color: var(--fg);
    padding: .35rem .4rem; font-family: inherit; font-size: .78rem; border-radius: 3px;
  }}
  footer {{ color: var(--fg-dim); font-size: .75rem; margin-top: 2rem; text-align: center; }}
</style>
</head>
<body>
<canvas id="matrix"></canvas>
<div class="scanlines"></div>
<div class="lang-switch">{lang_switch}</div>

<pre class="logo">{logo}</pre>
<p class="subtitle">root@filelib:{path_title}$ <span class="cursor">▌</span></p>

<div class="account-bar">{account_bar}</div>

<div class="breadcrumb">{breadcrumb} &nbsp; <a class="btn" href="/zip?path={path_query}">{t_zip_btn}</a></div>

<div id="preview-modal" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,.75); z-index:50; padding:2rem;" onclick="if(event.target===this) closePreview();">
  <div style="max-width:900px; max-height:90vh; margin:0 auto; background:var(--panel); border:1px solid var(--border); border-radius:4px; padding:1rem; overflow:auto; position:relative;">
    <button type="button" class="btn" onclick="closePreview()" style="position:absolute; top:.6rem; right:.6rem;">×</button>
    <h2 id="preview-name" style="margin-top:0;"></h2>
    <div id="preview-body"></div>
  </div>
</div>

{upload_panel}

{mkdir_panel}

{security_panel}

<div class="row" style="margin-bottom: .8rem;">
  <input type="text" id="search" placeholder="{t_search_placeholder}" onkeyup="filterRows()">
</div>

{content}

<footer>{t_footer}</footer>

<script>
function filterRows() {{
  const q = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('tbody tr').forEach(tr => {{
    tr.style.display = tr.dataset.name.includes(q) ? '' : 'none';
  }});
}}

// --- чекбоксы / массовые операции ---
function toggleSelectAll(box) {{
  document.querySelectorAll('.row-check').forEach(cb => cb.checked = box.checked);
}}

function selectedItems() {{
  const files = [], folders = [];
  document.querySelectorAll('.row-check:checked').forEach(cb => {{
    if (cb.dataset.kind === 'file') files.push(cb.dataset.key);
    else folders.push(cb.dataset.key);
  }});
  return {{files, folders}};
}}

function fillBulkForm(form, sel, extra) {{
  form.innerHTML = '';
  const addField = (name, value) => {{
    const inp = document.createElement('input');
    inp.type = 'hidden'; inp.name = name; inp.value = value;
    form.appendChild(inp);
  }};
  sel.files.forEach(id => addField('file_ids', id));
  sel.folders.forEach(p => addField('folder_paths', p));
  addField('path', {path_json});
  Object.entries(extra || {{}}).forEach(([k, v]) => addField(k, v));
}}

function bulkDelete() {{
  const sel = selectedItems();
  if (sel.files.length + sel.folders.length === 0) {{ alert({nothing_selected_json}); return; }}
  if (!confirm({confirm_bulk_delete_json})) return;
  const form = document.getElementById('bulk-delete-form');
  fillBulkForm(form, sel, {{}});
  form.submit();
}}

function bulkMove() {{
  const sel = selectedItems();
  if (sel.files.length + sel.folders.length === 0) {{ alert({nothing_selected_json}); return; }}
  const dest = prompt({bulk_move_prompt_json}, '');
  if (dest === null) return;
  const form = document.getElementById('bulk-move-form');
  fillBulkForm(form, sel, {{dest: dest}});
  form.submit();
}}

// --- drag & drop перемещение ---
let dragPayload = null;

function dragStart(ev, kind, key) {{
  dragPayload = {{kind, key}};
  ev.dataTransfer.effectAllowed = 'move';
}}

function dragOver(ev) {{
  ev.preventDefault();
  ev.currentTarget.style.outline = '1px dashed var(--accent)';
}}

function dragLeave(ev) {{
  ev.currentTarget.style.outline = '';
}}

function dropOn(ev, destFolder) {{
  ev.preventDefault();
  ev.currentTarget.style.outline = '';
  if (!dragPayload) return;
  if (dragPayload.kind === 'folder' && (destFolder === dragPayload.key || destFolder.indexOf(dragPayload.key + '/') === 0)) {{
    dragPayload = null;
    return;
  }}
  const form = document.createElement('form');
  form.method = 'post'; form.action = '/move'; form.style.display = 'none';
  const fields = {{kind: dragPayload.kind, key: dragPayload.key, dest: destFolder, path: {path_json}}};
  Object.entries(fields).forEach(([k, v]) => {{
    const inp = document.createElement('input');
    inp.type = 'hidden'; inp.name = k; inp.value = v;
    form.appendChild(inp);
  }});
  document.body.appendChild(form);
  dragPayload = null;
  form.submit();
}}

// breadcrumb — тоже цель для drop (перемещение в родительскую папку)
document.querySelectorAll('.breadcrumb a').forEach(a => {{
  a.addEventListener('dragover', e => e.preventDefault());
  a.addEventListener('drop', e => {{
    e.preventDefault();
    const url = new URL(a.href);
    const dest = url.searchParams.get('path') || '';
    dropOn(e, dest);
  }});
}});

// --- превью в браузере ---
function previewFile(id, name, kind) {{
  const modal = document.getElementById('preview-modal');
  const body = document.getElementById('preview-body');
  document.getElementById('preview-name').textContent = name;
  body.innerHTML = '';
  if (kind === 'image') {{
    const img = document.createElement('img');
    img.src = '/view/' + id;
    img.style.maxWidth = '100%';
    body.appendChild(img);
    modal.style.display = 'block';
  }} else {{
    fetch('/preview/' + id).then(r => r.ok ? r.text() : Promise.reject(r.status)).then(text => {{
      const pre = document.createElement('pre');
      pre.style.whiteSpace = 'pre-wrap';
      pre.style.wordBreak = 'break-word';
      pre.textContent = text;
      body.appendChild(pre);
      modal.style.display = 'block';
    }}).catch(() => {{
      window.open('/view/' + id, '_blank');
    }});
  }}
}}

function closePreview() {{
  document.getElementById('preview-modal').style.display = 'none';
}}

// --- прогресс-бар загрузки файла ---
function formatBytes(n) {{
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let i = 0;
  n = Number(n);
  while (n >= 1024 && i < units.length - 1) {{ n /= 1024; i++; }}
  return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + ' ' + units[i];
}}

function handleUpload(ev, form) {{
  ev.preventDefault();
  const fileInput = document.getElementById('upload-file-input');
  if (!fileInput.files.length) return false;

  // ВАЖНО: FormData(form) нужно строить ДО того, как что-либо в форме
  // станет disabled — отключённые поля браузер молча исключает из
  // FormData (как при обычной отправке формы), из-за чего файл пропадал
  // из тела запроса и сервер получал запрос почти без данных.
  const formData = new FormData(form);

  const wrap = document.getElementById('upload-progress-wrap');
  const bar = document.getElementById('upload-progress-bar');
  const label = document.getElementById('upload-progress-label');
  const btn = document.getElementById('upload-submit-btn');

  wrap.style.display = 'block';
  bar.style.width = '0%';
  bar.style.background = 'var(--fg)';
  btn.disabled = true;

  const xhr = new XMLHttpRequest();
  xhr.open('POST', form.action, true);

  xhr.upload.addEventListener('progress', function(e) {{
    if (!e.lengthComputable) return;
    const pct = Math.round((e.loaded / e.total) * 100);
    bar.style.width = pct + '%';
    label.textContent = {uploading_label_json}
      .replace('{{percent}}', pct)
      .replace('{{loaded}}', formatBytes(e.loaded))
      .replace('{{total}}', formatBytes(e.total));
  }});

  xhr.addEventListener('load', function() {{
    if (xhr.status >= 200 && xhr.status < 400) {{
      bar.style.width = '100%';
      label.textContent = {upload_done_label_json};
      window.location.reload();
    }} else {{
      bar.style.background = '#ff4444';
      const detail = (xhr.responseText || '').trim().slice(0, 200);
      label.textContent = {upload_error_label_json} + ' [HTTP ' + xhr.status + ']' + (detail ? ': ' + detail : '');
      console.error('upload failed', xhr.status, xhr.responseText);
      btn.disabled = false;
    }}
  }});

  xhr.addEventListener('error', function() {{
    bar.style.background = '#ff4444';
    label.textContent = {upload_error_label_json} + ' [network error — соединение оборвано до ответа сервера; проверьте, нет ли прокси/CDN с лимитом на размер запроса]';
    console.error('upload network error (connection reset/aborted before any HTTP response)');
    btn.disabled = false;
  }});

  xhr.addEventListener('timeout', function() {{
    bar.style.background = '#ff4444';
    label.textContent = {upload_error_label_json} + ' [timeout]';
    btn.disabled = false;
  }});

  xhr.send(formData);
  return false;
}}

// матричный дождь
(function() {{
  const c = document.getElementById('matrix');
  const ctx = c.getContext('2d');
  function resize() {{ c.width = window.innerWidth; c.height = window.innerHeight; }}
  resize();
  window.addEventListener('resize', resize);
  const chars = "アイウエオカキクケコサシスセソ01_/:$#{{}}";
  const fontSize = 14;
  let columns, drops;
  function setup() {{
    columns = Math.floor(c.width / fontSize);
    drops = Array(columns).fill(1);
  }}
  setup();
  function draw() {{
    ctx.fillStyle = "rgba(6,10,6,0.08)";
    ctx.fillRect(0, 0, c.width, c.height);
    ctx.fillStyle = "#33ff66";
    ctx.font = fontSize + "px monospace";
    for (let i = 0; i < drops.length; i++) {{
      const text = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);
      if (drops[i] * fontSize > c.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }}
  }}
  setInterval(draw, 50);
}})();
</script>
</body>
</html>
"""

LOGO_SMALL = r"""███████╗██╗██╗     ███████╗██╗     ██╗██████╗
██╔════╝██║██║     ██╔════╝██║     ██║██╔══██╗
█████╗  ██║██║     █████╗  ██║     ██║██████╔╝
██╔══╝  ██║██║     ██╔══╝  ██║     ██║██╔══██╗
██║     ██║███████╗███████╗███████╗██║██████╔╝
╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚═╝╚═════╝"""

TABLE_TEMPLATE = """<table>
<thead><tr><th><input type="checkbox" id="select-all" title="{t_select_all}" onclick="toggleSelectAll(this)"></th><th>{t_col_name}</th><th>{t_col_size}</th><th>{t_col_added}</th><th></th>{security_th}</tr></thead>
<tbody>
{rows}
</tbody>
</table>
"""

FOLDER_ROW = """<tr data-name="{name_lower}" draggable="true" ondragstart="dragStart(event,'folder','{key_js}')" ondragover="dragOver(event)" ondragleave="dragLeave(event)" ondrop="dropOn(event,'{key_js}')">
  <td><input type="checkbox" class="row-check" data-kind="folder" data-key="{key_attr}"></td>
  <td><a class="folder-link" href="/?path={href}">📁 {name}/</a></td>
  <td class="meta">{t_dir_label}</td>
  <td class="meta">—</td>
  <td class="actions">{delete_cell}</td>
  {security_cell}
</tr>
"""

FILE_ROW = """<tr data-name="{name_lower}" draggable="true" ondragstart="dragStart(event,'file','{key_js}')">
  <td><input type="checkbox" class="row-check" data-kind="file" data-key="{key_attr}"></td>
  <td>{lock_icon}{name}<div class="meta">{tags}</div></td>
  <td>{size}</td>
  <td class="meta">{added}</td>
  <td class="actions">
    {preview_cell}
    <a class="btn" href="/view/{id}" target="_blank">{view_label}</a>
    <a class="btn" href="/download/{id}">{get_label}</a>
    {delete_cell}
  </td>
  {security_cell}
</tr>
"""

FILE_PREVIEW_BTN = """<button type="button" class="btn" onclick="previewFile('{id}','{name_js}','{kind}')">{t_preview_btn}</button>"""

BULK_BAR_TEMPLATE = """<div class="row" style="margin-bottom:.6rem;">
  <button type="button" class="btn" onclick="bulkDelete()">{t_bulk_delete_btn}</button>
  <button type="button" class="btn" onclick="bulkMove()">{t_bulk_move_btn}</button>
  <span class="meta">{t_drag_hint}</span>
</div>
<form id="bulk-delete-form" method="post" action="/bulk/delete" style="display:none;"></form>
<form id="bulk-move-form" method="post" action="/bulk/move" style="display:none;"></form>
"""

FILE_SECURITY_CELL = """<td class="file-sec">
  <span class="badge {status_class}">{status_label}</span>
  <form class="row" method="post" action="/file/security/set" style="margin-top:.35rem;">
    <input type="hidden" name="file_id" value="{id}">
    <input type="hidden" name="path" value="{path_raw}">
    <input type="password" name="password" placeholder="{t_password_placeholder}" required style="min-width:100px;">
    <button class="btn" type="submit">{t_set_btn}</button>
  </form>
  {extra}
</td>"""

FILE_SECURITY_CLEAR_FORM = """<form method="post" action="/file/security/clear" style="margin-top:.35rem;" onsubmit="return confirm('{confirm_text}');">
    <input type="hidden" name="file_id" value="{id}">
    <input type="hidden" name="path" value="{path_raw}">
    <button class="btn danger" type="submit">{t_clear_btn}</button>
  </form>"""

FILE_GRANT_FORM = """<form class="row" method="post" action="/file/security/grant" style="margin-top:.35rem;">
    <input type="hidden" name="file_id" value="{id}">
    <input type="hidden" name="path" value="{path_raw}">
    <select name="login" required>{options}</select>
    <button class="btn" type="submit">{t_grant_btn}</button>
  </form>"""

FILE_GRANTED_BADGE = """<span class="badge open" style="margin:.2rem .3rem 0 0; display:inline-flex; align-items:center; gap:.3rem;">{login}<form method="post" action="/file/security/revoke" style="display:inline;">
      <input type="hidden" name="file_id" value="{id}">
      <input type="hidden" name="login" value="{login}">
      <input type="hidden" name="path" value="{path_raw}">
      <button type="submit" style="border:none;background:none;color:#ff4444;cursor:pointer;padding:0;font-size:.9rem;">×</button>
    </form></span>"""

DELETE_FORM = """<form method="post" action="/delete/{id}" onsubmit="return confirm('{confirm_text}');">
      <input type="hidden" name="path" value="{path_raw}">
      <button class="btn danger" type="submit">{del_label}</button>
    </form>"""

DELETE_FOLDER_FORM = """<form method="post" action="/delete-folder" onsubmit="return confirm('{confirm_text}');">
      <input type="hidden" name="folder" value="{folder_raw}">
      <input type="hidden" name="path" value="{path_raw}">
      <button class="btn danger" type="submit">{del_label}</button>
    </form>"""

UPLOAD_PANEL_TEMPLATE = """<div class="panel">
  <h2>{t_upload_title}</h2>
  <form class="row" id="upload-form" method="post" action="/upload" enctype="multipart/form-data" onsubmit="return handleUpload(event, this);">
    <input type="hidden" name="path" value="{path_raw}">
    <input type="file" name="file" id="upload-file-input" required>
    <button type="submit" id="upload-submit-btn">{t_upload_button}</button>
  </form>
  <div id="upload-progress-wrap" style="display:none; margin-top:.6rem;">
    <div style="background:#010401; border:1px solid var(--border); border-radius:3px; height:.9rem; overflow:hidden;">
      <div id="upload-progress-bar" style="height:100%; width:0%; background:var(--fg); box-shadow:0 0 8px var(--fg); transition:width .1s linear;"></div>
    </div>
    <div id="upload-progress-label" class="meta" style="margin-top:.3rem;"></div>
  </div>
</div>
"""

MKDIR_PANEL_TEMPLATE = """<div class="panel">
  <h2>{t_mkdir_title}</h2>
  <form class="row" method="post" action="/mkdir">
    <input type="hidden" name="parent" value="{path_raw}">
    <input type="text" name="name" placeholder="{t_mkdir_placeholder}" required>
    <button type="submit">{t_mkdir_button}</button>
  </form>
</div>
"""

LOCKED_PANEL_TEMPLATE = """<div class="panel">
  <h2>{title}</h2>
  <p class="locked-note">{note}</p>
</div>
"""

SECURITY_PANEL_TEMPLATE = """<div class="panel">
  <h2>{t_security_title}</h2>
  <p class="meta" style="margin-top:-.3rem;margin-bottom:.8rem;">{t_security_hint}</p>
  {rows}
</div>
"""

SECURITY_ROW_TEMPLATE = """<div class="sec-row">
  <span class="sec-label">{action_label}</span>
  <span class="badge {status_class}">{status_label}</span>
  <form class="row" method="post" action="/security/set" style="flex:1;">
    <input type="hidden" name="which" value="{which}">
    <input type="hidden" name="path" value="{path_raw}">
    <input type="password" name="password" placeholder="{t_password_placeholder}" required>
    <button class="btn" type="submit">{t_set_btn}</button>
  </form>
  {clear_form}
</div>
"""

SECURITY_CLEAR_FORM = """<form method="post" action="/security/clear" onsubmit="return confirm('{confirm_text}');">
    <input type="hidden" name="which" value="{which}">
    <input type="hidden" name="path" value="{path_raw}">
    <button class="btn danger" type="submit">{t_clear_btn}</button>
  </form>"""


def render_breadcrumb(path: str) -> str:
    parts = [p for p in path.split("/") if p]
    crumbs = [f'<a href="/?path=">~</a>']
    acc = ""
    for p in parts:
        acc = join_path(acc, p)
        crumbs.append(f'<a href="/?path={acc}">{html.escape(p)}</a>')
    return " / ".join(crumbs)


def render_lang_switch(lang: str, path: str) -> str:
    links = []
    for code, label in (("en", "EN"), ("ru", "RU")):
        cls = "active" if code == lang else ""
        links.append(f'<a class="{cls}" href="/lang/{code}?path={path}">{label}</a>')
    return "".join(links)


def render_account_bar(lang: str, current_user, path: str) -> str:
    if current_user:
        admin_link = ""
        if user_has_permission(current_user, "admin"):
            admin_link = f' &nbsp;|&nbsp; <a href="/admin/users">{t(lang, "accounts_link")}</a>'
        trash_link = ""
        if user_has_permission(current_user, "delete"):
            trash_link = f' &nbsp;|&nbsp; <a href="/trash?path={path}">{t(lang, "trash_link")}</a>'
        return (
            f'{html.escape(t(lang, "logged_in_as", login=current_user["login"]))}'
            f'{admin_link}'
            f'{trash_link}'
            f' &nbsp;|&nbsp; <a href="/logout?path={path}">{t(lang, "logout_btn")}</a>'
        )
    return (
        f'<a href="/login?next={quote(f"/?path={path}", safe="")}">{t(lang, "login_link")}</a>'
        f' &nbsp;|&nbsp; <a href="/register">{t(lang, "register_link")}</a>'
    )


def render_security_panel(lang: str, auth: dict, path: str) -> str:
    rows = ""
    action_labels = {"view": t(lang, "action_view"), "download": t(lang, "action_download"), "delete": t(lang, "action_delete")}
    for which in AUTH_ACTIONS:
        protected = auth.get(which) is not None
        status_class = "protected" if protected else "open"
        status_label = t(lang, "status_protected") if protected else t(lang, "status_open")
        clear_form = ""
        if protected:
            clear_form = SECURITY_CLEAR_FORM.format(
                which=which,
                path_raw=path,
                confirm_text=t(lang, "confirm_clear", action=action_labels[which]).replace("'", "\\'"),
                t_clear_btn=t(lang, "clear_btn"),
            )
        rows += SECURITY_ROW_TEMPLATE.format(
            action_label=action_labels[which],
            status_class=status_class,
            status_label=status_label,
            which=which,
            path_raw=path,
            t_password_placeholder=t(lang, "password_placeholder"),
            t_set_btn=t(lang, "set_btn"),
            clear_form=clear_form,
        )
    return SECURITY_PANEL_TEMPLATE.format(
        t_security_title=t(lang, "security_title"),
        t_security_hint=t(lang, "security_hint"),
        rows=rows,
    )


def render_index_page(path: str, lang: str = DEFAULT_LANG, unlocked: dict = None, current_user=None):
    data = load_index()
    path = norm_path(path)
    subfolders, files = list_children(data, path)
    auth = data.get("auth", {})
    unlocked = unlocked or {}

    lock_suffix = {}
    for which in AUTH_ACTIONS:
        protected = auth.get(which) is not None
        lock_suffix[which] = " 🔒" if (protected and not unlocked.get(which)) else ""

    show_security_col = user_has_permission(current_user, "security")
    all_logins = [u["login"] for u in data.get("users", [])]

    def _file_security_cell(it):
        protected = file_is_protected(it)
        status_class = "protected" if protected else "open"
        status_label = t(lang, "status_protected") if protected else t(lang, "status_open")
        extra = ""
        if protected:
            extra += FILE_SECURITY_CLEAR_FORM.format(
                id=it["id"], path_raw=path,
                confirm_text=t(lang, "confirm_clear", action=html.escape(it["name"])).replace("'", "\\'"),
                t_clear_btn=t(lang, "clear_btn"),
            )
            granted = [u for u in data.get("users", []) if it["id"] in u.get("unlocked_files", [])]
            for u in granted:
                extra += FILE_GRANTED_BADGE.format(login=html.escape(u["login"]), id=it["id"], path_raw=path)
            ungranted_logins = [l for l in all_logins if l not in {u["login"] for u in granted}]
            if ungranted_logins:
                options = f'<option value="" disabled selected>{t(lang, "grant_select_placeholder")}</option>' + "".join(
                    f'<option value="{html.escape(l)}">{html.escape(l)}</option>' for l in ungranted_logins
                )
                extra += FILE_GRANT_FORM.format(
                    id=it["id"], path_raw=path, options=options, t_grant_btn=t(lang, "grant_btn"),
                )
        return FILE_SECURITY_CELL.format(
            status_class=status_class, status_label=status_label,
            id=it["id"], path_raw=path,
            t_password_placeholder=t(lang, "password_placeholder"),
            t_set_btn=t(lang, "set_btn"),
            extra=extra,
        )

    can_delete = user_has_permission(current_user, "delete")
    rows = ""
    for sf in subfolders:
        href = join_path(path, sf)
        if can_delete:
            folder_delete_cell = DELETE_FOLDER_FORM.format(
                folder_raw=href,
                path_raw=path,
                del_label=t(lang, "del_folder_btn") + lock_suffix["delete"],
                confirm_text=t(lang, "confirm_delete_folder", name=html.escape(sf)).replace("'", "\\'"),
            )
        else:
            folder_delete_cell = ""
        rows += FOLDER_ROW.format(
            name_lower=html.escape(sf.lower()), href=href, name=html.escape(sf),
            key_js=href.replace("\\", "\\\\").replace("'", "\\'"),
            key_attr=html.escape(href),
            t_dir_label=t(lang, "dir_label"),
            delete_cell=folder_delete_cell,
            security_cell="<td></td>" if show_security_col else "",
        )
    for it in files:
        if can_delete:
            delete_cell = DELETE_FORM.format(
                id=it["id"],
                path_raw=path,
                del_label=t(lang, "del_btn") + lock_suffix["delete"],
                confirm_text=t(lang, "confirm_delete", name=html.escape(it["name"]).replace("'", "\\'")),
            )
        else:
            delete_cell = ""
        mime, _ = mimetypes.guess_type(it["name"])
        is_text = (mime and mime.startswith("text/")) or it["name"].lower().endswith(
            (".txt", ".md", ".json", ".log", ".csv", ".py", ".js", ".html", ".css", ".yml", ".yaml", ".xml")
        )
        is_image = bool(mime and mime.startswith("image/"))
        preview_cell = ""
        if not file_is_protected(it) and (is_text or is_image):
            preview_cell = FILE_PREVIEW_BTN.format(
                id=it["id"],
                name_js=html.escape(it["name"]).replace("'", "\\'"),
                kind="image" if is_image else "text",
                t_preview_btn=t(lang, "preview_btn"),
            )
        rows += FILE_ROW.format(
            id=it["id"],
            name=html.escape(it["name"]),
            name_lower=html.escape(it["name"].lower()),
            key_js=full_file_path(it).replace("\\", "\\\\").replace("'", "\\'"),
            key_attr=html.escape(it["id"]),
            size=human_size(it["size"]),
            added=it["added"],
            tags=html.escape(", ".join(it.get("tags", []))),
            path_raw=path,
            lock_icon="🔒 " if file_is_protected(it) else "",
            view_label=t(lang, "view_btn") + (" 🔒" if file_is_protected(it) else lock_suffix["view"]),
            get_label=t(lang, "get_btn") + (" 🔒" if file_is_protected(it) else lock_suffix["download"]),
            delete_cell=delete_cell,
            preview_cell=preview_cell,
            security_cell=_file_security_cell(it) if show_security_col else "",
        )

    if not subfolders and not files:
        content = f'<p class="empty">{t(lang, "empty")}</p>'
    else:
        table_html = TABLE_TEMPLATE.format(
            rows=rows,
            t_select_all=t(lang, "select_all"),
            t_col_name=t(lang, "col_name"),
            t_col_size=t(lang, "col_size"),
            t_col_added=t(lang, "col_added"),
            security_th=f'<th>{t(lang, "col_access")}</th>' if show_security_col else "",
        )
        bulk_bar = ""
        if can_delete:
            bulk_bar = BULK_BAR_TEMPLATE.format(
                t_bulk_delete_btn=t(lang, "bulk_delete_btn"),
                t_bulk_move_btn=t(lang, "bulk_move_btn"),
                t_drag_hint=t(lang, "drag_hint"),
            )
        content = bulk_bar + table_html

    if user_has_permission(current_user, "upload"):
        upload_panel = UPLOAD_PANEL_TEMPLATE.format(
            t_upload_title=t(lang, "upload_title"),
            t_upload_button=t(lang, "upload_button"),
            path_raw=path,
        )
    else:
        upload_panel = LOCKED_PANEL_TEMPLATE.format(
            title=t(lang, "upload_title"), note=t(lang, "no_permission_upload"),
        )

    if user_has_permission(current_user, "mkdir"):
        mkdir_panel = MKDIR_PANEL_TEMPLATE.format(
            t_mkdir_title=t(lang, "mkdir_title"),
            t_mkdir_placeholder=t(lang, "mkdir_placeholder"),
            t_mkdir_button=t(lang, "mkdir_button"),
            path_raw=path,
        )
    else:
        mkdir_panel = LOCKED_PANEL_TEMPLATE.format(
            title=t(lang, "mkdir_title"), note=t(lang, "no_permission_mkdir"),
        )

    if user_has_permission(current_user, "security"):
        security_panel = render_security_panel(lang, auth, path)
    else:
        security_panel = LOCKED_PANEL_TEMPLATE.format(
            title=t(lang, "security_title"), note=t(lang, "no_permission_security"),
        )

    return PAGE_TEMPLATE.format(
        html_lang=lang,
        path_title="/" + path if path else "/~",
        path_raw=path,
        path_query=quote(path, safe=""),
        logo=LOGO_SMALL,
        breadcrumb=render_breadcrumb(path),
        content=content,
        count=len(subfolders) + len(files),
        lang_switch=render_lang_switch(lang, path),
        account_bar=render_account_bar(lang, current_user, path),
        upload_panel=upload_panel,
        mkdir_panel=mkdir_panel,
        security_panel=security_panel,
        t_search_placeholder=t(lang, "search_placeholder"),
        t_zip_btn=t(lang, "zip_btn"),
        t_footer=t(lang, "footer", count=len(subfolders) + len(files)),
        path_json=json.dumps(path),
        nothing_selected_json=json.dumps(t(lang, "nothing_selected")),
        confirm_bulk_delete_json=json.dumps(t(lang, "confirm_bulk_delete")),
        bulk_move_prompt_json=json.dumps(t(lang, "bulk_move_prompt")),
        uploading_label_json=json.dumps(t(lang, "uploading_label")),
        upload_done_label_json=json.dumps(t(lang, "upload_done_label")),
        upload_error_label_json=json.dumps(t(lang, "upload_error_label")),
    )


UNLOCK_PAGE_TEMPLATE = """<!doctype html>
<html lang="{html_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>filelib :: unlock</title>
<style>
  body {{
    background: #060a06; color: #33ff66; font-family: 'Share Tech Mono', Consolas, monospace;
    max-width: 480px; margin: 4rem auto; padding: 0 1rem;
  }}
  .panel {{ border: 1px solid #1f5c2f; background: #0b120b; border-radius: 4px; padding: 1.2rem; }}
  h2 {{ margin: 0 0 .6rem 0; color: #a6ffb0; }}
  .meta {{ color: #1c8f3c; font-size: .85rem; margin-bottom: 1rem; }}
  .error {{ color: #ff4444; margin-bottom: 1rem; }}
  .row {{ display: flex; gap: .6rem; }}
  input[type=password] {{
    background: #010401; border: 1px solid #1f5c2f; color: #33ff66; flex: 1;
    padding: .5rem .6rem; font-family: inherit; font-size: .9rem; border-radius: 3px;
  }}
  button {{
    background: transparent; color: #33ff66; border: 1px solid #1c8f3c;
    padding: .4rem .8rem; font-family: inherit; cursor: pointer; border-radius: 3px;
  }}
  button:hover {{ border-color: #00ffcc; color: #00ffcc; }}
  a {{ color: #1c8f3c; }}
</style>
</head>
<body>
<div class="panel">
  <h2>{t_unlock_title}</h2>
  <p class="meta">{t_unlock_hint}</p>
  {error_html}
  <form class="row" method="post" action="/unlock">
    <input type="hidden" name="action" value="{action}">
    <input type="hidden" name="next" value="{next}">
    <input type="password" name="password" placeholder="{t_unlock_placeholder}" autofocus required>
    <button type="submit">{t_unlock_btn}</button>
  </form>
  <p style="margin-top:1rem;"><a href="/">{t_back_link}</a></p>
</div>
</body>
</html>
"""


def render_unlock_page(lang: str, action: str, next_url: str, error: bool = False) -> str:
    error_html = f'<p class="error">{t(lang, "unlock_error")}</p>' if error else ""
    return UNLOCK_PAGE_TEMPLATE.format(
        html_lang=lang,
        t_unlock_title=t(lang, "unlock_title"),
        t_unlock_hint=t(lang, "unlock_hint"),
        error_html=error_html,
        action=html.escape(action),
        next=html.escape(next_url),
        t_unlock_placeholder=t(lang, "unlock_placeholder"),
        t_unlock_btn=t(lang, "unlock_btn"),
        t_back_link=t(lang, "back_link"),
    )


FILE_UNLOCK_PAGE_TEMPLATE = """<!doctype html>
<html lang="{html_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>filelib :: unlock</title>
<style>
  body {{
    background: #060a06; color: #33ff66; font-family: 'Share Tech Mono', Consolas, monospace;
    max-width: 480px; margin: 4rem auto; padding: 0 1rem;
  }}
  .panel {{ border: 1px solid #1f5c2f; background: #0b120b; border-radius: 4px; padding: 1.2rem; }}
  h2 {{ margin: 0 0 .6rem 0; color: #a6ffb0; }}
  .meta {{ color: #1c8f3c; font-size: .85rem; margin-bottom: 1rem; }}
  .error {{ color: #ff4444; margin-bottom: 1rem; }}
  .row {{ display: flex; gap: .6rem; }}
  input[type=password] {{
    background: #010401; border: 1px solid #1f5c2f; color: #33ff66; flex: 1;
    padding: .5rem .6rem; font-family: inherit; font-size: .9rem; border-radius: 3px;
  }}
  button {{
    background: transparent; color: #33ff66; border: 1px solid #1c8f3c;
    padding: .4rem .8rem; font-family: inherit; cursor: pointer; border-radius: 3px;
  }}
  button:hover {{ border-color: #00ffcc; color: #00ffcc; }}
  a {{ color: #1c8f3c; }}
</style>
</head>
<body>
<div class="panel">
  <h2>{t_file_unlock_title}</h2>
  <p class="meta">{t_file_unlock_hint}</p>
  {error_html}
  <form class="row" method="post" action="/unlock-file">
    <input type="hidden" name="id" value="{file_id}">
    <input type="hidden" name="next" value="{next}">
    <input type="password" name="password" placeholder="{t_unlock_placeholder}" autofocus required>
    <button type="submit">{t_unlock_btn}</button>
  </form>
  <p style="margin-top:1rem;"><a href="/">{t_back_link}</a></p>
</div>
</body>
</html>
"""


def render_file_unlock_page(lang: str, file_id: str, file_name: str, next_url: str, error: bool = False) -> str:
    error_html = f'<p class="error">{t(lang, "unlock_error")}</p>' if error else ""
    return FILE_UNLOCK_PAGE_TEMPLATE.format(
        html_lang=lang,
        t_file_unlock_title=t(lang, "file_unlock_title"),
        t_file_unlock_hint=t(lang, "file_unlock_hint", name=html.escape(file_name)),
        error_html=error_html,
        file_id=html.escape(file_id),
        next=html.escape(next_url),
        t_unlock_placeholder=t(lang, "unlock_placeholder"),
        t_unlock_btn=t(lang, "unlock_btn"),
        t_back_link=t(lang, "back_link"),
    )


REGISTER_PAGE_TEMPLATE = """<!doctype html>
<html lang="{html_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>filelib :: register</title>
<style>
  body {{
    background: #060a06; color: #33ff66; font-family: 'Share Tech Mono', Consolas, monospace;
    max-width: 480px; margin: 4rem auto; padding: 0 1rem;
  }}
  .panel {{ border: 1px solid #1f5c2f; background: #0b120b; border-radius: 4px; padding: 1.2rem; }}
  h2 {{ margin: 0 0 .6rem 0; color: #a6ffb0; }}
  .meta {{ color: #1c8f3c; font-size: .85rem; margin-bottom: 1rem; }}
  .error {{ color: #ff4444; margin-bottom: 1rem; }}
  .col {{ display: flex; flex-direction: column; gap: .6rem; }}
  input[type=text], input[type=password] {{
    background: #010401; border: 1px solid #1f5c2f; color: #33ff66;
    padding: .5rem .6rem; font-family: inherit; font-size: .9rem; border-radius: 3px;
  }}
  button {{
    background: transparent; color: #33ff66; border: 1px solid #1c8f3c;
    padding: .4rem .8rem; font-family: inherit; cursor: pointer; border-radius: 3px;
  }}
  button:hover {{ border-color: #00ffcc; color: #00ffcc; }}
  a {{ color: #1c8f3c; }}
</style>
</head>
<body>
<div class="panel">
  <h2>{t_register_title}</h2>
  <p class="meta">{t_register_hint}</p>
  {error_html}
  <form class="col" method="post" action="/register">
    <input type="text" name="username" placeholder="{t_login_user_placeholder}" value="{login_value}" autofocus required>
    <input type="password" name="password" placeholder="{t_login_pass_placeholder}" required>
    <input type="password" name="confirm" placeholder="{t_register_confirm_placeholder}" required>
    <button type="submit">{t_register_btn}</button>
  </form>
  <p style="margin-top:1rem;"><a href="/login">{t_have_account_link}</a> &nbsp;|&nbsp; <a href="/">{t_back_link}</a></p>
</div>
</body>
</html>
"""


def render_register_page(lang: str, error: str = None, login: str = "") -> str:
    error_html = ""
    if error:
        key = {"empty": "register_error_empty", "mismatch": "register_error_mismatch", "taken": "register_error_taken"}.get(error)
        if key:
            error_html = f'<p class="error">{t(lang, key)}</p>'
    return REGISTER_PAGE_TEMPLATE.format(
        html_lang=lang,
        t_register_title=t(lang, "register_title"),
        t_register_hint=t(lang, "register_hint"),
        error_html=error_html,
        login_value=html.escape(login),
        t_login_user_placeholder=t(lang, "login_user_placeholder"),
        t_login_pass_placeholder=t(lang, "login_pass_placeholder"),
        t_register_confirm_placeholder=t(lang, "register_confirm_placeholder"),
        t_register_btn=t(lang, "register_btn"),
        t_have_account_link=t(lang, "have_account_link"),
        t_back_link=t(lang, "back_link"),
    )


LOGIN_PAGE_TEMPLATE = """<!doctype html>
<html lang="{html_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>filelib :: login</title>
<style>
  body {{
    background: #060a06; color: #33ff66; font-family: 'Share Tech Mono', Consolas, monospace;
    max-width: 480px; margin: 4rem auto; padding: 0 1rem;
  }}
  .panel {{ border: 1px solid #1f5c2f; background: #0b120b; border-radius: 4px; padding: 1.2rem; }}
  h2 {{ margin: 0 0 .6rem 0; color: #a6ffb0; }}
  .meta {{ color: #1c8f3c; font-size: .85rem; margin-bottom: 1rem; }}
  .error {{ color: #ff4444; margin-bottom: 1rem; }}
  .col {{ display: flex; flex-direction: column; gap: .6rem; }}
  input[type=text], input[type=password] {{
    background: #010401; border: 1px solid #1f5c2f; color: #33ff66;
    padding: .5rem .6rem; font-family: inherit; font-size: .9rem; border-radius: 3px;
  }}
  button {{
    background: transparent; color: #33ff66; border: 1px solid #1c8f3c;
    padding: .4rem .8rem; font-family: inherit; cursor: pointer; border-radius: 3px;
  }}
  button:hover {{ border-color: #00ffcc; color: #00ffcc; }}
  a {{ color: #1c8f3c; }}
</style>
</head>
<body>
<div class="panel">
  <h2>{t_login_title}</h2>
  <p class="meta">{t_login_hint}</p>
  {error_html}
  <form class="col" method="post" action="/login">
    <input type="hidden" name="next" value="{next}">
    <input type="text" name="username" placeholder="{t_login_user_placeholder}" autofocus required>
    <input type="password" name="password" placeholder="{t_login_pass_placeholder}" required>
    <button type="submit">{t_login_btn}</button>
  </form>
  <p style="margin-top:1rem;"><a href="/register">{t_register_link}</a> &nbsp;|&nbsp; <a href="/">{t_back_link}</a></p>
</div>
</body>
</html>
"""


def render_login_page(lang: str, next_url: str, error: bool = False) -> str:
    error_html = f'<p class="error">{t(lang, "login_error")}</p>' if error else ""
    return LOGIN_PAGE_TEMPLATE.format(
        html_lang=lang,
        t_login_title=t(lang, "login_title"),
        t_login_hint=t(lang, "login_hint"),
        error_html=error_html,
        next=html.escape(next_url),
        t_login_user_placeholder=t(lang, "login_user_placeholder"),
        t_login_pass_placeholder=t(lang, "login_pass_placeholder"),
        t_login_btn=t(lang, "login_btn"),
        t_register_link=t(lang, "register_link"),
        t_back_link=t(lang, "back_link"),
    )


ADMIN_PAGE_TEMPLATE = """<!doctype html>
<html lang="{html_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>filelib :: accounts</title>
<style>
  body {{
    background: #060a06; color: #33ff66; font-family: 'Share Tech Mono', Consolas, monospace;
    max-width: 900px; margin: 0 auto; padding: 1.5rem 1rem 4rem;
  }}
  a {{ color: #1c8f3c; }}
  h2 {{ margin: 0 0 .6rem 0; color: #a6ffb0; font-size: .95rem; text-transform: uppercase; letter-spacing: .06em; }}
  .panel {{ border: 1px solid #1f5c2f; background: #0b120b; border-radius: 4px; padding: 1rem; margin-bottom: 1.2rem; }}
  .col {{ display: flex; flex-direction: column; gap: .6rem; max-width: 420px; }}
  .row {{ display: flex; gap: .8rem; flex-wrap: wrap; align-items: center; }}
  input[type=text], input[type=password] {{
    background: #010401; border: 1px solid #1f5c2f; color: #33ff66;
    padding: .5rem .6rem; font-family: inherit; font-size: .9rem; border-radius: 3px;
  }}
  button, .btn {{
    background: transparent; color: #33ff66; border: 1px solid #1c8f3c;
    padding: .4rem .8rem; font-family: inherit; font-size: .8rem; cursor: pointer; border-radius: 3px;
  }}
  button:hover, .btn:hover {{ border-color: #00ffcc; color: #00ffcc; }}
  .btn.danger:hover {{ border-color: #ff4444; color: #ff4444; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  th {{ text-align: left; color: #1c8f3c; border-bottom: 1px solid #1f5c2f; padding: .4rem;
        font-size: .7rem; text-transform: uppercase; letter-spacing: .05em; }}
  td {{ padding: .6rem .4rem; border-bottom: 1px solid #123018; vertical-align: top; }}
  label {{ font-size: .78rem; margin-right: .7rem; white-space: nowrap; }}
  .meta {{ color: #1c8f3c; font-size: .78rem; margin-top: -.2rem; margin-bottom: .8rem; }}
  .empty {{ color: #1c8f3c; text-align: center; padding: 1rem; }}
  .perm-form, .pass-form {{ display: flex; flex-wrap: wrap; gap: .4rem .8rem; align-items: center; }}
</style>
</head>
<body>
<p><a href="/">{t_back_link}</a></p>
<h2 style="font-size:1.1rem;">{t_admin_title}</h2>
<p class="meta">{t_admin_hint}</p>

<div class="panel">
  <h2>{t_add_user_title}</h2>
  <form class="col" method="post" action="/admin/users/add">
    <input type="text" name="login" placeholder="{t_login_placeholder}" required>
    <input type="password" name="password" placeholder="{t_password_placeholder}" required>
    <div class="row">{add_perm_checkboxes}</div>
    <button type="submit">{t_add_user_btn}</button>
  </form>
</div>

<div class="panel">
  <h2>{t_existing_title}</h2>
  {users_table}
</div>
</body>
</html>
"""

ADMIN_USER_ROW = """<tr>
  <td>{login}</td>
  <td>
    <form class="perm-form" method="post" action="/admin/users/permissions">
      <input type="hidden" name="login" value="{login}">
      {perm_checkboxes}
      <button class="btn" type="submit">{t_save_perms_btn}</button>
    </form>
  </td>
  <td class="meta">{created}</td>
  <td>
    <form class="pass-form" method="post" action="/admin/users/password">
      <input type="hidden" name="login" value="{login}">
      <input type="password" name="password" placeholder="{t_col_new_password}" required style="min-width:120px;">
      <button class="btn" type="submit">{t_set_password_btn}</button>
    </form>
  </td>
  <td>
    <form method="post" action="/admin/users/delete" onsubmit="return confirm('{confirm_text}');">
      <input type="hidden" name="login" value="{login}">
      <button class="btn danger" type="submit">{t_delete_account_btn}</button>
    </form>
  </td>
</tr>
"""


def _perm_checkboxes(lang: str, checked_perms) -> str:
    checked_perms = set(checked_perms or [])
    parts = []
    for perm in USER_PERMISSIONS:
        checked = "checked" if perm in checked_perms else ""
        parts.append(f'<label><input type="checkbox" name="permission" value="{perm}" {checked}> {perm}</label>')
    return "".join(parts)


def render_admin_users_page(lang: str, data) -> str:
    users = data.get("users", [])
    if users:
        rows = ""
        for u in users:
            rows += ADMIN_USER_ROW.format(
                login=html.escape(u["login"]),
                perm_checkboxes=_perm_checkboxes(lang, u.get("permissions", [])),
                created=u.get("created", "—"),
                t_col_new_password=t(lang, "col_new_password"),
                t_save_perms_btn=t(lang, "save_perms_btn"),
                t_set_password_btn=t(lang, "set_password_btn"),
                t_delete_account_btn=t(lang, "delete_account_btn"),
                confirm_text=t(lang, "confirm_delete_account", login=html.escape(u["login"]).replace("'", "\\'")),
            )
        users_table = (
            "<table><thead><tr>"
            f'<th>{t(lang, "col_login")}</th><th>{t(lang, "col_permissions")}</th>'
            f'<th>{t(lang, "col_created")}</th><th></th><th></th>'
            "</tr></thead><tbody>" + rows + "</tbody></table>"
        )
    else:
        users_table = f'<p class="empty">{t(lang, "no_accounts_yet")}</p>'

    return ADMIN_PAGE_TEMPLATE.format(
        html_lang=lang,
        t_back_link=t(lang, "back_link"),
        t_admin_title=t(lang, "admin_title"),
        t_admin_hint=t(lang, "admin_hint"),
        t_add_user_title=t(lang, "add_user_title"),
        t_login_placeholder=t(lang, "login_user_placeholder"),
        t_password_placeholder=t(lang, "login_pass_placeholder"),
        add_perm_checkboxes=_perm_checkboxes(lang, []),
        t_add_user_btn=t(lang, "add_user_btn"),
        t_existing_title=t(lang, "existing_title"),
        users_table=users_table,
    )


TRASH_PAGE_TEMPLATE = """<!doctype html>
<html lang="{html_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>filelib :: trash</title>
<style>
  body {{
    background: #060a06; color: #33ff66; font-family: 'Share Tech Mono', Consolas, monospace;
    max-width: 900px; margin: 0 auto; padding: 1.5rem 1rem 4rem;
  }}
  a {{ color: #1c8f3c; }}
  h2 {{ margin: 0 0 .6rem 0; color: #a6ffb0; font-size: .95rem; text-transform: uppercase; letter-spacing: .06em; }}
  .panel {{ border: 1px solid #1f5c2f; background: #0b120b; border-radius: 4px; padding: 1rem; margin-bottom: 1.2rem; }}
  button, .btn {{
    background: transparent; color: #33ff66; border: 1px solid #1c8f3c;
    padding: .4rem .8rem; font-family: inherit; font-size: .8rem; cursor: pointer; border-radius: 3px;
  }}
  button:hover, .btn:hover {{ border-color: #00ffcc; color: #00ffcc; }}
  .btn.danger:hover {{ border-color: #ff4444; color: #ff4444; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  th {{ text-align: left; color: #1c8f3c; border-bottom: 1px solid #1f5c2f; padding: .4rem;
        font-size: .7rem; text-transform: uppercase; letter-spacing: .05em; }}
  td {{ padding: .5rem .4rem; border-bottom: 1px solid #123018; vertical-align: middle; }}
  .meta {{ color: #1c8f3c; font-size: .78rem; margin-top: -.2rem; margin-bottom: .8rem; }}
  .empty {{ color: #1c8f3c; text-align: center; padding: 1rem; }}
  .actions form {{ display: inline; margin-right: .3rem; }}
</style>
</head>
<body>
<p><a href="/?path={back_path}">{t_back_link}</a></p>
<h2 style="font-size:1.1rem;">{t_trash_title}</h2>
<p class="meta">{t_trash_hint}</p>

<div class="panel">
  {rows_or_empty}
  {empty_all_form}
</div>
</body>
</html>
"""

TRASH_ROW = """<tr>
  <td>/{path}</td>
  <td>{size}</td>
  <td class="meta">{deleted_at}</td>
  <td class="actions">
    <form method="post" action="/trash/restore">
      <input type="hidden" name="id" value="{id}">
      <input type="hidden" name="path" value="{back_path}">
      <button class="btn" type="submit">{t_restore_btn}</button>
    </form>
    <form method="post" action="/trash/delete" onsubmit="return confirm('{confirm_text}');">
      <input type="hidden" name="id" value="{id}">
      <button class="btn danger" type="submit">{t_purge_btn}</button>
    </form>
  </td>
</tr>
"""

TRASH_EMPTY_FORM = """<form method="post" action="/trash/empty" onsubmit="return confirm('{confirm_text}');" style="margin-top:.8rem;">
  <button class="btn danger" type="submit">{t_empty_trash_btn}</button>
</form>"""


def render_trash_page(lang: str, data, back_path: str = "") -> str:
    trash = sorted(data.get("trash", []), key=lambda e: e.get("deleted_at", ""), reverse=True)
    if trash:
        rows = ""
        for entry in trash:
            rows += TRASH_ROW.format(
                path=html.escape(full_file_path(entry)),
                size=human_size(entry["size"]),
                deleted_at=entry.get("deleted_at", "—"),
                id=entry["id"],
                back_path=back_path,
                t_restore_btn=t(lang, "restore_btn"),
                t_purge_btn=t(lang, "purge_btn"),
                confirm_text=t(lang, "confirm_purge", name=html.escape(entry["name"])).replace("'", "\\'"),
            )
        rows_or_empty = (
            "<table><thead><tr>"
            f'<th>{t(lang, "col_name")}</th><th>{t(lang, "col_size")}</th>'
            f'<th>{t(lang, "col_deleted")}</th><th></th>'
            "</tr></thead><tbody>" + rows + "</tbody></table>"
        )
        empty_all_form = TRASH_EMPTY_FORM.format(
            confirm_text=t(lang, "confirm_empty_trash").replace("'", "\\'"),
            t_empty_trash_btn=t(lang, "empty_trash_btn"),
        )
    else:
        rows_or_empty = f'<p class="empty">{t(lang, "trash_empty_note")}</p>'
        empty_all_form = ""

    return TRASH_PAGE_TEMPLATE.format(
        html_lang=lang,
        back_path=back_path,
        t_back_link=t(lang, "back_link"),
        t_trash_title=t(lang, "trash_title"),
        t_trash_hint=t(lang, "trash_hint", days=TRASH_RETENTION_DAYS),
        rows_or_empty=rows_or_empty,
        empty_all_form=empty_all_form,
    )


def parse_multipart_stream(chunk_iter, boundary: str, tmp_dir: Path):
    """Потоковый парсер multipart/form-data.

    В отличие от `parse_multipart` (который получает уже целиком
    прочитанное в память тело запроса), эта версия читает данные
    небольшими кусками из `chunk_iter` и льёт содержимое поля "file"
    сразу на диск во временный файл — тело загружаемого файла НИКОГДА
    не оказывается целиком в оперативной памяти. Это важно для больших
    видео: раньше сервер буферизовал весь файл (и не один раз при
    разборе) в RAM, и на слабой машине/VPS процесс мог быть убит
    OOM-killer'ом ОС прямо посреди загрузки — снаружи это выглядит как
    полностью зависший/неотвечающий сервер, без единой строчки в логе.

    Возвращает (fields: {name: bytes} — маленькие текстовые поля,
                file_info: {"filename", "tmp_path", "size"} | None).
    Файл, если он был, уже полностью записан на диск по пути tmp_path —
    вызывающий код отвечает за то, чтобы либо переместить его на
    постоянное место, либо удалить при ошибке."""
    delimiter = b"--" + boundary.encode()
    part_delim = b"\r\n" + delimiter
    lookback = len(part_delim) + 4

    buf = bytearray()
    fields: dict = {}
    file_info = None

    it = iter(chunk_iter)

    def _next_chunk():
        try:
            return next(it)
        except StopIteration:
            return None

    # ищем самую первую границу (до неё может быть пустая преамбула)
    while delimiter not in buf:
        chunk = _next_chunk()
        if chunk is None:
            return fields, file_info
        buf.extend(chunk)
    idx = buf.find(delimiter)
    del buf[:idx + len(delimiter)]

    while True:
        while len(buf) < 2:
            chunk = _next_chunk()
            if chunk is None:
                return fields, file_info
            buf.extend(chunk)
        if bytes(buf[:2]) == b"--":
            return fields, file_info  # закрывающая граница — конец тела
        if bytes(buf[:2]) == b"\r\n":
            del buf[:2]

        while b"\r\n\r\n" not in buf:
            chunk = _next_chunk()
            if chunk is None:
                return fields, file_info
            buf.extend(chunk)
        header_end = buf.find(b"\r\n\r\n")
        header_blob = bytes(buf[:header_end])
        del buf[:header_end + 4]

        headers_text = header_blob.decode(errors="replace")
        disposition_line = next(
            (line for line in headers_text.splitlines() if line.lower().startswith("content-disposition")), ""
        )
        field_name, filename = None, None
        for chunk_h in disposition_line.split(";"):
            chunk_h = chunk_h.strip()
            if chunk_h.startswith("name="):
                field_name = chunk_h.split("=", 1)[1].strip().strip('"')
            elif chunk_h.startswith("filename="):
                filename = chunk_h.split("=", 1)[1].strip().strip('"')

        is_file_field = filename is not None
        file_fh = None
        tmp_path = None
        written = 0
        value_chunks = []

        if is_file_field:
            tmp_path = tmp_dir / f"upload_{uuid.uuid4().hex}.part"
            file_fh = open(tmp_path, "wb")

        try:
            while True:
                pos = buf.find(part_delim)
                if pos != -1:
                    piece = bytes(buf[:pos])
                    del buf[:pos + len(part_delim)]
                    if is_file_field:
                        file_fh.write(piece)
                        written += len(piece)
                    else:
                        value_chunks.append(piece)
                    break
                # безопасно сбрасываем всё, кроме "хвоста" — вдруг граница
                # разрезана ровно между двумя прочитанными кусками
                if len(buf) > lookback:
                    flush_len = len(buf) - lookback
                    piece = bytes(buf[:flush_len])
                    del buf[:flush_len]
                    if is_file_field:
                        file_fh.write(piece)
                        written += len(piece)
                    else:
                        value_chunks.append(piece)
                chunk = _next_chunk()
                if chunk is None:
                    # соединение оборвалось раньше времени — сохраняем
                    # то, что успели получить, и завершаем разбор
                    piece = bytes(buf)
                    del buf[:]
                    if is_file_field:
                        file_fh.write(piece)
                        written += len(piece)
                    else:
                        value_chunks.append(piece)
                        fields[field_name] = b"".join(value_chunks)
                    if is_file_field:
                        file_fh.close()
                        file_info = {"filename": filename, "tmp_path": tmp_path, "size": written}
                    return fields, file_info
                buf.extend(chunk)
        finally:
            if is_file_field and file_fh and not file_fh.closed:
                file_fh.close()

        if is_file_field:
            file_info = {"filename": filename, "tmp_path": tmp_path, "size": written}
        else:
            fields[field_name] = b"".join(value_chunks)


def parse_multipart(body: bytes, content_type: str):
    """Простейший парсер multipart/form-data. Возвращает dict полей: {name: (filename|None, bytes)}.

    Границы частей ищутся строго по последовательности CRLF + '--boundary',
    поэтому бинарное содержимое файла (видео, картинки и т.п.) извлекается
    ровно один в один — раньше здесь был grubby `.rstrip(b"\\r\\n")`,
    который мог откусывать хвостовые байты бинарного файла, если те
    случайно совпадали с CR/LF (нередко для видео/бинарников), портя
    загруженный файл или обрывая его."""
    result = {}
    if "boundary=" not in content_type:
        return result
    boundary = content_type.split("boundary=", 1)[1].strip().strip('"')
    delimiter = b"\r\n--" + boundary.encode()

    # Добавляем фиктивный "\r\n" перед телом, чтобы самая первая часть
    # (которая по спеке начинается с "--boundary" без ведущего CRLF)
    # обрабатывалась той же логикой split, что и все остальные.
    for piece in (b"\r\n" + body).split(delimiter):
        if piece.startswith(b"\r\n"):
            piece = piece[2:]
        if not piece or piece.startswith(b"--"):
            continue  # закрывающая граница или пустой хвост
        if b"\r\n\r\n" not in piece:
            continue
        header_blob, content = piece.split(b"\r\n\r\n", 1)
        headers = header_blob.decode(errors="replace")
        disposition_line = next(
            (line for line in headers.splitlines() if line.lower().startswith("content-disposition")), ""
        )
        field_name, filename = None, None
        for chunk in disposition_line.split(";"):
            chunk = chunk.strip()
            if chunk.startswith("name="):
                field_name = chunk.split("=", 1)[1].strip().strip('"')
            elif chunk.startswith("filename="):
                filename = chunk.split("=", 1)[1].strip().strip('"')
        if field_name is None:
            continue
        result[field_name] = (filename, content)
    return result


class FileLibHandler(BaseHTTPRequestHandler):
    server_version = "filelib-hacker/2.0"
    # Большие видео/архивы могут заливаться долго на медленном канале —
    # не обрываем соединение раньше времени (по умолчанию у http.server
    # таймаут не задан, но выставляем явно, чтобы не зависеть от системных
    # умолчаний ОС/сокета).
    timeout = 600

    def log_message(self, fmt, *fargs):
        sys.stderr.write(c("[net] ", "dim") + f"{fmt % fargs}\n")

    def _send_html(self, html_text, status=200):
        data = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location, set_cookie: str = None):
        self.send_response(303)
        self.send_header("Location", location)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()

    def _cookies(self) -> SimpleCookie:
        jar = SimpleCookie()
        raw = self.headers.get("Cookie", "")
        if raw:
            try:
                jar.load(raw)
            except Exception:
                pass
        return jar

    def _get_lang(self) -> str:
        jar = self._cookies()
        if "filelib_lang" in jar:
            val = jar["filelib_lang"].value
            if val in TRANSLATIONS:
                return val
        return DEFAULT_LANG

    def _unlocked_map(self) -> dict:
        jar = self._cookies()
        result = {}
        for action in AUTH_ACTIONS:
            morsel = jar.get(f"filelib_unlock_{action}")
            result[action] = bool(morsel and verify_unlock_token(morsel.value, action))
        return result

    def _is_unlocked(self, action: str) -> bool:
        jar = self._cookies()
        morsel = jar.get(f"filelib_unlock_{action}")
        return bool(morsel and verify_unlock_token(morsel.value, action))

    def _is_file_unlocked(self, file_id: str) -> bool:
        jar = self._cookies()
        morsel = jar.get(f"filelib_unlock_file_{file_id}")
        return bool(morsel and verify_unlock_token(morsel.value, f"file:{file_id}"))

    def _current_user(self, data):
        """Возвращает запись аккаунта для текущей сессии (или None).
        Права всегда берутся из свежего data — отзыв прав/удаление
        аккаунта из терминала действует мгновенно, даже со старой кукой."""
        jar = self._cookies()
        morsel = jar.get("filelib_session")
        if not morsel:
            return None
        login = verify_session_token(morsel.value)
        if not login:
            return None
        return find_user(data, login)

    @staticmethod
    def _parse_form(body: bytes) -> dict:
        fields = {}
        for pair in body.decode(errors="replace").split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                fields[unquote(k)] = unquote(v.replace("+", " "))
        return fields

    @staticmethod
    def _parse_form_multi(body: bytes) -> dict:
        """Как _parse_form, но сохраняет ВСЕ значения одноимённых полей
        (нужно для наборов чекбоксов permission[])."""
        fields = {}
        for pair in body.decode(errors="replace").split("&"):
            if not pair:
                continue
            if "=" in pair:
                k, v = pair.split("=", 1)
            else:
                k, v = pair, ""
            k = unquote(k)
            v = unquote(v.replace("+", " "))
            fields.setdefault(k, []).append(v)
        return fields

    def _send_file(self, item, inline: bool):
        path = FILES_DIR / item["stored_filename"]
        if not path.exists():
            self.send_error(404, "Файл не найден на диске")
            return
        mime, _ = mimetypes.guess_type(item["name"])
        mime = mime or "application/octet-stream"
        disposition = "inline" if inline else "attachment"
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(path.stat().st_size))
        # Header values must be latin-1. A filename with non-ASCII characters
        # (Cyrillic, emoji, accents, etc.) would raise UnicodeEncodeError here
        # and abort the connection mid-response ("connection reset" in the
        # browser), while /upload and /delete never hit this code path.
        # Use a plain ASCII fallback plus the RFC 5987 filename* form so
        # every browser gets a safe name and the correct original name.
        ascii_name = item["name"].encode("ascii", "replace").decode("ascii").replace('"', "_")
        utf8_name = quote(item["name"], safe="")
        self.send_header(
            "Content-Disposition",
            f'{disposition}; filename="{ascii_name}"; filename*=UTF-8\'\'{utf8_name}',
        )
        self.end_headers()
        with open(path, "rb") as f:
            shutil.copyfileobj(f, self.wfile)

    def do_GET(self):
        try:
            self._do_GET_inner()
        except (BrokenPipeError, ConnectionResetError):
            # клиент оборвал соединение (например, закрыл вкладку во время
            # долгой загрузки/скачивания) — не роняем поток сервера.
            pass
        except Exception as e:
            self._safe_error(500, f"internal error: {e}")

    def _do_GET_inner(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        qs = parse_qs(parsed.query)
        data = load_index()
        lang = self._get_lang()
        current_user = self._current_user(data)

        if path == "/":
            lib_path = norm_path((qs.get("path") or [""])[0])
            if lib_path and lib_path not in all_folder_paths(data):
                lib_path = ""
            self._send_html(render_index_page(lib_path, lang, self._unlocked_map(), current_user))
        elif path == "/login":
            next_url = (qs.get("next") or ["/"])[0]
            self._send_html(render_login_page(lang, next_url))
        elif path == "/logout":
            back_path = norm_path((qs.get("path") or [""])[0])
            cookie = "filelib_session=; Path=/; Max-Age=0; SameSite=Lax"
            self._redirect(f"/?path={back_path}", set_cookie=cookie)
        elif path == "/admin/users":
            if not current_user:
                self._redirect(f"/login?next={quote('/admin/users', safe='')}")
                return
            if not user_has_permission(current_user, "admin"):
                self.send_error(403, "insufficient permissions")
                return
            self._send_html(render_admin_users_page(lang, data))
        elif path.startswith("/lang/"):
            code = path.split("/", 2)[2]
            if code not in TRANSLATIONS:
                code = DEFAULT_LANG
            back_path = norm_path((qs.get("path") or [""])[0])
            cookie = f"filelib_lang={code}; Path=/; Max-Age=31536000; SameSite=Lax"
            self._redirect(f"/?path={back_path}", set_cookie=cookie)
        elif path == "/unlock":
            action = (qs.get("action") or [""])[0]
            next_url = (qs.get("next") or ["/"])[0]
            if action not in AUTH_ACTIONS or data["auth"].get(action) is None:
                self._redirect(next_url)
                return
            self._send_html(render_unlock_page(lang, action, next_url))
        elif path == "/unlock-file":
            file_id = (qs.get("id") or [""])[0]
            next_url = (qs.get("next") or ["/"])[0]
            item = next((it for it in data["files"] if it["id"] == file_id), None)
            if not item or not file_is_protected(item):
                self._redirect(next_url)
                return
            if user_can_bypass_file_password(current_user, item) or self._is_file_unlocked(file_id):
                self._redirect(next_url)
                return
            self._send_html(render_file_unlock_page(lang, file_id, item["name"], next_url))
        elif path == "/register":
            if current_user:
                self._redirect("/")
                return
            self._send_html(render_register_page(lang))
        elif path == "/api/files":
            # Никогда не отдавать хеши/соли паролей (ни аккаунтов, ни старых
            # блокировок view/download/delete) через публичный JSON-эндпоинт.
            safe_data = {
                "folders": data.get("folders", []),
                "files": [
                    {**{k: v for k, v in f.items() if k != "password"},
                     "password_protected": f.get("password") is not None}
                    for f in data.get("files", [])
                ],
                "auth": {k: (v is not None) for k, v in data.get("auth", {}).items()},
                "users": [
                    {"login": u["login"], "permissions": u.get("permissions", []), "created": u.get("created")}
                    for u in data.get("users", [])
                ],
            }
            out = json.dumps(safe_data, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
        elif path == "/trash":
            if not current_user:
                self._redirect(f"/login?next={quote('/trash', safe='')}")
                return
            if not user_has_permission(current_user, "delete"):
                self.send_error(403, "insufficient permissions")
                return
            back_path = norm_path((qs.get("path") or [""])[0])
            self._send_html(render_trash_page(lang, data, back_path))

        elif path.startswith("/preview/"):
            file_id = path.split("/", 2)[2]
            item = next((it for it in data["files"] if it["id"] == file_id), None)
            if not item:
                self.send_error(404, "Файл не найден в библиотеке")
                return
            next_url = self.path
            if file_is_protected(item):
                if not user_can_bypass_file_password(current_user, item) and not self._is_file_unlocked(file_id):
                    self._redirect(f"/unlock-file?id={file_id}&next={quote(next_url, safe='')}")
                    return
            elif data["auth"].get("view") is not None and not self._is_unlocked("view"):
                self._redirect(f"/unlock?action=view&next={quote(next_url, safe='')}")
                return
            fpath = FILES_DIR / item["stored_filename"]
            if not fpath.exists():
                self.send_error(404, "Файл не найден на диске")
                return
            mime, _ = mimetypes.guess_type(item["name"])
            if not (mime and mime.startswith("text/")) and not item["name"].lower().endswith(
                (".txt", ".md", ".json", ".log", ".csv", ".py", ".js", ".html", ".css", ".yml", ".yaml", ".xml")
            ):
                self.send_error(415, "предпросмотр текста недоступен для этого типа файла")
                return
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                self.send_error(500, "не удалось прочитать файл")
                return
            out = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        elif path == "/zip":
            folder_target = norm_path((qs.get("path") or [""])[0])
            if folder_target and folder_target not in all_folder_paths(data):
                self.send_error(404, "папка не найдена")
                return
            next_url = self.path
            if data["auth"].get("download") is not None and not self._is_unlocked("download"):
                self._redirect(f"/unlock?action=download&next={quote(next_url, safe='')}")
                return
            targets = [
                it for it in _folder_files_recursive(data, folder_target)
                if user_can_bypass_file_password(current_user, it) or self._is_file_unlocked(it["id"])
            ]
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for it in targets:
                    fpath = FILES_DIR / it["stored_filename"]
                    if not fpath.exists():
                        continue
                    rel_folder = norm_path(it.get("folder", ""))
                    if folder_target:
                        rel_folder = rel_folder[len(folder_target):].lstrip("/")
                    arcname = join_path(rel_folder, it["name"]) or it["name"]
                    zf.write(fpath, arcname)
            payload = buf.getvalue()
            zip_name = (basename_of(folder_target) or "library") + ".zip"
            ascii_name = zip_name.encode("ascii", "replace").decode("ascii").replace('"', "_")
            utf8_name = quote(zip_name, safe="")
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{utf8_name}',
            )
            self.end_headers()
            self.wfile.write(payload)

        elif path.startswith("/view/") or path.startswith("/download/"):
            action = "view" if path.startswith("/view/") else "download"
            file_id = path.split("/", 2)[2]
            item = next((it for it in data["files"] if it["id"] == file_id), None)
            if not item:
                self.send_error(404, "Файл не найден в библиотеке")
                return
            next_url = self.path  # keep original path + query so the file serves right after unlock
            if file_is_protected(item):
                if not user_can_bypass_file_password(current_user, item) and not self._is_file_unlocked(file_id):
                    self._redirect(f"/unlock-file?id={file_id}&next={quote(next_url, safe='')}")
                    return
            elif data["auth"].get(action) is not None and not self._is_unlocked(action):
                self._redirect(f"/unlock?action={action}&next={quote(next_url, safe='')}")
                return
            self._send_file(item, inline=path.startswith("/view/"))
        else:
            self.send_error(404, "404 :: страница не найдена")

    def do_POST(self):
        try:
            self._do_POST_inner()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except MemoryError:
            self._safe_error(500, "файл слишком большой для текущего лимита памяти сервера")
        except Exception as e:
            self._safe_error(500, f"internal error: {e}")

    def _safe_error(self, status: int, message: str):
        """Пытается вернуть корректный HTTP-ответ вместо обрыва соединения.
        Если заголовки уже отправлены (например, часть файла уже стримилась),
        просто логирует и молча закрывает — клиент всё равно получит
        сетевую ошибку, но сервер не падает и не подвисает."""
        sys.stderr.write(c("[err] ", "yellow") + f"{status}: {message}\n")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            body = message.encode("utf-8", errors="replace")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

    def _read_request_body(self) -> bytes:
        """Читает тело запроса. Поддерживает и обычный `Content-Length`,
        и `Transfer-Encoding: chunked` (некоторые браузеры/прокси шлют
        большие multipart-загрузки чанками без Content-Length — раньше
        такие запросы читались как пустое тело, что вызывало 400 при
        любой попытке загрузить файл)."""
        te = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in te:
            chunks = []
            while True:
                size_line = self.rfile.readline(64).strip()
                if b";" in size_line:  # chunk-extension, игнорируем
                    size_line = size_line.split(b";", 1)[0]
                try:
                    chunk_size = int(size_line, 16)
                except ValueError:
                    break
                if chunk_size == 0:
                    # финальный пустой чанк + возможные trailer-заголовки
                    while True:
                        trailer = self.rfile.readline()
                        if trailer in (b"\r\n", b"\n", b""):
                            break
                    break
                chunks.append(self.rfile.read(chunk_size))
                self.rfile.read(2)  # завершающий CRLF после данных чанка
            return b"".join(chunks)
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        length = max(length, 0)
        return self.rfile.read(length) if length else b""

    def _iter_request_body_chunks(self, chunk_size: int = 65536):
        """Как _read_request_body, но лениво — отдаёт тело запроса
        небольшими кусками вместо накопления всего в памяти. Используется
        при потоковой загрузке файла (см. _handle_upload_streaming)."""
        te = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in te:
            while True:
                size_line = self.rfile.readline(64).strip()
                if b";" in size_line:
                    size_line = size_line.split(b";", 1)[0]
                try:
                    size = int(size_line, 16)
                except ValueError:
                    return
                if size == 0:
                    while True:
                        trailer = self.rfile.readline()
                        if trailer in (b"\r\n", b"\n", b""):
                            break
                    return
                remaining = size
                while remaining:
                    piece = self.rfile.read(min(chunk_size, remaining))
                    if not piece:
                        return
                    remaining -= len(piece)
                    yield piece
                self.rfile.read(2)
        else:
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                length = 0
            remaining = max(length, 0)
            while remaining:
                piece = self.rfile.read(min(chunk_size, remaining))
                if not piece:
                    return
                remaining -= len(piece)
                yield piece

    def _handle_upload_streaming(self, parsed, content_type, data, current_user):
        """Обрабатывает POST /upload потоково: тело файла льётся сразу на
        диск во временный файл и переименовывается на постоянное место,
        без буферизации целого файла в оперативной памяти (см.
        parse_multipart_stream)."""
        if not user_has_permission(current_user, "upload"):
            # Проверяем права ДО чтения тела — не тратим канал и память
            # на большую загрузку, если пользователь всё равно не сможет
            # её сохранить.
            self._redirect(f"/login?next={quote(self.path, safe='')}")
            return
        if "boundary=" not in content_type:
            self._safe_error(400, "multipart/form-data без boundary")
            return
        boundary = content_type.split("boundary=", 1)[1].strip().strip('"')

        FILES_DIR.mkdir(parents=True, exist_ok=True)
        try:
            fields, file_info = parse_multipart_stream(
                self._iter_request_body_chunks(), boundary, FILES_DIR
            )
        except OSError as e:
            self._send_html(
                f"<p>Ошибка записи на диск: {html.escape(str(e))}. "
                f"Возможно, не хватает места. <a href='/'>Назад</a></p>",
                status=500,
            )
            return

        target = norm_path((fields.get("path") or b"").decode(errors="replace"))

        if file_info is None or not file_info.get("filename"):
            if file_info and file_info.get("tmp_path"):
                Path(file_info["tmp_path"]).unlink(missing_ok=True)
            debug_info = (
                f"Content-Length: {self.headers.get('Content-Length', '(нет)')} | "
                f"Transfer-Encoding: {self.headers.get('Transfer-Encoding', '(нет)')} | "
                f"Content-Type: {html.escape(content_type) or '(нет)'} | "
                f"распознанные поля: {list(fields.keys()) or '(ни одного)'}"
            )
            sys.stderr.write(c("[upload-400] ", "yellow") + debug_info + "\n")
            self._send_html(
                "<p>Ошибка загрузки: не удалось найти файл в запросе.</p>"
                f"<p style='font-size:.8em;opacity:.8'>{debug_info}</p>"
                "<p><a href='/'>Назад</a></p>",
                status=400,
            )
            return

        if target:
            ensure_folder_chain(data, target)

        file_id = uuid.uuid4().hex
        safe_name = Path(file_info["filename"]).name
        dest = FILES_DIR / f"{file_id}_{safe_name}"
        try:
            Path(file_info["tmp_path"]).replace(dest)
        except OSError as e:
            Path(file_info["tmp_path"]).unlink(missing_ok=True)
            self._send_html(
                f"<p>Ошибка записи на диск: {html.escape(str(e))}. "
                f"Возможно, не хватает места. <a href='/?path={target}'>Назад</a></p>",
                status=500,
            )
            return

        data["files"].append({
            "id": file_id,
            "name": safe_name,
            "stored_filename": dest.name,
            "size": dest.stat().st_size,
            "added": datetime.now().isoformat(timespec="seconds"),
            "tags": ["upload"],
            "folder": target,
            "password": None,
        })
        save_index(data)
        self._redirect(f"/?path={target}")

    def _do_POST_inner(self):
        parsed = urlparse(self.path)
        content_type = self.headers.get("Content-Type", "")
        data = load_index()
        lang = self._get_lang()
        current_user = self._current_user(data)

        if parsed.path == "/upload" and content_type.lower().startswith("multipart/form-data"):
            self._handle_upload_streaming(parsed, content_type, data, current_user)
            return

        body = self._read_request_body()

        if parsed.path == "/login":
            fields = self._parse_form(body)
            username = fields.get("username", "")
            password = fields.get("password", "")
            next_url = fields.get("next") or "/"
            user = find_user(data, username)
            if user and verify_password(password, user["salt"], user["hash"]):
                token = make_session_token(user["login"])
                cookie = f"filelib_session={token}; Path=/; Max-Age={SESSION_TTL_SECONDS}; SameSite=Lax"
                self._redirect(next_url, set_cookie=cookie)
            else:
                self._send_html(render_login_page(lang, next_url, error=True), status=401)
            return

        elif parsed.path.startswith("/admin/users/"):
            if not user_has_permission(current_user, "admin"):
                self.send_error(403, "insufficient permissions")
                return

            action = parsed.path.split("/", 3)[3]

            if action == "add":
                fields_multi = self._parse_form_multi(body)
                login = (fields_multi.get("login") or [""])[0].strip()
                password = (fields_multi.get("password") or [""])[0]
                perms = set(fields_multi.get("permission", [])) & set(USER_PERMISSIONS)
                if login and password and not find_user(data, login):
                    salt_hex, hash_hex = hash_password(password)
                    data.setdefault("users", []).append({
                        "login": login,
                        "salt": salt_hex,
                        "hash": hash_hex,
                        "permissions": sorted(perms),
                        "unlocked_files": [],
                        "created": datetime.now().isoformat(timespec="seconds"),
                    })
                    save_index(data)
                self._redirect("/admin/users")
                return

            elif action == "permissions":
                fields_multi = self._parse_form_multi(body)
                login = (fields_multi.get("login") or [""])[0]
                perms = set(fields_multi.get("permission", [])) & set(USER_PERMISSIONS)
                user = find_user(data, login)
                if user:
                    user["permissions"] = sorted(perms)
                    save_index(data)
                self._redirect("/admin/users")
                return

            elif action == "password":
                fields = self._parse_form(body)
                login = fields.get("login", "")
                password = fields.get("password", "")
                user = find_user(data, login)
                if user and password:
                    salt_hex, hash_hex = hash_password(password)
                    user["salt"], user["hash"] = salt_hex, hash_hex
                    save_index(data)
                self._redirect("/admin/users")
                return

            elif action == "delete":
                fields = self._parse_form(body)
                login = fields.get("login", "")
                data["users"] = [u for u in data.get("users", []) if u["login"].lower() != login.lower()]
                save_index(data)
                self._redirect("/admin/users")
                return

            else:
                self.send_error(404)
                return

        elif parsed.path == "/unlock":
            fields = self._parse_form(body)
            action = fields.get("action", "")
            next_url = fields.get("next") or "/"
            password = fields.get("password", "")
            entry = data["auth"].get(action)
            if action not in AUTH_ACTIONS or entry is None:
                self._redirect(next_url)
                return
            if verify_password(password, entry["salt"], entry["hash"]):
                token = make_unlock_token(action)
                cookie = f"filelib_unlock_{action}={token}; Path=/; Max-Age={UNLOCK_TTL_SECONDS}; SameSite=Lax"
                self._redirect(next_url, set_cookie=cookie)
            else:
                self._send_html(render_unlock_page(lang, action, next_url, error=True), status=401)
            return

        elif parsed.path == "/unlock-file":
            fields = self._parse_form(body)
            file_id = fields.get("id", "")
            next_url = fields.get("next") or "/"
            password = fields.get("password", "")
            item = next((it for it in data["files"] if it["id"] == file_id), None)
            if not item or not file_is_protected(item):
                self._redirect(next_url)
                return
            entry = item["password"]
            if verify_password(password, entry["salt"], entry["hash"]):
                token = make_unlock_token(f"file:{file_id}")
                cookie = f"filelib_unlock_file_{file_id}={token}; Path=/; Max-Age={UNLOCK_TTL_SECONDS}; SameSite=Lax"
                self._redirect(next_url, set_cookie=cookie)
            else:
                self._send_html(render_file_unlock_page(lang, file_id, item["name"], next_url, error=True), status=401)
            return

        elif parsed.path == "/register":
            if current_user:
                self._redirect("/")
                return
            fields = self._parse_form(body)
            login = fields.get("username", "").strip()
            password = fields.get("password", "")
            confirm = fields.get("confirm", "")
            error = None
            if not login or not password:
                error = "empty"
            elif password != confirm:
                error = "mismatch"
            elif find_user(data, login):
                error = "taken"
            if error:
                self._send_html(render_register_page(lang, error=error, login=login), status=400)
                return
            salt_hex, hash_hex = hash_password(password)
            data.setdefault("users", []).append({
                "login": login,
                "salt": salt_hex,
                "hash": hash_hex,
                "permissions": [],
                "unlocked_files": [],
                "created": datetime.now().isoformat(timespec="seconds"),
            })
            save_index(data)
            token = make_session_token(login)
            cookie = f"filelib_session={token}; Path=/; Max-Age={SESSION_TTL_SECONDS}; SameSite=Lax"
            self._redirect("/", set_cookie=cookie)
            return

        elif parsed.path == "/file/security/set":
            fields = self._parse_form(body)
            file_id = fields.get("file_id", "")
            password = fields.get("password", "")
            back = norm_path(fields.get("path", ""))
            if not user_has_permission(current_user, "security"):
                self._redirect(f"/login?next={quote(f'/?path={back}', safe='')}")
                return
            item = next((it for it in data["files"] if it["id"] == file_id), None)
            if item and password:
                salt_hex, hash_hex = hash_password(password)
                item["password"] = {"salt": salt_hex, "hash": hash_hex}
                save_index(data)
            self._redirect(f"/?path={back}")
            return

        elif parsed.path == "/file/security/clear":
            fields = self._parse_form(body)
            file_id = fields.get("file_id", "")
            back = norm_path(fields.get("path", ""))
            if not user_has_permission(current_user, "security"):
                self._redirect(f"/login?next={quote(f'/?path={back}', safe='')}")
                return
            item = next((it for it in data["files"] if it["id"] == file_id), None)
            if item:
                item["password"] = None
                for u in data.get("users", []):
                    if file_id in u.get("unlocked_files", []):
                        u["unlocked_files"] = [f for f in u["unlocked_files"] if f != file_id]
                save_index(data)
            self._redirect(f"/?path={back}")
            return

        elif parsed.path == "/file/security/grant":
            fields = self._parse_form(body)
            file_id = fields.get("file_id", "")
            login = fields.get("login", "")
            back = norm_path(fields.get("path", ""))
            if not user_has_permission(current_user, "security"):
                self._redirect(f"/login?next={quote(f'/?path={back}', safe='')}")
                return
            user = find_user(data, login)
            item = next((it for it in data["files"] if it["id"] == file_id), None)
            if user and item and file_id not in user.get("unlocked_files", []):
                user.setdefault("unlocked_files", []).append(file_id)
                save_index(data)
            self._redirect(f"/?path={back}")
            return

        elif parsed.path == "/file/security/revoke":
            fields = self._parse_form(body)
            file_id = fields.get("file_id", "")
            login = fields.get("login", "")
            back = norm_path(fields.get("path", ""))
            if not user_has_permission(current_user, "security"):
                self._redirect(f"/login?next={quote(f'/?path={back}', safe='')}")
                return
            user = find_user(data, login)
            if user:
                user["unlocked_files"] = [f for f in user.get("unlocked_files", []) if f != file_id]
                save_index(data)
            self._redirect(f"/?path={back}")
            return

        elif parsed.path == "/security/set":
            fields = self._parse_form(body)
            which = fields.get("which", "")
            password = fields.get("password", "")
            back = norm_path(fields.get("path", ""))
            if not user_has_permission(current_user, "security"):
                self._redirect(f"/login?next={quote(f'/?path={back}', safe='')}")
                return
            if which in AUTH_ACTIONS and password:
                salt_hex, hash_hex = hash_password(password)
                data["auth"][which] = {"salt": salt_hex, "hash": hash_hex}
                save_index(data)
            self._redirect(f"/?path={back}")
            return

        elif parsed.path == "/security/clear":
            fields = self._parse_form(body)
            which = fields.get("which", "")
            back = norm_path(fields.get("path", ""))
            if not user_has_permission(current_user, "security"):
                self._redirect(f"/login?next={quote(f'/?path={back}', safe='')}")
                return
            if which in AUTH_ACTIONS:
                data["auth"][which] = None
                save_index(data)
            self._redirect(f"/?path={back}")
            return

        if parsed.path == "/upload":
            fields = parse_multipart(body, content_type)
            target = norm_path((fields.get("path", (None, b""))[1] or b"").decode(errors="replace"))
            if not user_has_permission(current_user, "upload"):
                self._redirect(f"/login?next={quote(f'/?path={target}', safe='')}")
                return
            filename, content = fields.get("file", (None, None))
            if not filename or content is None:
                debug_info = (
                    f"Content-Length: {self.headers.get('Content-Length', '(нет)')} | "
                    f"Transfer-Encoding: {self.headers.get('Transfer-Encoding', '(нет)')} | "
                    f"тело получено: {len(body)} байт | "
                    f"Content-Type: {html.escape(content_type) or '(нет)'} | "
                    f"boundary найден: {'boundary=' in content_type} | "
                    f"распознанные поля: {list(fields.keys()) or '(ни одного)'}"
                )
                sys.stderr.write(c("[upload-400] ", "yellow") + debug_info + "\n")
                self._send_html(
                    "<p>Ошибка загрузки: не удалось найти файл в запросе.</p>"
                    f"<p style='font-size:.8em;opacity:.8'>{debug_info}</p>"
                    "<p><a href='/'>Назад</a></p>",
                    status=400,
                )
                return
            if target:
                ensure_folder_chain(data, target)
            file_id = uuid.uuid4().hex
            safe_name = Path(filename).name
            dest = FILES_DIR / f"{file_id}_{safe_name}"
            try:
                dest.write_bytes(content)
            except OSError as e:
                self._send_html(
                    f"<p>Ошибка записи на диск: {html.escape(str(e))}. "
                    f"Возможно, не хватает места. <a href='/?path={target}'>Назад</a></p>",
                    status=500,
                )
                return
            data["files"].append({
                "id": file_id,
                "name": safe_name,
                "stored_filename": dest.name,
                "size": dest.stat().st_size,
                "added": datetime.now().isoformat(timespec="seconds"),
                "tags": ["upload"],
                "folder": target,
                "password": None,
            })
            save_index(data)
            self._redirect(f"/?path={target}")

        elif parsed.path == "/mkdir":
            fields = self._parse_form(body)
            parent = norm_path(fields.get("parent", ""))
            if not user_has_permission(current_user, "mkdir"):
                self._redirect(f"/login?next={quote(f'/?path={parent}', safe='')}")
                return
            name = fields.get("name", "").strip()
            if name:
                ensure_folder_chain(data, join_path(parent, name))
                save_index(data)
            self._redirect(f"/?path={parent}")

        elif parsed.path.startswith("/delete/"):
            file_id = parsed.path.split("/", 2)[2]
            fields = self._parse_form(body)
            back = norm_path(fields.get("path", ""))
            if not user_has_permission(current_user, "delete"):
                self._redirect(f"/login?next={quote(f'/?path={back}', safe='')}")
                return
            if data["auth"].get("delete") is not None and not self._is_unlocked("delete"):
                self._redirect(f"/unlock?action=delete&next={quote(f'/?path={back}', safe='')}")
                return
            item = next((it for it in data["files"] if it["id"] == file_id), None)
            if item:
                move_to_trash(data, item)
                save_index(data)
            self._redirect(f"/?path={back}")

        elif parsed.path == "/delete-folder":
            fields = self._parse_form(body)
            folder_target = norm_path(fields.get("folder", ""))
            back = norm_path(fields.get("path", ""))
            if not user_has_permission(current_user, "delete"):
                self._redirect(f"/login?next={quote(f'/?path={back}', safe='')}")
                return
            if data["auth"].get("delete") is not None and not self._is_unlocked("delete"):
                self._redirect(f"/unlock?action=delete&next={quote(f'/?path={back}', safe='')}")
                return
            if folder_target and resolve_folder(data, folder_target) is not None:
                delete_folder_recursive(data, folder_target)
                save_index(data)
            self._redirect(f"/?path={back}")

        elif parsed.path == "/bulk/delete":
            fields_multi = self._parse_form_multi(body)
            back = norm_path((fields_multi.get("path") or [""])[0])
            if not user_has_permission(current_user, "delete"):
                self._redirect(f"/login?next={quote(f'/?path={back}', safe='')}")
                return
            if data["auth"].get("delete") is not None and not self._is_unlocked("delete"):
                self._redirect(f"/unlock?action=delete&next={quote(f'/?path={back}', safe='')}")
                return
            for file_id in fields_multi.get("file_ids", []):
                item = next((it for it in data["files"] if it["id"] == file_id), None)
                if item:
                    move_to_trash(data, item)
            for folder_path in fields_multi.get("folder_paths", []):
                folder_path = norm_path(folder_path)
                if folder_path and resolve_folder(data, folder_path) is not None:
                    delete_folder_recursive(data, folder_path)
            save_index(data)
            self._redirect(f"/?path={back}")
            return

        elif parsed.path == "/bulk/move":
            fields_multi = self._parse_form_multi(body)
            back = norm_path((fields_multi.get("path") or [""])[0])
            dest = norm_path((fields_multi.get("dest") or [""])[0])
            if not user_has_permission(current_user, "mkdir") and not user_has_permission(current_user, "upload"):
                self._redirect(f"/login?next={quote(f'/?path={back}', safe='')}")
                return
            if dest and resolve_folder(data, dest) is None:
                ensure_folder_chain(data, dest)
            dest_resolved = resolve_folder(data, dest) if dest else ""
            for file_id in fields_multi.get("file_ids", []):
                item = next((it for it in data["files"] if it["id"] == file_id), None)
                if item:
                    item["folder"] = dest_resolved or ""
            for folder_path in fields_multi.get("folder_paths", []):
                _move_folder(data, norm_path(folder_path), dest_resolved or "")
            save_index(data)
            self._redirect(f"/?path={back}")
            return

        elif parsed.path == "/move":
            # Drag & drop перемещение одного файла или папки.
            fields = self._parse_form(body)
            kind = fields.get("kind", "")
            key = norm_path(fields.get("key", ""))
            dest = norm_path(fields.get("dest", ""))
            back = norm_path(fields.get("path", ""))
            if not user_has_permission(current_user, "mkdir") and not user_has_permission(current_user, "upload"):
                self.send_error(403, "insufficient permissions")
                return
            if dest and resolve_folder(data, dest) is None:
                ensure_folder_chain(data, dest)
            dest_resolved = resolve_folder(data, dest) if dest else ""
            if kind == "file":
                item = resolve_file(data, key)
                if item is not None:
                    item["folder"] = dest_resolved or ""
            elif kind == "folder":
                _move_folder(data, key, dest_resolved or "")
            save_index(data)
            self._redirect(f"/?path={back}")
            return

        elif parsed.path == "/trash/restore":
            fields = self._parse_form(body)
            trash_id = fields.get("id", "")
            back = norm_path(fields.get("path", ""))
            if not user_has_permission(current_user, "delete"):
                self._redirect(f"/login?next={quote('/trash', safe='')}")
                return
            restore_from_trash(data, trash_id)
            save_index(data)
            self._redirect(f"/trash?path={back}" if back else "/trash")
            return

        elif parsed.path == "/trash/delete":
            fields = self._parse_form(body)
            trash_id = fields.get("id", "")
            if not user_has_permission(current_user, "delete"):
                self._redirect(f"/login?next={quote('/trash', safe='')}")
                return
            entry = next((x for x in data.get("trash", []) if x["id"] == trash_id), None)
            if entry:
                purge_trash_entry(data, entry)
                save_index(data)
            self._redirect("/trash")
            return

        elif parsed.path == "/trash/empty":
            if not user_has_permission(current_user, "delete"):
                self._redirect(f"/login?next={quote('/trash', safe='')}")
                return
            for entry in list(data.get("trash", [])):
                purge_trash_entry(data, entry)
            save_index(data)
            self._redirect("/trash")
            return

        else:
            self.send_error(404)


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def cmd_serve(args):
    ensure_storage()
    server = ThreadingHTTPServer((args.host, args.port), FileLibHandler)
    local_url = f"http://localhost:{args.port}"
    lan_url = f"http://{local_ip()}:{args.port}"

    print_banner()
    ok(f"сервер поднят и слушает эфир...")
    print(f"    {c('локально:', 'dim')}  {c(local_url, 'bgreen')}")
    print(f"    {c('в сети:  ', 'dim')}  {c(lan_url, 'bgreen')}  {c('(доступ с телефона/др. устройств)', 'dim')}")
    print()
    info_msg("Ctrl+C для завершения сессии")
    print()

    if not args.no_browser:
        try:
            webbrowser.open(local_url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        info_msg("соединение разорвано. до связи.")
        server.shutdown()


# ==========================================================================
# Точка входа
# ==========================================================================

def build_parser():
    p = argparse.ArgumentParser(prog="filelib", description="CLI-библиотека файлов с папками (hacker edition)")
    sub = p.add_subparsers(dest="command")

    p_add = sub.add_parser("add", help="добавить файл в библиотеку")
    p_add.add_argument("path", help="путь к файлу на диске")
    p_add.add_argument("--to", help="папка внутри библиотеки, напр. work/reports")
    p_add.add_argument("--name", help="отображаемое имя (по умолчанию — имя файла)")
    p_add.add_argument("--tag", action="append", help="тег (можно указать несколько раз)")
    p_add.add_argument("--move", action="store_true", help="переместить файл вместо копирования")
    p_add.set_defaults(func=cmd_add)

    p_mkdir = sub.add_parser("mkdir", help="создать папку (с подпапками, как mkdir -p)")
    p_mkdir.add_argument("path", help="напр. work/reports/2026")
    p_mkdir.set_defaults(func=cmd_mkdir)

    p_ls = sub.add_parser("ls", help="показать содержимое папки")
    p_ls.add_argument("path", nargs="?", default="", help="папка (по умолчанию — корень)")
    p_ls.set_defaults(func=cmd_ls)

    p_tree = sub.add_parser("tree", help="дерево папок и файлов")
    p_tree.add_argument("path", nargs="?", default="", help="папка (по умолчанию — корень)")
    p_tree.set_defaults(func=cmd_tree)

    p_find = sub.add_parser("find", help="поиск файла по имени/тегу во всей библиотеке")
    p_find.add_argument("query")
    p_find.set_defaults(func=cmd_find)

    p_mv = sub.add_parser("mv", help="переместить файл или папку")
    p_mv.add_argument("source", help="путь/имя файла или папки")
    p_mv.add_argument("dest", help="папка назначения (пусто = корень)")
    p_mv.set_defaults(func=cmd_mv)

    p_info = sub.add_parser("info", help="подробности о файле")
    p_info.add_argument("key", help="путь, имя или id файла")
    p_info.set_defaults(func=cmd_info)

    p_open = sub.add_parser("open", help="открыть файл системным приложением")
    p_open.add_argument("key", help="путь, имя или id файла")
    p_open.set_defaults(func=cmd_open)

    p_rm = sub.add_parser("rm", help="удалить файл или папку (переносится в корзину, см. 'trash')")
    p_rm.add_argument("key", help="путь, имя или id файла/папки")
    p_rm.add_argument("--recursive", "-r", action="store_true", help="удалить папку со всем содержимым")
    p_rm.add_argument("--yes", "-y", action="store_true", help="не спрашивать подтверждение")
    p_rm.set_defaults(func=cmd_rm)

    p_trash = sub.add_parser("trash", help="корзина удалённых файлов (восстановление/очистка)")
    trash_sub = p_trash.add_subparsers(dest="trash_command")

    p_trash_ls = trash_sub.add_parser("ls", help="показать содержимое корзины")
    p_trash_ls.set_defaults(func=cmd_trash_ls)

    p_trash_restore = trash_sub.add_parser("restore", help="восстановить файл из корзины")
    p_trash_restore.add_argument("key", help="id или имя файла в корзине")
    p_trash_restore.set_defaults(func=cmd_trash_restore)

    p_trash_empty = trash_sub.add_parser("empty", help="окончательно очистить корзину")
    p_trash_empty.add_argument("--yes", "-y", action="store_true", help="не спрашивать подтверждение")
    p_trash_empty.set_defaults(func=cmd_trash_empty)

    def _trash_default(args):
        p_trash.print_help()

    p_trash.set_defaults(func=_trash_default)

    p_user = sub.add_parser("user", help="управление аккаунтами (login/пароль/права) для веб-интерфейса")
    user_sub = p_user.add_subparsers(dest="user_command")

    p_user_add = user_sub.add_parser("add", help="создать аккаунт")
    p_user_add.add_argument("login")
    p_user_add.add_argument("--password", help="пароль (если не указан — будет запрошен скрытым вводом)")
    p_user_add.add_argument(
        "--permission", "-p", action="append", choices=USER_PERMISSIONS,
        help="право доступа (можно указать несколько раз): upload, mkdir, delete, security, admin",
    )
    p_user_add.add_argument("--admin", action="store_true", help="выдать все права (эквивалент -p admin)")
    p_user_add.set_defaults(func=cmd_user_add)

    p_user_passwd = user_sub.add_parser("passwd", help="сменить пароль аккаунта")
    p_user_passwd.add_argument("login")
    p_user_passwd.add_argument("--password", help="новый пароль (если не указан — будет запрошен скрытым вводом)")
    p_user_passwd.set_defaults(func=cmd_user_passwd)

    p_user_rm = user_sub.add_parser("rm", help="удалить аккаунт")
    p_user_rm.add_argument("login")
    p_user_rm.add_argument("--yes", "-y", action="store_true", help="не спрашивать подтверждение")
    p_user_rm.set_defaults(func=cmd_user_rm)

    p_user_grant = user_sub.add_parser("grant", help="выдать право аккаунту")
    p_user_grant.add_argument("login")
    p_user_grant.add_argument("permission", choices=USER_PERMISSIONS)
    p_user_grant.set_defaults(func=cmd_user_grant)

    p_user_revoke = user_sub.add_parser("revoke", help="отозвать право у аккаунта")
    p_user_revoke.add_argument("login")
    p_user_revoke.add_argument("permission", choices=USER_PERMISSIONS)
    p_user_revoke.set_defaults(func=cmd_user_revoke)

    p_user_ls = user_sub.add_parser("ls", help="список аккаунтов и их прав")
    p_user_ls.set_defaults(func=cmd_user_ls)

    def _user_default(args):
        p_user.print_help()

    p_user.set_defaults(func=_user_default)

    p_serve = sub.add_parser("serve", help="запустить локальный веб-сервер")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--no-browser", action="store_true", help="не открывать браузер автоматически")
    p_serve.set_defaults(func=cmd_serve)

    return p


def main():
    ensure_storage()
    parser = build_parser()
    args = parser.parse_args()
    if not getattr(args, "command", None):
        print_banner()
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
