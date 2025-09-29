import requests
import hashlib
import urllib3
from xml.etree import ElementTree as ET
from datetime import datetime
import uuid
import pandas as pd
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkcalendar import DateEntry


# === СПИСОК БАЗ ДАННЫХ IIKO ===
IIKO_BASES = {
    
}

# === АВТОРИЗАЦИЯ ===
LOGIN = ""
PASSWORD = ""


# Отключение предупреждений о сертификатах
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IikoRevenueReporter:
    def __init__(self, login, password):
        self.login = login
        self.password = password
        self.session = requests.Session()
        self.session.verify = False
        self.token = None

    def auth(self, base_url):
        """Аутентификация"""
        auth_url = f"{base_url}/auth"
        try:
            password_hash = hashlib.sha1(self.password.encode()).hexdigest()
            response = self.session.post(
                auth_url,
                data={'login': self.login, 'pass': password_hash},
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            if response.status_code == 200:
                self.token = response.text.strip()
                return True, "Авторизация успешна"
            return False, f"Ошибка авторизации: {response.status_code} - {response.text}"
        except Exception as e:
            return False, f"Ошибка подключения: {str(e)}"

    def get_stores(self, base_url):
        """Загрузка складов"""
        if not self.token:
            return None, "Сначала авторизуйтесь."

        url = f"{base_url}/v2/entities/list"
        params = {"rootType": "Account", "includeDeleted": "false"}

        try:
            response = self.session.get(url, params=params, headers={'Authorization': self.token})
            if response.status_code == 200:
                accounts = response.json()
                stores = [
                    acc for acc in accounts
                    if isinstance(acc, dict) and acc.get("type") == "INVENTORY_ASSETS"
                ]
                return stores, ""
            else:
                return None, f"Ошибка API: {response.status_code}\n{response.text}"
        except Exception as e:
            return None, f"Ошибка запроса: {e}"

    def find_product_by_name(self, base_url, search_name):
        """Поиск товара по имени"""
        if not self.token:
            return None, "Сначала авторизуйтесь."

        url = f"{base_url}/v2/entities/products/list"
        try:
            response = self.session.post(
                url,
                data={"includeDeleted": "false"},
                headers={'Authorization': self.token}
            )
            if response.status_code != 200:
                return None, f"Ошибка номенклатуры: {response.status_code}"

            products = response.json()
            search_lower = search_name.lower()

            for p in products:
                name = p.get("name", "")
                if search_lower in name.lower():
                    if p.get("stockControl", True):  # только с учётом
                        return {"id": p["id"].strip().lower(), "name": name}, ""

            return None, f"Товар '{search_name}' не найден или не ведёт учёт."
        except Exception as e:
            return None, f"Ошибка поиска: {e}"

    def upload_inventory(self, base_url, inventory_data):
        """Отправка инвентаризации"""
        if not self.token:
            return None, "Сначала авторизуйтесь."

        url = f"{base_url}/documents/import/incomingInventory"
        root = ET.Element("document")

        for key in ["documentNumber", "dateIncoming", "status", "storeId", "comment"]:
            if key in inventory_data:
                ET.SubElement(root, key).text = str(inventory_data[key])

        use_time = ET.SubElement(root, "useDefaultDocumentTime")
        use_time.text = str(bool(inventory_data.get("useDefaultDocumentTime", False))).lower()

        items_el = ET.SubElement(root, "items")
        for item in inventory_data.get("items", []):
            item_el = ET.SubElement(items_el, "item")
            for field in ["status", "productId", "amountContainer", "comment"]:
                if field in item and item[field] is not None:
                    ET.SubElement(item_el, field).text = str(item[field])

        xml_str = ET.tostring(root, encoding='utf-8', method='xml').decode('utf-8')
        full_xml = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str

        try:
            response = self.session.post(
                url,
                data=full_xml,
                headers={
                    'Content-Type': 'application/xml',
                    'Authorization': self.token
                }
            )
            if response.status_code == 200:
                result_xml = ET.fromstring(response.content)
                return result_xml, "Успешно отправлено"
            else:
                error_text = response.text.strip() or f"HTTP {response.status_code}"
                return None, f"Ошибка: {error_text}"
        except Exception as e:
            return None, f"Ошибка сети: {str(e)}"


class InventoryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("iiko Инвентаризация из Excel")
        self.root.geometry("640x740")
        self.file_path = tk.StringVar()
        self.selected_base = tk.StringVar()
        self.reporter = None
        self.stores = []
        self.setup_ui()

    def setup_ui(self):
        frame = ttk.Frame(self.root, padding="15")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # === Заголовок ===
        title_label = ttk.Label(frame, text="📤 Инвентаризация в iiko", font=("Arial", 14, "bold"))
        title_label.grid(row=0, column=0, columnspan=5, pady=(0, 20), sticky=tk.W)

        # === Блок 1: Организация + Авторизация ===
        ttk.Label(frame, text="🏢 Организация:", font=("Arial", 10)).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.base_combo = ttk.Combobox(
            frame,
            values=list(IIKO_BASES.keys()),
            textvariable=self.selected_base,
            state="readonly",
            width=38
        )
        self.base_combo.grid(row=1, column=1, columnspan=2, pady=5, sticky=tk.W)
        self.base_combo.set("Старик Хинкалыч Курск")

        # Логин
        ttk.Label(frame, text="👤 Логин:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.login_entry = ttk.Entry(frame, width=30)
        self.login_entry.insert(0, LOGIN)
        self.login_entry.grid(row=2, column=1, pady=5, sticky=tk.W)

        # Пароль
        ttk.Label(frame, text="🔑 Пароль:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(frame, width=30, show="*")
        self.password_entry.insert(0, PASSWORD)
        self.password_entry.grid(row=3, column=1, pady=5, sticky=tk.W)

        # Кнопка авторизации и статус
        ttk.Button(frame, text="Авторизоваться", command=self.authorize).grid(row=2, column=2, rowspan=2, padx=10)
        self.auth_status = ttk.Label(frame, text="❌ Не авторизован", foreground="red")
        self.auth_status.grid(row=2, column=3, rowspan=2, padx=(10, 0), sticky=tk.W)

        # === Разделитель ===
        ttk.Separator(frame, orient=tk.HORIZONTAL).grid(row=4, column=0, columnspan=5, sticky='ew', pady=15)

        # === Блок 2: Загрузка файла ===
        ttk.Label(frame, text="📂 Excel-файл:", font=("Arial", 10)).grid(row=5, column=0, sticky=tk.W, pady=5)

        # Поле ввода пути + кнопка "Выбрать" рядом
        file_frame = ttk.Frame(frame)
        file_frame.grid(row=6, column=0, columnspan=4, sticky=tk.W, pady=3)

        ttk.Entry(file_frame, textvariable=self.file_path, width=50).pack(side=tk.LEFT)
        ttk.Button(file_frame, text="Выбрать", command=self.browse_file).pack(side=tk.LEFT, padx=(5, 0))

        # === Разделитель ===
        ttk.Separator(frame, orient=tk.HORIZONTAL).grid(row=7, column=0, columnspan=5, sticky='ew', pady=15)

        # === Блок 3: Параметры документа ===
        ttk.Label(frame, text="📦 Параметры инвентаризации", font=("Arial", 12, "bold")).grid(
            row=8, column=0, columnspan=5, pady=(0, 15), sticky=tk.W)

        # --- Склад ---
        ttk.Label(frame, text="Склад:").grid(row=9, column=0, sticky=tk.W, pady=6)
        self.store_combo = ttk.Combobox(frame, state="disabled", width=40)
        self.store_combo.grid(row=9, column=1, columnspan=3, pady=6, sticky=tk.W)

        # --- Дата и время ---
        ttk.Label(frame, text="Дата и время:").grid(row=10, column=0, sticky=tk.W, pady=6)

        datetime_frame = ttk.Frame(frame)
        datetime_frame.grid(row=10, column=1, columnspan=3, pady=6, sticky=tk.W)

        self.date_entry = DateEntry(
            datetime_frame,
            width=12,
            background='darkblue',
            foreground='white',
            date_pattern='yyyy-mm-dd'
        )
        self.date_entry.set_date(datetime.now())
        self.date_entry.pack(side=tk.LEFT)

        ttk.Label(datetime_frame, text="   ").pack(side=tk.LEFT)  # отступ

        self.time_spin_h = ttk.Spinbox(datetime_frame, from_=0, to=23, width=3, format="%02.0f")
        self.time_spin_h.set(datetime.now().hour)
        self.time_spin_h.pack(side=tk.LEFT)

        ttk.Label(datetime_frame, text=":", font=("Arial", 10)).pack(side=tk.LEFT)

        self.time_spin_m = ttk.Spinbox(datetime_frame, from_=0, to=59, width=3, format="%02.0f")
        self.time_spin_m.set((datetime.now().minute // 5) * 5)
        self.time_spin_m.pack(side=tk.LEFT)

        ttk.Label(datetime_frame, text=" (ЧЧ:ММ)", foreground="gray", font=("Arial", 9)).pack(side=tk.LEFT, padx=(5, 0))

        # --- Статус документа ---
        ttk.Label(frame, text="Статус:").grid(row=11, column=0, sticky=tk.W, pady=10)
        self.status_var = tk.StringVar(value="NEW")
        ttk.Radiobutton(frame, text="Черновик", variable=self.status_var, value="NEW").grid(row=11, column=1, sticky=tk.W)
        ttk.Radiobutton(frame, text="Проведён", variable=self.status_var, value="PROCESSED").grid(row=11, column=2, sticky=tk.W)

        # === Кнопка отправки ===
        ttk.Button(frame, text="🚀 Создать инвентаризацию", command=self.upload_from_excel).grid(
            row=12, column=0, columnspan=5, pady=20)

        # === Лог операций ===
        ttk.Label(frame, text="Лог операций:", font=("Arial", 10)).grid(row=13, column=0, sticky=tk.W, pady=(0, 5))

        # Поле лога
        self.log_text = tk.Text(frame, height=12, width=85, font=("Courier", 9))
        self.log_text.grid(row=14, column=0, columnspan=4, pady=(0, 5), sticky='ew')
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scrollbar.grid(row=14, column=4, sticky='ns')
        self.log_text.config(yscrollcommand=scrollbar.set)

        # Кнопка "Очистить лог" — под логом, по центру
        ttk.Button(frame, text="Очистить лог", command=self.clear_log).grid(
            row=15, column=0, columnspan=5, pady=(0, 10), sticky=tk.W+tk.E)

        # Настройка растягивания колонок
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(2, weight=1)
        frame.columnconfigure(3, weight=1)
        frame.columnconfigure(4, weight=0)

    def log(self, message):
        self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M')}] {message}\n")
        self.log_text.see(tk.END)
        # Ограничиваем размер лога (~1000 строк)
        if int(self.log_text.index('end-1c').split('.')[0]) > 1000:
            self.log_text.delete(1.0, 2.0)

    def clear_log(self):
        """Очищает текстовое поле лога"""
        self.log_text.delete(1.0, tk.END)
        self.log("Лог очищен")

    def browse_file(self):
        path = filedialog.askopenfilename(filetypes=[("Excel", "*.xlsx *.xls")])
        if path:
            self.file_path.set(path)
            self.log(f"Файл выбран: {path}")

    def authorize(self):
        self.log_text.delete(1.0, tk.END)
        selected_name = self.selected_base.get()
        if not selected_name:
            messagebox.showerror("Ошибка", "Выберите организацию!")
            return

        base_url = IIKO_BASES[selected_name]
        login = self.login_entry.get().strip()
        password = self.password_entry.get().strip()

        if not login or not password:
            messagebox.showerror("Ошибка", "Заполните логин и пароль!")
            return

        self.reporter = IikoRevenueReporter(login, password)
        success, msg = self.reporter.auth(base_url)
        self.log(msg)

        if success:
            self.auth_status.config(text="✅ Авторизован", foreground="green")
            self.load_stores(base_url)
        else:
            self.auth_status.config(text="❌ Ошибка", foreground="red")
            messagebox.showerror("Ошибка", msg)

    def load_stores(self, base_url):
        """Загружает склады с фильтрацией: исключает 'не используем' для всех,
           и дополнительно фильтрует по городам только для Казани"""
        stores, err = self.reporter.get_stores(base_url)
        if err:
            self.log(f"❌ Ошибка загрузки складов: {err}")
            return

        if not stores:
            self.log("⚠️ Склады не найдены")
            return

        # Чёрный список слов — склады с такими словами всегда исключаются
        blacklist = [
            "не используем",
            "не используется",
            "тестовый",
            "тест ",
            "архив",
            "резерв",
            "черновик",
            "временный",
            "backup"
        ]

        # Получаем выбранную организацию
        selected_base = self.selected_base.get()

        filtered_stores = []
        for store in stores:
            name = store["name"]
            name_lower = name.lower().strip()

            # Проверяем чёрный список — всегда!
            is_blacklisted = any(bad in name_lower for bad in blacklist)
            if is_blacklisted:
                # self.log(f"🚫 Пропущен (не используем): {name}")
                continue

            # Дополнительная фильтрация ТОЛЬКО для Казани
            if "Казань" in selected_base:
                keywords = ["казань", "железногорск", "брянск"]
                if not any(kw in name_lower for kw in keywords):
                    # self.log(f"🔍 Пропущен (не по локации): {name}")
                    continue

            # Если прошёл все проверки — добавляем
            filtered_stores.append(store)

        stores = filtered_stores

        if not stores:
            self.log("⚠️ После фильтрации ни один склад не подошёл")
            self.store_combo.config(state="disabled", values=[])
            return

        # Сохраняем и заполняем комбобокс
        self.stores = stores
        store_names = [s["name"] for s in stores]
        self.store_combo.config(state="readonly", values=store_names)
        self.log(f"✅ Загружено складов: {len(stores)}")

    def upload_from_excel(self):
        if not self.reporter:
            messagebox.showerror("Ошибка", "Сначала авторизуйтесь!")
            return

        file_path = self.file_path.get()
        if not file_path:
            messagebox.showerror("Ошибка", "Выберите Excel-файл!")
            return

        if not self.store_combo.get():
            messagebox.showerror("Ошибка", "Выберите склад!")
            return

        try:
            excel_file = pd.ExcelFile(file_path)
            sheet_names = excel_file.sheet_names
            self.log(f"✅ Найдено листов: {len(sheet_names)} — {', '.join(sheet_names)}")

            selected_store_name = self.store_combo.get()
            store = next((s for s in self.stores if s["name"] == selected_store_name), None)
            if not store:
                messagebox.showerror("Ошибка", "Склад не найден")
                return

            base_url = IIKO_BASES[self.selected_base.get()]

            date_obj = self.date_entry.get_date()
            hour = int(self.time_spin_h.get())
            minute = int(self.time_spin_m.get())
            dt = datetime.combine(date_obj, datetime.min.time().replace(hour=hour, minute=minute))
            date_incoming = dt.strftime("%Y-%m-%dT%H:%M:00")

            for sheet_name in sheet_names:
                self.log(f"\n🔄 Обработка листа: '{sheet_name}'")

                # Читаем лист — заголовки в первой строке (как ты сделал)
                try:
                    df = pd.read_excel(file_path, sheet_name=sheet_name, header=0)
                except Exception as e:
                    self.log(f"❌ Не удалось прочитать лист '{sheet_name}': {e}")
                    continue

                # Гибкая проверка колонок — ищем по ключевым словам
                name_keywords = ["наименов", "товар", "название", "продукт", "позиция"]
                amount_keywords = ["остаток", "факт", "количеств", "количество", "фактический"]
                comment_keywords = ["отметк", "коммент", "замет"]

                name_col = next((col for col in df.columns 
                                if any(kw in str(col).strip().lower() for kw in name_keywords)), None)
                amount_col = next((col for col in df.columns 
                                  if any(kw in str(col).strip().lower() for kw in amount_keywords)), None)
                comment_col = next((col for col in df.columns 
                                   if any(kw in str(col).strip().lower() for kw in comment_keywords)), None)

                if not name_col or not amount_col:
                    self.log(f"❌ Лист '{sheet_name}' не содержит нужных колонок: "
                             f"наименование={name_col}, остаток={amount_col}")
                    continue

                self.log(f"✅ Лист '{sheet_name}': найдены колонки: "
                         f"'{name_col}', '{amount_col}', {'-' if not comment_col else comment_col}")

                items = []
                errors = []

                for idx, row in df.iterrows():
                    product_name = str(row[name_col]).strip()
                    if not product_name or product_name.lower() == 'nan':
                        continue  # Пропускаем пустые строки

                    # Получаем количество — если пусто, ставим 0
                    amount_val = row[amount_col]
                    if pd.isna(amount_val) or str(amount_val).strip() == '':
                        amount = 0.0
                        self.log(f"⚠️ Лист '{sheet_name}', строка {idx+2}: количество пустое → установлено 0")
                    else:
                        amount_str = str(amount_val).strip().replace(',', '.')
                        if not amount_str or not any(c.isdigit() for c in amount_str):
                            errors.append(f"Лист '{sheet_name}', строка {idx+2}: некорректное количество '{amount_str}' → установлено 0")
                            amount = 0.0
                        else:
                            try:
                                amount = float(amount_str)
                                if amount < 0:
                                    errors.append(f"Лист '{sheet_name}', строка {idx+2}: отрицательное количество '{amount}' → установлено 0")
                                    amount = 0.0
                            except (ValueError, TypeError):
                                errors.append(f"Лист '{sheet_name}', строка {idx+2}: не удалось преобразовать в число '{amount_str}' → установлено 0")
                                amount = 0.0

                    # Поиск товара — если не найден, пропускаем
                    product, err = self.reporter.find_product_by_name(base_url, product_name)
                    if not product:
                        errors.append(f"Лист '{sheet_name}', строка {idx+2}: {err} → позиция пропущена")
                        continue

                    comment = str(row.get(comment_col, "")).strip() or f"Лист: {sheet_name}"

                    items.append({
                        "status": "SAVE",
                        "productId": product["id"],
                        "amountContainer": amount,
                        "comment": comment[:255]
                    })

                if not items:
                    self.log(f"⚠️ Лист '{sheet_name}': нет корректных позиций")
                    continue

                doc_number = f"INV-{uuid.uuid4().hex[:8].upper()}"
                inventory_data = {
                    "documentNumber": doc_number,
                    "dateIncoming": date_incoming,
                    "status": self.status_var.get(),
                    "storeId": store["id"],
                    "comment": f"Склад: {selected_store_name} | Лист: {sheet_name}",
                    "useDefaultDocumentTime": False,
                    "items": items
                }

                self.log(f"📤 Отправка: {doc_number}, лист '{sheet_name}'")
                result_xml, msg = self.reporter.upload_inventory(base_url, inventory_data)
                self.log(msg)

                if result_xml is not None:
                    valid = result_xml.find("valid").text
                    doc_num = result_xml.find("documentNumber").text
                    self.log(f"✅ Документ: {doc_num}, валиден: {valid}")
                    if valid == "true":
                        store_elem = result_xml.find("store/name")
                        if store_elem is not None:
                            self.log(f"🏭 На складе: {store_elem.text}")
                        for item in result_xml.findall("items/item"):
                            name = item.find("product/name").text
                            actual = item.find("actualAmount").text
                            diff = item.find("differenceAmount").text
                            self.log(f"📦 {name}: фактически {actual}, разница {diff}")
                    else:
                        error = result_xml.find("errorMessage")
                        if error is not None and error.text:
                            self.log(f"❌ Ошибка: {error.text}")
                else:
                    self.log(f"❌ Ошибка отправки листа '{sheet_name}'")

                if errors:
                    for err in errors:
                        self.log(f"🔴 {err}")

            self.log("\n🎉 Все листы обработаны!")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при обработке файла: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = InventoryApp(root)
    root.mainloop()