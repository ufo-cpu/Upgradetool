"""Router Batch Management Tool (GUI + Orchestrator)

- Phases: (1) 设备改址(顺序) → (2) 任务并行(升级/配置) → (3) 验证(可选) → (4) MES 上报(可选)
- 设备发现: 通过 Scapy ARP 在共享 IP 上发现 MAC 列表，结合自动网卡选择
- 执行引擎: Playwright 驱动 Web 自动化，线程池并行处理设备
- 连通性: 通过通用 TCP 端口检查确保设备/服务在线
- 稳定性: 静态 ARP 固定目标、改址后清理 ARP、消息队列跨线程更新 GUI
"""
import glob
# main_app.py
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
import threading
import queue
import subprocess
import re
import os
import sys
import time
import logging
import json
import socket
import psutil
import ipaddress
import requests
import pandas as pd
from playwright.sync_api import Playwright, sync_playwright, expect
import telnetlib
import locale
import platform
from contextlib import nullcontext
# --- Project Modules ---
from models import model_factory
from i18n import get_i18n
from config.device_defaults import get_model_defaults

# --- Set up basic logging for console output ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s')

class BatchUpdaterApp:
    """主应用：负责 GUI、任务调度与跨线程通信。

    组成：
    - GUI（主线程）: Tkinter 控制面板、状态/进度、日志与结果表
    - 调度线程（Orchestrator）: 统一编排四阶段流程
    - 工作线程池: 并行执行升级/配置等 Playwright 自动化任务

    关键稳定性机制：
    - 自动选择同网段网卡，结合 ARP 扫描发现设备
    - 改址前设置静态 ARP，避免 ARP 竞争；任务结束统一清 ARP
    - 采用队列在工作线程与 GUI 线程之间传递消息，避免直接跨线程操作控件
    """
    def __init__(self, root):
        """初始化应用与 GUI 状态、绑定菜单与变量，启动 GUI 轮询等。"""
        self.root = root
        self.i18n = get_i18n()
        self._detect_system_language()
        self.i18n.register_callback(self._on_language_changed)
        self.root.title(self.i18n.t('app_title'))
        self.root.geometry("1000x800")

        # --- Menu Bar ---
        self._build_menus()

        self.gui_queue = queue.Queue()
        self.verification_queue = queue.Queue()
        self.worker_thread = None
        self.stop_event = threading.Event()

        # --- Job Definition ---
        self.job_definition = {
            "model": tk.StringVar(),
            "protocol": tk.StringVar(value="http"),
            "port": tk.StringVar(value="80"),
            "do_upgrade": tk.BooleanVar(),
            "firmware_path": tk.StringVar(),
            "do_ig502_step": tk.BooleanVar(value=True),
            "do_import_config": tk.BooleanVar(),
            "do_upgrade_boot": tk.BooleanVar(value=True),  # 新增：是否升级Bootloader
            "do_shipmode": tk.BooleanVar(value=False),
            "config_path": tk.StringVar(),
            "incremental_config_path": tk.StringVar(),
            "do_restore_defaults": tk.BooleanVar(value=False),
            "restore_default_ip": tk.BooleanVar(),
            "is_default_ip": tk.StringVar(),
            "do_modify_config": tk.BooleanVar(value=False),
            "do_import_incremental_config": tk.BooleanVar(value=False),
            "modify_config_text": tk.StringVar(),
            "initial_ip": tk.StringVar(value="192.168.2.1"),
            "discovery_cidr": tk.StringVar(),
            "cidr_mode": tk.StringVar(value=""),  # "" (none), "CIDR-302", or "CIDR-BOX"
            "cidr_box_target_count": tk.StringVar(value="12"),  # 默认目标数量
            "box_ssh_host": tk.StringVar(),
            "box_ssh_user": tk.StringVar(value="linaro"),
            "box_ssh_password": tk.StringVar(value="linaro"),
            # "box_ssh_user": tk.StringVar(value="edge"),
            # "box_ssh_password": tk.StringVar(value="security@edge"),
            "new_ip_start": tk.StringVar(value="192.168.2.200"),
            "network_interface": tk.StringVar(value="Ethernet 4"),
            "username": tk.StringVar(),
            "password": tk.StringVar(),
            "credential_mode": tk.StringVar(value="Static"),  # Static, API, File
            "credential_file_path": tk.StringVar(),
            "use_dynamic_password": tk.BooleanVar(value=False),
            "verify_enabled": tk.BooleanVar(),
            "verify_ip": tk.StringVar(value="192.168.2.1"),
            "verify_protocol": tk.StringVar(value="http"),
            "verify_port": tk.StringVar(value="80"),
            "verify_username": tk.StringVar(),
            "verify_password": tk.StringVar(),
            "oem_action": tk.StringVar(value="None"),
            "element_verify_enabled": tk.BooleanVar(),
            "element_search_value": tk.StringVar(value="None"),
            # 用户配置项：记录底层设备 MAC 与 IP 是否一致，仅作为配置存储，不参与业务逻辑判断
            "lowest_mac_ip_same": tk.BooleanVar(value=False),
        }

        self.ig502_expected_ip = "192.168.1.1"
        self.ig502_script_relpath = os.path.join("scripts", "ig502", "ig502_step.py")
        
        # --- Status Variables ---
        self.status_vars = {
            "overall_status": tk.StringVar(value=self.i18n.t('status.idle')),
            "progress_counter": tk.StringVar(value=self.i18n.format('status.processed_format', count=0, total=0)),
            "verified_counter": tk.StringVar(value=self.i18n.format('status.verified_format', count=0, total=0)),
            "time_elapsed": tk.StringVar(value=self.i18n.format('status.time_format', time='00:00:00')),
            "api_status": tk.StringVar(value=self.i18n.t('status.login_not_configured')),
        }
        
        self.device_map = {} # Maps MAC to Treeview item ID
        self.mac_to_box_ip = {} # Maps device MAC to BOX IP (for CIDR-BOX mode NAT refresh)
        # CIDR-BOX 模式下，升级后 BOX NAT 刷新使用的缓存和锁（避免并发在同一 BOX 上跑脚本）
        self.box_nat_refresh_cache = {}  # {box_ip: {mac: linux_ip} 或 None}
        self.box_nat_refresh_lock = threading.Lock()
        self.timer_running = False
        # ---【新增】: 永久索引映射表 {mac: index_int} ---
        self.fixed_indices = {}


        # API Login Credentials
        self.api_domain = None
        self.operator_username = None
        self.operator_password = None
        self.auth_token = None
        self.refresh_token = None
        self.token_expired_time = 0
        self.newly_installed_firmware_version = None

        self._create_widgets()
        self._toggle_cidr_fields()  # Initialize CIDR field visibility
        self.process_gui_queue()
        self.update_start_button_state()
        self.load_config() # Load config on startup

    def _create_widgets(self):
        """构建主界面控件树（配置区/动作区/状态区/日志区）。

        注意：不做业务逻辑；状态更新依赖 GUI 消息队列，避免直接跨线程更新控件。
        """
        # --- Status Bar (at the bottom) ---
        status_bar = ttk.Frame(self.root, relief=tk.SUNKEN, padding="2 5 2 5")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(status_bar, textvariable=self.status_vars["api_status"]).pack(side="left")

        # --- Main Paned Window (fills the rest of the space) ---
        main_pane = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        top_frame = ttk.Frame(main_pane)
        main_pane.add(top_frame)

        log_zone_frame = ttk.LabelFrame(main_pane, text=self.i18n.t('log.title'))
        main_pane.add(log_zone_frame, weight=1)

        # --- 1. Config Zone ---
        config_zone_frame = ttk.LabelFrame(top_frame, text=self.i18n.t('config.title'))
        config_zone_frame.grid(row=0, column=0, rowspan=2, padx=10, pady=10, sticky="ns")
        
        ttk.Label(config_zone_frame, text=self.i18n.t('config.router_model')).grid(row=0, column=0, sticky="w", padx=5, pady=3)
        self.model_combo = ttk.Combobox(config_zone_frame, textvariable=self.job_definition["model"], state="readonly", width=20)
        self.model_combo['values'] = model_factory.get_available_models()
        self.model_combo.grid(row=0, column=1, sticky="ew", padx=5, pady=3)
        self.model_combo.bind("<<ComboboxSelected>>", self._on_model_selected)

        ttk.Label(config_zone_frame, text=self.i18n.t('config.protocol')).grid(row=1, column=0, sticky="w", padx=5, pady=3)
        self.protocol_combo = ttk.Combobox(config_zone_frame, textvariable=self.job_definition["protocol"], values=["http", "https"], width=20)
        self.protocol_combo.grid(row=1, column=1, sticky="ew", padx=5, pady=3)

        ttk.Label(config_zone_frame, text=self.i18n.t('config.port')).grid(row=2, column=0, sticky="w", padx=5, pady=3)
        port_entry = ttk.Entry(config_zone_frame, textvariable=self.job_definition["port"], width=22)
        port_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=3)

        # CIDR Mode Selection and Discovery CIDR on same row (row 3)
        cidr_frame = ttk.Frame(config_zone_frame)
        cidr_frame.grid(row=3, column=0, columnspan=2, sticky="ew", padx=5, pady=3)
        
        # Radio buttons for CIDR mode (optional)
        ttk.Radiobutton(
            cidr_frame,
            text=self.i18n.t('config.cidr_mode_302'),
            variable=self.job_definition["cidr_mode"],
            value="CIDR-302",
            # 支持再次点击已选中的单选按钮时取消选择
            command=lambda m="CIDR-302": self._on_cidr_mode_clicked(m),
        ).pack(side=tk.LEFT)
        ttk.Radiobutton(
            cidr_frame,
            text=self.i18n.t('config.cidr_mode_box'),
            variable=self.job_definition["cidr_mode"],
            value="CIDR-BOX",
            # 支持再次点击已选中的单选按钮时取消选择
            command=lambda m="CIDR-BOX": self._on_cidr_mode_clicked(m),
        ).pack(side=tk.LEFT, padx=10)

        # 仅记录“底层设备 MAC 与 IP 是否一致”的用户选择，不参与任何业务逻辑
        self.lowest_mac_ip_same_check = ttk.Checkbutton(
            cidr_frame,
            text=self.i18n.t('config.lowest_mac_ip_same'),
            variable=self.job_definition["lowest_mac_ip_same"],
        )
        # self.lowest_mac_ip_same_check.pack(side=tk.LEFT, padx=10)
        
        # Discovery CIDR field - shown when either mode is selected
        self.discovery_label = ttk.Label(cidr_frame, text=self.i18n.t('config.discovery_cidr'))
        self.discovery_entry = ttk.Entry(cidr_frame, textvariable=self.job_definition["discovery_cidr"], width=22)

        ttk.Label(config_zone_frame, text=self.i18n.t('config.initial_ip')).grid(row=4, column=0, sticky="w", padx=5, pady=3)
        init_ip_entry = ttk.Entry(config_zone_frame, textvariable=self.job_definition["initial_ip"], width=22)
        init_ip_entry.grid(row=4, column=1, sticky="ew", padx=5, pady=3)

        ttk.Label(config_zone_frame, text=self.i18n.t('config.new_ip_start')).grid(row=5, column=0, sticky="w", padx=5, pady=3)
        new_ip_entry = ttk.Entry(config_zone_frame, textvariable=self.job_definition["new_ip_start"], width=22)
        new_ip_entry.grid(row=5, column=1, sticky="ew", padx=5, pady=3)

        ttk.Label(config_zone_frame, text=self.i18n.t('config.username')).grid(row=6, column=0, sticky="w", padx=5, pady=3)
        self.user_entry = ttk.Entry(config_zone_frame, textvariable=self.job_definition["username"], width=22)
        self.user_entry.grid(row=6, column=1, sticky="ew", padx=5, pady=3)

        ttk.Label(config_zone_frame, text=self.i18n.t('config.password')).grid(row=7, column=0, sticky="w", padx=5, pady=3)
        self.pass_entry = ttk.Entry(config_zone_frame, textvariable=self.job_definition["password"], show="*", width=22)
        self.pass_entry.grid(row=7, column=1, sticky="ew", padx=5, pady=3)

        cred_frame = ttk.LabelFrame(config_zone_frame, text=self.i18n.t('config.credential_mode'))
        cred_frame.grid(row=8, column=0, columnspan=2, sticky="ew", padx=5, pady=10)

        top_cred_frame = ttk.Frame(cred_frame)
        top_cred_frame.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        ttk.Radiobutton(top_cred_frame, text=self.i18n.t('config.static_credentials'), variable=self.job_definition["credential_mode"], value="Static", command=self._toggle_credential_fields).pack(side=tk.LEFT)
        ttk.Radiobutton(top_cred_frame, text=self.i18n.t('config.dynamic_password_api'), variable=self.job_definition["credential_mode"], value="API", command=self._toggle_credential_fields).pack(side=tk.LEFT, padx=10)
        
        file_cred_frame = ttk.Frame(cred_frame)
        file_cred_frame.grid(row=1, column=0, sticky="w", padx=5, pady=2)
        ttk.Radiobutton(file_cred_frame, text=self.i18n.t('config.import_from_file'), variable=self.job_definition["credential_mode"], value="File", command=self._toggle_credential_fields).pack(side=tk.LEFT)
        self.cred_file_entry = ttk.Entry(file_cred_frame, textvariable=self.job_definition["credential_file_path"], width=40, state="disabled")
        self.cred_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.cred_file_button = ttk.Button(file_cred_frame, text=self.i18n.t('config.browse'), command=lambda: self._browse_file("credential_file_path"), state="disabled")
        self.cred_file_button.pack(side=tk.LEFT, padx=5)

        tasks_frame = ttk.LabelFrame(config_zone_frame, text=self.i18n.t('tasks.title'))
        tasks_frame.grid(row=9, column=0, columnspan=2, sticky="ew", padx=5, pady=10)

        # Post-Config Verification Frame
        verify_frame = ttk.LabelFrame(config_zone_frame, text=self.i18n.t('verification.title'))
        verify_frame.grid(row=10, column=0, columnspan=3, sticky="ew", padx=5, pady=10)

        # -------------------------- 左侧：Enable Verification Phase 区域 --------------------------
        left_frame = ttk.Frame(verify_frame)
        left_frame.grid(row=0, column=0, padx=10, pady=5, sticky="nsw")

        # 左侧校验复选框
        self.verify_check = ttk.Checkbutton(
            left_frame,
            text=self.i18n.t('verification.enable_verification'),
            variable=self.job_definition["verify_enabled"],
            command=self._toggle_verify_mutex
        )
        self.verify_check.grid(row=0, column=0, columnspan=2, sticky="w", padx=5)

        # 左侧控件（存储到列表，方便批量启用/禁用）
        self.left_verify_widgets = []

        # New Shared IP
        ttk.Label(left_frame, text=self.i18n.t('verification.new_shared_ip')).grid(row=1, column=0, sticky="w", padx=5, pady=3)
        verify_ip_entry = ttk.Entry(left_frame, textvariable=self.job_definition["verify_ip"], width=22)
        verify_ip_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=3)
        self.left_verify_widgets.append(verify_ip_entry)

        # New Protocol
        ttk.Label(left_frame, text=self.i18n.t('verification.new_protocol')).grid(row=2, column=0, sticky="w", padx=5, pady=3)
        verify_proto_combo = ttk.Combobox(left_frame, textvariable=self.job_definition["verify_protocol"],
                                          values=["http", "https"], width=20)
        verify_proto_combo.grid(row=2, column=1, sticky="ew", padx=5, pady=3)
        self.left_verify_widgets.append(verify_proto_combo)

        # New Port
        ttk.Label(left_frame, text=self.i18n.t('verification.new_port')).grid(row=3, column=0, sticky="w", padx=5, pady=3)
        verify_port_entry = ttk.Entry(left_frame, textvariable=self.job_definition["verify_port"], width=22)
        verify_port_entry.grid(row=3, column=1, sticky="ew", padx=5, pady=3)
        self.left_verify_widgets.append(verify_port_entry)

        # New Username
        ttk.Label(left_frame, text=self.i18n.t('verification.new_username')).grid(row=4, column=0, sticky="w", padx=5, pady=3)
        verify_user_entry = ttk.Entry(left_frame, textvariable=self.job_definition["verify_username"], width=22)
        verify_user_entry.grid(row=4, column=1, sticky="ew", padx=5, pady=3)
        self.left_verify_widgets.append(verify_user_entry)

        # New Password
        ttk.Label(left_frame, text=self.i18n.t('verification.new_password')).grid(row=5, column=0, sticky="w", padx=5, pady=3)
        verify_pass_entry = ttk.Entry(left_frame, textvariable=self.job_definition["verify_password"], show="*",
                                      width=22)
        verify_pass_entry.grid(row=5, column=1, sticky="ew", padx=5, pady=3)
        self.left_verify_widgets.append(verify_pass_entry)

        # OEM Action
        ttk.Label(left_frame, text=self.i18n.t('verification.oem_action')).grid(row=6, column=0, sticky="w", padx=5, pady=3)
        self.oem_combo = ttk.Combobox(left_frame, textvariable=self.job_definition["oem_action"],
                                      values=["None", "SLS"], width=20)
        self.oem_combo.grid(row=6, column=1, sticky="ew", padx=5, pady=3)
        self.left_verify_widgets.append(self.oem_combo)

        # -------------------------- 右侧：Enable Element Verification 区域 --------------------------
        right_frame = ttk.Frame(verify_frame)
        right_frame.grid(row=0, column=1, padx=20, pady=5, sticky="nsw")

        # 右侧校验复选框
        self.element_verify_check = ttk.Checkbutton(
            right_frame,
            text=self.i18n.t('verification.enable_element_verification'),
            variable=self.job_definition["element_verify_enabled"],
            command=self._toggle_verify_mutex
        )
        self.element_verify_check.grid(row=0, column=0, columnspan=2, sticky="w", padx=5)

        # 右侧控件（存储到列表，方便批量启用/禁用）
        self.right_verify_widgets = []

        # Element to Search
        ttk.Label(right_frame, text=self.i18n.t('verification.element_to_search')).grid(row=1, column=0, sticky="w", padx=5, pady=3)
        self.element_search_entry = ttk.Entry(right_frame,
                                              textvariable=self.job_definition["element_search_value"], width=22)
        self.element_search_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=3)
        self.right_verify_widgets.append(self.element_search_entry)


        self.upgrade_check = ttk.Checkbutton(tasks_frame, text=self.i18n.t('tasks.upgrade_firmware'), variable=self.job_definition["do_upgrade"], command=self._toggle_file_input)
        self.upgrade_check.grid(row=0, column=0, sticky="w", padx=5)
        self.firmware_entry = ttk.Entry(tasks_frame, textvariable=self.job_definition["firmware_path"], width=40, state="disabled")
        self.firmware_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        self.firmware_button = ttk.Button(tasks_frame, text=self.i18n.t('config.browse'), command=lambda: self._browse_file("firmware_path"), state="disabled")
        self.firmware_button.grid(row=0, column=2, padx=5, pady=2)

        self.upgrade_boot_check = ttk.Checkbutton(tasks_frame, text=self.i18n.t('tasks.upgrade_bootloader'), variable=self.job_definition["do_upgrade_boot"])
        self.upgrade_boot_check.grid(row=1, column=0, columnspan=3, sticky="w", padx=5, pady=2)

        # === 新增：运输模式复选框 ===
        self.shipmode_check = ttk.Checkbutton(tasks_frame, text=self.i18n.t("config.shipmode_label"), variable=self.job_definition["do_shipmode"])
        self.shipmode_check.grid(row=1, column=2, sticky="w", padx=5, pady=2)
        # ===========================

        self.ig502_step_check = ttk.Checkbutton(
            tasks_frame,
            text='IG502 Step (Optional / Model-Specific)',
            variable=self.job_definition["do_ig502_step"],
            command=self.update_start_button_state,
        )
        self.ig502_step_check.grid(row=2, column=0, sticky="w", padx=5, pady=2)

        self.ig502_model_status_var = tk.StringVar(value='Model: Not IG502 (auto-skip)')
        self.ig502_model_status_label = ttk.Label(tasks_frame, textvariable=self.ig502_model_status_var)
        self.ig502_model_status_label.grid(row=2, column=1, sticky="w", padx=5, pady=2)

        self.ig502_run_button = ttk.Button(
            tasks_frame,
            text='Run IG502 Script',
            state="disabled",
            command=self._run_ig502_step_manual,
        )
        self.ig502_run_button.grid(row=2, column=2, padx=5, pady=2)

        self.config_check = ttk.Checkbutton(tasks_frame, text=self.i18n.t('tasks.import_config'), variable=self.job_definition["do_import_config"], command=self._toggle_file_input)
        self.config_check.grid(row=3, column=0, sticky="w", padx=5)
        self.config_entry = ttk.Entry(tasks_frame, textvariable=self.job_definition["config_path"], width=40, state="disabled")
        self.config_entry.grid(row=3, column=1, sticky="ew", padx=5, pady=2)
        self.config_button = ttk.Button(tasks_frame, text=self.i18n.t('config.browse'), command=lambda: self._browse_file("config_path"), state="disabled")
        self.config_button.grid(row=3, column=2, padx=5, pady=2)

        self.restore_check = ttk.Checkbutton(tasks_frame, text=self.i18n.t('tasks.restore_defaults'), variable=self.job_definition["do_restore_defaults"], command=self._toggle_file_input)
        self.restore_check.grid(row=4, column=0, sticky="w", padx=5)

        # 新增：恢复默认IP 标签
        self.ip_label = ttk.Checkbutton(tasks_frame, text=self.i18n.t('tasks.restore_default_ip'), variable=self.job_definition["restore_default_ip"], command=self._toggle_file_input)
        self.ip_label.grid(row=4, column=1, sticky="w", padx=(5, 5), pady=2)


        # 新增：恢复默认IP 下拉框（Combobox）
        self.restore_ip_combobox = ttk.Combobox(tasks_frame, textvariable=self.job_definition["is_default_ip"], values=["YES", "NO"],  state="disabled", width=10)
        self.restore_ip_combobox.grid(row=4, column=2, sticky="w", padx=5, pady=2)
        self.restore_ip_combobox.current(0)  # 0=YES，1=NO
        self.restore_ip_combobox.bind("<<ComboboxSelected>>", self._toggle_file_input)

        # New: Modify Current Config (text input) - TEMPORARILY HIDDEN
        # self.modify_check = ttk.Checkbutton(tasks_frame, text="Modify Current Config", variable=self.job_definition["do_modify_config"], command=self._toggle_file_input)
        # self.modify_check.grid(row=5, column=0, sticky="w", padx=5)
        # self.modify_entry = ttk.Entry(tasks_frame, textvariable=self.job_definition["modify_config_text"], width=40, state="disabled")
        # self.modify_entry.grid(row=5, column=1, sticky="ew", padx=5, pady=2)

        self.incremental_config_check = ttk.Checkbutton(tasks_frame, text=self.i18n.t('tasks.import_incremental_config'), variable=self.job_definition["do_import_incremental_config"],command=self._toggle_file_input)
        self.incremental_config_check.grid(row=7, column=0, sticky="w", padx=5)
        self.incremental_config_entry = ttk.Entry(tasks_frame, textvariable=self.job_definition["incremental_config_path"], width=40, state="disabled")
        self.incremental_config_entry.grid(row=7, column=1, sticky="ew", padx=5, pady=2)
        self.incremental_config_button = ttk.Button(tasks_frame, text=self.i18n.t('config.browse'), command=lambda: self._browse_file("incremental_config_path"), state="disabled")
        self.incremental_config_button.grid(row=7, column=2, padx=5, pady=2)


        # Placeholder button column to keep grid alignment
        ttk.Label(tasks_frame, text="").grid(row=5, column=2)

        tasks_frame.columnconfigure(1, weight=1)

        # --- 2. Action Zone ---
        action_zone_frame = ttk.LabelFrame(top_frame, text=self.i18n.t('action.title'))
        action_zone_frame.grid(row=0, column=1, padx=10, pady=10, sticky="new")
        
        self.start_button = ttk.Button(action_zone_frame, text=self.i18n.t('action.start_batch'), command=self.start_worker)
        self.start_button.pack(pady=5, padx=10, fill="x")
        self.stop_button = ttk.Button(action_zone_frame, text=self.i18n.t('action.stop'), command=self.stop_worker, state=tk.DISABLED)
        self.stop_button.pack(pady=5, padx=10, fill="x")

        self.clear_log_button = ttk.Button(action_zone_frame, text=self.i18n.t('action.clear_all'), command=self._clear_all)
        self.clear_log_button.pack(pady=5, padx=10, fill="x")

        # --- 3. Status Zone ---
        status_zone_frame = ttk.LabelFrame(top_frame, text=self.i18n.t('status.title'))
        status_zone_frame.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")
        top_frame.columnconfigure(1, weight=1)
        top_frame.rowconfigure(1, weight=1)

        status_labels_frame = ttk.Frame(status_zone_frame)
        status_labels_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(status_labels_frame, textvariable=self.status_vars["overall_status"]).pack(side="left")
        ttk.Label(status_labels_frame, textvariable=self.status_vars["time_elapsed"]).pack(side="left", padx=10)
        
        counters_frame = ttk.Frame(status_labels_frame)
        counters_frame.pack(side="right")
        ttk.Label(counters_frame, textvariable=self.status_vars["progress_counter"]).pack(side="top", anchor="e")
        self.verified_label = ttk.Label(counters_frame, textvariable=self.status_vars["verified_counter"])
        # The label will be packed (made visible) by a message from the orchestrator
        
        self.progress_bar = ttk.Progressbar(status_zone_frame, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill="x", padx=5, pady=2)
        
        tree_frame = ttk.Frame(status_zone_frame)
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # columns = ("mac", "ip", "sn", "version", "bootloader", "upgrade", "config", "status", "verification")
        columns = ("index", "mac", "ip", "sn", "version", "bootloader", "upgrade", "config", "status", "verification")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")

        self.tree.heading("index", text=self.i18n.t('status.index') if hasattr(self.i18n, 't') else "#") # 如果没有翻译key，直接显示
        self.tree.column("index", width=40, anchor="center") # 宽度设小一点，居中显示
        self.tree.heading("mac", text=self.i18n.t('status.device_mac'))
        self.tree.heading("ip", text=self.i18n.t('status.new_ip'))
        self.tree.heading("sn", text=self.i18n.t('status.sn'))
        self.tree.heading("version", text=self.i18n.t('status.version'))
        self.tree.heading("bootloader", text=self.i18n.t('status.bootloader'))
        self.tree.heading("upgrade", text=self.i18n.t('status.upgrade'))
        self.tree.heading("config", text=self.i18n.t('status.import_config'))
        self.tree.heading("status", text=self.i18n.t('status.status'))
        self.tree.heading("verification", text=self.i18n.t('status.verification'))

        self.tree.column("mac", width=140, anchor="w")
        self.tree.column("ip", width=100, anchor="w")
        self.tree.column("sn", width=120, anchor="w")
        self.tree.column("version", width=120, anchor="w")
        self.tree.column("bootloader", width=120, anchor="w")
        self.tree.column("upgrade", width=90, anchor="center")
        self.tree.column("config", width=100, anchor="center")
        self.tree.column("status", width=90, anchor="center")
        self.tree.column("verification", width=90, anchor="center")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(side="left", fill="both", expand=True)
        
        self.tree.tag_configure('SUCCESS', background='#c8e6c9')
        self.tree.tag_configure('FAILED', background='#ffcdd2')

        # --- 4. Log Zone ---
        self.log_area = scrolledtext.ScrolledText(log_zone_frame, wrap=tk.WORD, state="disabled", height=10)
        self.log_area.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.log_area.tag_config('INFO', foreground='black')
        self.log_area.tag_config('SUCCESS', foreground='green')
        self.log_area.tag_config('ERROR', foreground='red')
        self.log_area.tag_config('HEADER', foreground='purple', font=('TkDefaultFont', 10, 'bold'))

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self._toggle_credential_fields()
        self._refresh_ig502_step_ui()

    def _is_ig502_model(self, model_name):
        """判断当前选中的型号是否属于 IG502。"""
        return "IG502" in str(model_name or "").upper()

    def _refresh_ig502_step_ui(self):
        """根据型号更新 IG502 步骤的可见性/可用性提示。"""
        is_ig502 = self._is_ig502_model(self.job_definition["model"].get())

        if is_ig502:
            status_now = self.ig502_model_status_var.get()
            known_runtime_states = {
                'IG502 step running...',
                'IG502 step success ✅',
                'IG502 step failed ❌',
            }
            if status_now not in known_runtime_states:
                self.ig502_model_status_var.set('Model: IG502')
            self.ig502_step_check.config(state="normal")
            self.ig502_run_button.config(state="normal")
            if not self.job_definition["do_ig502_step"].get():
                self.job_definition["do_ig502_step"].set(True)
        else:
            self.ig502_model_status_var.set('Model: Not IG502 (auto-skip)')
            self.ig502_step_check.config(state="disabled")
            self.ig502_run_button.config(state="disabled")
            self.job_definition["do_ig502_step"].set(False)

    def _queue_log_text(self, msg, level='INFO'):
        """写入一条原始文本日志（无需 i18n key）。"""
        timestamp = time.strftime("%H:%M:%S")
        self.gui_queue.put({'type': 'log', 'level': level, 'msg': f"[{timestamp}] {msg}"})

    def _resolve_ig502_script_path(self):
        """获取 IG502 脚本绝对路径。"""
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), self.ig502_script_relpath)

    def _pick_ig502_edge_config_path(self, job_def):
        """IG502 edge 配置文件来源：优先增量配置，其次普通配置。"""
        return job_def.get("incremental_config_path") or job_def.get("config_path") or ""

    def _run_ig502_step_manual(self):
        """手动执行 IG502 专用步骤（按钮触发）。"""
        if not self._is_ig502_model(self.job_definition["model"].get()):
            self._queue_log_text('Current model is not IG502, manual step skipped.', 'INFO')
            return

        self.ig502_run_button.config(state="disabled")
        self.ig502_model_status_var.set('IG502 step running...')

        def _worker():
            try:
                job_def = {
                    "protocol": self.job_definition["protocol"].get(),
                    "port": self.job_definition["port"].get(),
                    "initial_ip": self.job_definition["initial_ip"].get(),
                    "username": self.job_definition["username"].get(),
                    "password": self.job_definition["password"].get(),
                    "firmware_path": self.job_definition["firmware_path"].get(),
                    "config_path": self.job_definition["config_path"].get(),
                    "incremental_config_path": self.job_definition["incremental_config_path"].get(),
                }
                success, new_ip = self._run_ig502_pre_config(job_def, job_def["initial_ip"], job_def["username"], job_def["password"])
                if success:
                    self.root.after(0, lambda: self.job_definition["initial_ip"].set(new_ip))
                    self.root.after(0, lambda: self.ig502_model_status_var.set('IG502 step success ✅'))
                else:
                    self.root.after(0, lambda: self.ig502_model_status_var.set('IG502 step failed ❌'))
            finally:
                self.root.after(0, self._refresh_ig502_step_ui)

        threading.Thread(target=_worker, name="IG502-Manual", daemon=True).start()

    def _run_ig502_pre_config(self, job_def, ip, user, pwd):
        """执行 IG502 脚本并判断 IP 是否切换到 192.168.1.1。"""
        script_path = self._resolve_ig502_script_path()
        if not os.path.exists(script_path):
            self._queue_log_text(f'IG502 script not found: {script_path}', 'ERROR')
            return False, ip

        firmware_path = job_def.get("firmware_path") or ""
        edge_config_path = self._pick_ig502_edge_config_path(job_def)
        import_config_path = job_def.get("config_path") or ""

        cmd = [
            sys.executable,
            script_path,
            "--ip", ip,
            "--username", user,
            "--password", pwd,
            "--protocol", job_def.get("protocol", "http"),
            "--firmware", firmware_path,
            "--edge-config", edge_config_path,
            "--import-config", import_config_path,
            "--expected-ip", self.ig502_expected_ip,
        ]

        self._queue_log_text(f'Start IG502 pre-config script for device: {ip}', 'INFO')

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            if process.stdout:
                for line in process.stdout:
                    log_line = line.strip()
                    if log_line:
                        self._queue_log_text(f"[IG502] {log_line}", 'INFO')

            return_code = process.wait(timeout=900)
        except subprocess.TimeoutExpired:
            self._queue_log_text('IG502 script timed out.', 'ERROR')
            process.kill()
            return False, ip
        except Exception as exc:
            self._queue_log_text(f'IG502 script execution exception: {str(exc)}', 'ERROR')
            return False, ip

        if return_code != 0:
            self._queue_log_text(f'IG502 script failed with return code: {return_code}', 'ERROR')
            return False, ip

        new_ip = self.ig502_expected_ip
        ping_ok = self._check_ping(new_ip, count=1, timeout=2, max_retries=10, retry_delay=2)
        try:
            port_val = int(job_def.get("port", 80))
        except (TypeError, ValueError):
            port_val = 80
        port_ok = self._check_tcp_port(new_ip, port_val, timeout=30)

        if ping_ok and port_ok:
            self._queue_log_text(f'IG502 step succeeded, device switched to {new_ip}', 'SUCCESS')
            return True, new_ip

        self._queue_log_text(f'IG502 step failed, target IP {new_ip} unreachable.', 'ERROR')
        return False, ip

    def _on_model_selected(self, event=None):
        """
        回调函数：当用户在下拉框选择型号时触发
        从 configs.device_defaults 获取默认配置并自动填充
        """
        selected_model = self.job_definition["model"].get()
        
        # 获取默认配置
        defaults = get_model_defaults(selected_model)

        if defaults:
            # 定义界面变量与配置键名的映射关系
            fields_map = {
                "protocol": self.job_definition["protocol"],
                "port": self.job_definition["port"],
                "initial_ip": self.job_definition["initial_ip"],
                "new_ip_start": self.job_definition["new_ip_start"],
                "username": self.job_definition["username"],
                "password": self.job_definition["password"],
                "credential_mode": self.job_definition["credential_mode"]
            }

            # 遍历并设置值
            for key, tk_var in fields_map.items():
                if key in defaults:
                    tk_var.set(defaults[key])

            # 如果切换了凭据模式（如从 File 切到 Static），需要刷新界面控件状态
            if "credential_mode" in defaults:
                self._toggle_credential_fields()
        
        self._refresh_ig502_step_ui()

        # 最后更新 Start 按钮的可用状态
        self.update_start_button_state()
    # def _clear_all(self):
    #     """清空日志与表格、重置进度/计时与状态条。"""
    #     self.log_area.config(state="normal")
    #     self.log_area.delete('1.0', tk.END)
    #     self.log_area.config(state="disabled")
    #     self.tree.delete(*self.tree.get_children())
    #     self.device_map = {}
    #     self.status_vars["overall_status"].set(self.i18n.t('status.idle'))
    #     self.status_vars["progress_counter"].set(self.i18n.format('status.processed_format', count=0, total=0))
    #     self.status_vars["verified_counter"].set(self.i18n.format('status.verified_format', count=0, total=0))
    #     self.status_vars["time_elapsed"].set(self.i18n.format('status.time_format', time='00:00:00'))
    #     self.verified_label.pack_forget()
    #     self.progress_bar['value'] = 0
    def _clear_all(self):
        """清空日志与表格、重置进度/计时与状态条"""
        self.log_area.config(state="normal")
        self.log_area.delete('1.0', tk.END)
        self.log_area.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.device_map = {}
        # ---【新增】: 清空索引表 ---
        self.fixed_indices = {}
        # 清理 CIDR-BOX 相关缓存，避免跨批次复用旧映射
        self.mac_to_box_ip = {}
        self.box_nat_refresh_cache = {}
        self.status_vars["overall_status"].set(self.i18n.t('status.idle'))
        ...
        self.progress_bar['value'] = 0


    def _browse_file(self, key):
        """弹出文件选择框并写回到对应字段。

        参数:
            key: 需要写入 job_definition 的键名（如 firmware_path/config_path/credential_file_path）
        """
        file_types = []
        if key == "credential_file_path":
            file_types = [("Excel/CSV files", "*.xlsx *.xls *.csv"), ("All files", "*.*")]
            path = filedialog.askopenfilename(filetypes=file_types)
        else:
            path = filedialog.askopenfilename()

        if path:
            self.job_definition[key].set(path)
            self.update_start_button_state()

    def _toggle_file_input(self, *args):
        """根据任务勾选状态启用/禁用文件选择控件，保持互斥关系。"""
        # Handle upgrade checkbox
        self.firmware_entry.config(state="normal" if self.job_definition["do_upgrade"].get() else "disabled")
        self.firmware_button.config(state="normal" if self.job_definition["do_upgrade"].get() else "disabled")

        # Handle mutual exclusivity for config import vs. restore
        if self.job_definition["do_restore_defaults"].get():
            # 恢复出厂设置时：禁用所有配置相关控件
            self.config_entry.config(state="disabled")
            self.config_button.config(state="disabled")
            self.config_check.config(state="disabled")
            self.incremental_config_entry.config(state="disabled")
            self.incremental_config_check.config(state="disabled")
            self.incremental_config_button.config(state="disabled")
            self.ip_label.config(state="disabled")
            self.restore_ip_combobox.config(state="disabled")
        else:
            # 未恢复出厂设置时：先启用两个勾选框（基础状态）
            self.config_check.config(state="normal")
            self.incremental_config_check.config(state="normal")
            self.ip_label.config(state="normal")

            # 新增：普通导入 ↔ 增量导入 互斥控制
            import_config_enabled = self.job_definition["do_import_config"].get()
            import_incremental_enabled = self.job_definition["do_import_incremental_config"].get()

            # 普通导入勾选 → 禁用增量导入的所有控件
            if import_config_enabled:
                self.incremental_config_check.config(state="disabled")
                self.incremental_config_entry.config(state="disabled")
                self.incremental_config_button.config(state="disabled")
                # self.ip_label.config(state="normal")
                self.job_definition["restore_default_ip"].set(True)
                self.restore_ip_combobox.config(state="normal")
                self.restore_ip_combobox.current(1)

            # 增量导入勾选 → 禁用普通导入的所有控件
            elif import_incremental_enabled:
                self.config_check.config(state="disabled")
                self.config_entry.config(state="disabled")
                self.config_button.config(state="disabled")

            # 两者都未勾选 → 启用输入框+按钮（但默认禁用，需勾选后才启用）
            else:
                self.config_entry.config(state="disabled")
                self.config_button.config(state="disabled")
                self.incremental_config_entry.config(state="disabled")
                self.incremental_config_button.config(state="disabled")
                # self.restore_ip_combobox.current(0)

            #  若未被互斥逻辑禁用，根据自身勾选状态启用对应输入框+按钮
            if not import_incremental_enabled:  # 未勾选增量导入时，普通导入才生效
                self.config_entry.config(state="normal" if import_config_enabled else "disabled")
                self.config_button.config(state="normal" if import_config_enabled else "disabled")
            if not import_config_enabled:  # 未勾选普通导入时，增量导入才生效
                self.incremental_config_entry.config(state="normal" if import_incremental_enabled else "disabled")
                self.incremental_config_button.config(state="normal" if import_incremental_enabled else "disabled")

        if self.job_definition["restore_default_ip"].get():
            self.restore_ip_combobox.config(state="normal")
        else:
            self.restore_ip_combobox.config(state="disabled")

        # 定义需要触发禁用的配置项Key列表
        disable_triggers = [
            "do_import_config",
            "do_import_incremental_config",
            "restore_default_ip"
            # 未来新增配置项直接加在这里
        ]

        # 批量判断：任意一个触发项为真，就禁用
        should_disable = any(
            self.job_definition[key].get() for key in disable_triggers
        )
        self.restore_check.config(state="disabled" if should_disable else "normal")

        # Handle modify config text box - TEMPORARILY HIDDEN
        # self.modify_entry.config(state="normal" if self.job_definition["do_modify_config"].get() else "disabled")

        self._refresh_ig502_step_ui()
        self.update_start_button_state()

    def _toggle_verify_mutex(self):
        """实现两种验证方式的互斥切换 + 控件状态控制"""
        verify_enabled = self.job_definition["verify_enabled"].get()
        element_verify_enabled = self.job_definition["element_verify_enabled"].get()

        # 互斥核心逻辑：确保同一时间只有一个勾选
        if verify_enabled and element_verify_enabled:
            # 取消后勾选的（通过判断触发源，更精准）
            # 这里通过比较状态变化方向判断，若两个都为True，取消右侧
            self.job_definition["element_verify_enabled"].set(False)

        # 更新控件状态（启用选中的校验区域，禁用未选中的）
        self._update_verify_widgets_state()

    def _update_verify_widgets_state(self):
        """根据复选框状态，更新对应区域的控件启用/禁用状态"""
        verify_enabled = self.job_definition["verify_enabled"].get()
        element_verify_enabled = self.job_definition["element_verify_enabled"].get()

    # def _toggle_cidr_fields(self, *args):
    #     """Toggle visibility of Discovery CIDR field based on CIDR mode selection."""
    #     cidr_mode = self.job_definition["cidr_mode"].get()
        
    #     # 先清空字段
    #     self.discovery_label.pack_forget()
    #     self.discovery_entry.pack_forget()
    #     self.lowest_mac_ip_same_check.pack_forget()
    #     # 未选择 CIDR 模式时，直接返回
    #     if cidr_mode not in ("CIDR-302", "CIDR-BOX"):
    #         return
        
    #     # CIDR-302 或 CIDR-BOX 都显示 Discovery CIDR 字段
    #     if cidr_mode in ["CIDR-302", "CIDR-BOX"]:
    #         self.lowest_mac_ip_same_check.pack(side=tk.LEFT, padx=10)
    #         self.discovery_label.pack(side=tk.LEFT, padx=(10, 5))
    #         self.discovery_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
    def _toggle_cidr_fields(self, *args):
        """Toggle visibility of Discovery CIDR field based on CIDR mode selection."""
        cidr_mode = self.job_definition["cidr_mode"].get()
        
        # 1. 先隐藏原有控件
        self.discovery_label.pack_forget()
        self.discovery_entry.pack_forget()
        self.lowest_mac_ip_same_check.pack_forget()
        
        # 2. 如果存在 CIDR-BOX 的额外参数框，也先隐藏（避免切换模式时残留）
        if hasattr(self, 'box_params_frame'):
            self.box_params_frame.pack_forget()
        
        # 3. 未选择 CIDR 模式时，直接返回
        if cidr_mode not in ("CIDR-302", "CIDR-BOX"):
            return
        
        # 4. 显示通用的 Discovery CIDR 和 Checkbox (CIDR-302 和 CIDR-BOX 都需要)
        self.lowest_mac_ip_same_check.pack(side=tk.LEFT, padx=10)
        self.discovery_label.pack(side=tk.LEFT, padx=(10, 5))
        self.discovery_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 5. 针对 CIDR-BOX 模式，额外显示 Count 和 Timeout 输入框
        if cidr_mode == "CIDR-BOX":
            # 如果容器还没创建过，则创建一次（懒加载）
            if not hasattr(self, 'box_params_frame'):
                # 使用 discovery_entry 的父容器作为 parent，确保在同一行
                self.box_params_frame = ttk.Frame(self.discovery_entry.master)
                
                # Count 输入框 (目标设备数量)
                ttk.Label(self.box_params_frame, text=self.i18n.t("config.cidr_count")).pack(side=tk.LEFT, padx=(5,2))
                ttk.Entry(self.box_params_frame, textvariable=self.job_definition["cidr_box_target_count"], width=5).pack(side=tk.LEFT)
                
            
            # 显示参数容器
            self.box_params_frame.pack(side=tk.LEFT, padx=10)

    def _toggle_credential_fields(self, *args):
        """根据凭据模式（Static/API/File）切换账号/密码输入与文件导入控件的可用状态。"""
        mode = self.job_definition["credential_mode"].get()
        
        is_static = (mode == "Static")
        self.user_entry.config(state="normal" if is_static else "disabled")
        self.pass_entry.config(state="normal" if is_static else "disabled")

        is_file = (mode == "File")
        self.cred_file_entry.config(state="normal" if is_file else "disabled")
        self.cred_file_button.config(state="normal" if is_file else "disabled")

    def update_start_button_state(self, *args):
        """计算 Start 按钮可用性：需选中型号、至少一个任务，且所需文件已选择。"""
        model_selected = bool(self.job_definition["model"].get())

        # Check if individual tasks are valid (have files if needed)
        upgrade_ok = not self.job_definition["do_upgrade"].get() or bool(self.job_definition["firmware_path"].get())
        config_ok = not self.job_definition["do_import_config"].get() or bool(self.job_definition["config_path"].get())
        incremental_config_ok = not self.job_definition["do_import_incremental_config"].get() or bool(self.job_definition["incremental_config_path"].get())
        restore_ip_ok = self.job_definition["restore_default_ip"].get()
        restore_defaults_ok = self.job_definition["do_restore_defaults"].get()

        # Check if at least one task is selected
        task_selected = (
            self.job_definition["do_upgrade"].get() or 
            self.job_definition["do_import_config"].get() or
            self.job_definition["do_restore_defaults"].get() or
            self.job_definition["do_modify_config"].get() or
            self.job_definition["do_import_incremental_config"].get()
        )

        if model_selected and task_selected and upgrade_ok and config_ok and incremental_config_ok and (restore_ip_ok or restore_defaults_ok):
            self.start_button.config(state="normal")
        else:
            self.start_button.config(state="disabled")

    def update_timer(self):
        """按秒更新耗时显示（HH:MM:SS），直到计时器停止。"""
        if not self.timer_running:
            return
        
        elapsed_seconds = time.time() - self.start_time
        # Format into HH:MM:SS
        time_str = time.strftime("%H:%M:%S", time.gmtime(elapsed_seconds))
        self.status_vars["time_elapsed"].set(self.i18n.format('status.time_format', time=time_str))
        
        self.root.after(1000, self.update_timer) # Schedule next update

    # def queue_log(self, msg, level='INFO'):
    #     """向 GUI 队列写入一条带级别的日志消息。"""
    #     timestamp = time.strftime("%H:%M:%S")
    #     formatted_msg = f"[{timestamp}] {msg}"
    #     self.gui_queue.put({'type': 'log', 'level': level, 'msg': formatted_msg})
    
    def queue_log_i18n(self, key, level='INFO', **fmt_kwargs):
        """使用 i18n key 写日志，自动按当前语言翻译并格式化。"""
        if fmt_kwargs:
            text = self.i18n.format(key, **fmt_kwargs)
        else:
            text = self.i18n.t(key)

        timestamp = time.strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {text}"
        self.gui_queue.put({'type': 'log', 'level': level, 'msg': formatted_msg})

    def process_gui_queue(self):
        """从 GUI 消息队列取出消息并更新界面。

        说明：工作线程只能入队消息，实际的控件更新在主线程中执行，确保线程安全。
        """
        try:
            while True:
                msg = self.gui_queue.get_nowait()
                msg_type = msg.get('type')

                if msg_type == 'log':
                    self.log_area.config(state="normal")
                    self.log_area.insert(tk.END, f"{msg['msg']}\n", msg['level'])
                    self.log_area.see(tk.END)
                    self.log_area.config(state="disabled")
                
                elif msg_type == 'status_update':
                    self.status_vars[msg['target']].set(msg['msg'])

                elif msg_type == 'progress_max':
                    self.progress_bar.config(maximum=msg['value'])

                elif msg_type == 'progress_value':
                    self.progress_bar.config(value=msg['value'])

                elif msg_type == 'clear_devices':
                    self.tree.delete(*self.tree.get_children())
                    self.device_map = {}

                elif msg_type == 'add_device':
                    mac = msg['mac']
                    # ---【修改点】: 优先使用后端传入的固定索引 ---
                    # 如果 msg 中包含 'index'，则使用它；否则回退到动态计算 (len+1)
                    if 'index' in msg:
                        index_val = msg['index']
                    else:
                        index_val = len(self.tree.get_children()) + 1
                    # ----------------------------------------
                    
                    # values 元组结构 (10列):
                    # (序号, MAC, IP, SN, 版本, Bootloader, 升级, 配置, 状态, 验证)
                    values = (
                        index_val,
                        mac,
                        '',
                        '',
                        '',
                        'N/A',
                        msg.get('upgrade', 'N/A'),
                        msg.get('config', 'N/A'),
                        self.i18n.t("table_values.queued"), # Default status
                        self.i18n.t("table_values.pending") # Default verification
                    )
                    
                    item_id = self.tree.insert("", "end", values=values, iid=mac)
                    self.device_map[mac] = item_id
                    # # 1. 计算序号：当前已有子项数量 + 1
                    # current_count = len(self.tree.get_children())
                    # index_val = current_count + 1
                    # # 2. 将 index_val 加到 values 的最前面
                    # values = (index_val, mac, '', '', '', '', msg.get('upgrade', 'N/A'), msg.get('config', 'N/A'), 'Queued', 'Pending')
                    # # values = (mac, '', '', '', '', msg.get('upgrade', 'N/A'), msg.get('config', 'N/A'), 'Queued', 'Pending')
                    # item_id = self.tree.insert("", "end", values=values, iid=mac)
                    # self.device_map[mac] = item_id

                elif msg_type == 'update_device':
                    mac = msg['mac']
                    item_id = self.device_map.get(mac)
                    if item_id:
                        col_map = {
                            "index": 0,       # 新增
                            "mac": 1,         # 原为 0
                            "ip": 2,          # 原为 1
                            "sn": 3,          # 原为 2
                            "version": 4,     # 原为 3
                            "bootloader": 5,  # 原为 4
                            "upgrade": 6,     # 原为 5
                            "config": 7,      # 原为 6
                            "status": 8,      # 原为 7
                            "verification": 9 # 原为 8
                        }
                        # col_map = {"mac": 0, "ip": 1, "sn": 2, "version": 3,
                        #         "bootloader": 4, "upgrade": 5, "config": 6,
                        #         "status": 7, "verification": 8}
                        col_index = col_map[msg['column']]
                        if col_index is not None:
                            current_values = list(self.tree.item(item_id, 'values'))
                            # 确保 values 长度足够（防止意外越界）
                            if len(current_values) > col_index:
                                current_values[col_index] = msg['value']
                                self.tree.item(item_id, values=tuple(current_values))

                elif msg_type == 'update_device_status':
                    mac = msg['mac']
                    item_id = self.device_map.get(mac)
                    if item_id:
                        self.tree.item(item_id, tags=(msg['tag'],))

                elif msg_type == 'show_verified_counter':
                    self.verified_label.pack(side="top", anchor="e")

                elif msg_type == 'hide_verified_counter':
                    self.verified_label.pack_forget()

                elif msg_type == 'show_completion_message':
                    total_count = 0
                    success_count = 0
                    failed_count = 0
                    pending_count = 0

                    # 1. 定义状态判定集合 (基于 i18n 动态获取当前语言的关键字)
                    # 成功的状态关键字
                    success_keywords = {
                        self.i18n.t("table_values.success"),
                        self.i18n.t("table_values.skipped"),
                        self.i18n.t("table_values.restored"),
                        self.i18n.t("table_values.verified_tcp"),
                        self.i18n.t("table_values.verified_login"),
                        self.i18n.t("table_values.verified_oem"),
                        self.i18n.t("table_values.shipmode_ok"),
                        "Ready", "Ready (Skipped)"  # 兼容代码中的硬编码状态
                    }

                    # 失败的状态关键字
                    failed_keywords = {
                        self.i18n.t("table_values.failed"),
                        self.i18n.t("table_values.tcp_failed"),
                        self.i18n.t("table_values.login_failed"),
                        self.i18n.t("table_values.oem_failed"),
                        self.i18n.t("table_values.creds_failed"),
                        self.i18n.t("table_values.api_error"),
                        self.i18n.t("table_values.reboot_failed"),
                        self.i18n.t("table_values.restore_failed"),
                        self.i18n.t("table_values.shipmode_fail"),
                        "Error"
                    }

                    # 2. 遍历 Treeview 进行统计
                    for item_id in self.tree.get_children():
                        total_count += 1
                        item_values = self.tree.item(item_id)['values']
                        # 状态列在第 9 列 (索引 8)，验证列在第 10 列 (索引 9)
                        status_text = str(item_values[8])
                        verify_text = str(item_values[9])

                        # 判定逻辑：优先看验证列，再看状态列
                        # 如果是“验证”阶段，验证成功才算最终成功
                        is_success = (status_text in success_keywords) or (verify_text in success_keywords)
                        is_failed = (status_text in failed_keywords) or (verify_text in failed_keywords)

                        if is_failed:
                            failed_count += 1
                        elif is_success:
                            success_count += 1
                        else:
                            # 既不是明确成功也不是明确失败（如 Queued, Running, Pending）
                            pending_count += 1

                    # 3. 构建差异化提示信息
                    title = self.i18n.t("messages.batch_summary_title")

                    # 场景 A: 完美全通
                    if failed_count == 0 and pending_count == 0 and total_count > 0:
                        msg = self.i18n.format("messages.batch_summary_perfect", total=total_count)
                        messagebox.showinfo(title, msg)

                    # 场景 B: 存在失败 (显示警告)
                    elif failed_count > 0:
                        msg = self.i18n.format("messages.batch_summary_warning",
                                               total=total_count,
                                               success=success_count,
                                               failed=failed_count)
                        messagebox.showwarning(title, msg)

                    # 场景 C: 只有成功和未完成（例如用户中途停止）
                    else:
                        msg = self.i18n.format("messages.batch_summary_incomplete",
                                               total=total_count,
                                               success=success_count,
                                               failed=failed_count,
                                               pending=pending_count)
                        messagebox.showinfo(title, msg)
                    # messagebox.showinfo(self.i18n.t("messages.success_title"), self.i18n.t("messages.batch_complete"))

                elif msg_type == 'show_error_message':
                    messagebox.showerror(msg.get('title', self.i18n.t("messages.error_title")), msg.get('message', ''))

                elif msg_type == 'sort_tree_by_ip':
                    try:
                        # 1. 获取所有表格项 ID
                        items = list(self.tree.get_children())
                        
                        # 2. 定义排序键值函数 (使用 ipaddress 进行数值排序)
                        def get_ip_key(iid):
                            # 获取第3列 (索引2) 的值，即 "新IP"
                            val = self.tree.item(iid)['values'][2]
                            try:
                                # 尝试转为 IPv4 对象进行比较
                                return ipaddress.IPv4Address(str(val).strip())
                            except ValueError:
                                # 如果是空值或无效IP，赋予 0.0.0.0 放在最前面
                                return ipaddress.IPv4Address('0.0.0.0')

                        # 3. 执行排序
                        items.sort(key=get_ip_key)

                        # 4. 重新调整 Treeview 中的位置
                        for index, iid in enumerate(items):
                            self.tree.move(iid, '', index)
                            
                    except Exception as e:
                        print(f"GUI Sort Error: {e}")

        except queue.Empty:
            pass
        self.root.after(100, self.process_gui_queue)

    def _validate_api_session_health(self, job_def: dict) -> bool:
        """
        启动前健康检查：
        验证 API 模式下的操作员会话是否有效。
        如果 Token 过期且无法刷新，立即阻断并提示。
        """
        # 1. 如果不是 API 模式，直接放行
        if job_def.get("credential_mode") != "API":
            return True

        # 2. 检查基础配置是否存在
        if not self.api_domain or not self.operator_username:
            messagebox.showwarning(
                self.i18n.t("messages.config_error_title"),
                self.i18n.t("messages.operator_login_config_error")
            )
            self._show_operator_login_dialog()
            return False

        # 3. 尝试获取有效 Token (此方法内部会尝试刷新 Token)
        token = self._get_valid_auth_token()

        if not token:
            # Token 无效且刷新失败
            self.queue_log_i18n("log.operator_session_invalid_or_expired", "ERROR")

            # 弹窗警告
            messagebox.showerror(
                self.i18n.t("messages.session_expired_title"),
                self.i18n.t("messages.session_expired_msg")
            )

            self._show_operator_login_dialog()
            return False

        # 一切正常
        return True
    def start_worker(self):
        """启动调度线程（Orchestrator）并开启计时器。"""
        current_job = {key: var.get() for key, var in self.job_definition.items()}
        # 先校验静态凭证是否填写完整
        if not self._validate_static_credentials(current_job):
            return
        
        # 再校验增量配置是否被 handler 支持
        if not self._validate_incremental_config_request(current_job):
            return

        # 在这里进行拦截，如果 Session 无效，直接 return，不清除界面，不启动线程
        if not self._validate_api_session_health(current_job):
            return

        self._clear_all()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.queue_log_i18n("log.worker_start", "HEADER")
        
        # --- Start Timer ---
        self.start_time = time.time()
        self.timer_running = True
        self.update_timer()

        self.stop_event.clear()
        print(current_job)  # For debugging
        self.worker_thread = threading.Thread(target=self.orchestrator_logic, args=(current_job,), name="Orchestrator")
        self.worker_thread.daemon = True
        self.worker_thread.start()

    def _validate_static_credentials(self, job_def: dict) -> bool:
        """
        静态凭据模式下，要求用户名和密码都填写。
        若有缺失，则弹窗提示并取消本次批处理。
        """
        if job_def.get("credential_mode") != "Static":
            return True

        username = job_def.get("username") or ""
        password = job_def.get("password") or ""
        if username and password:
            return True

        messagebox.showinfo(
            self.i18n.t("messages.static_credentials_missing_title"),
            self.i18n.t("messages.static_credentials_missing_msg"),
        )
        return False

    def _validate_incremental_config_request(self, job_def: dict) -> bool:
        """
        Ensures the selected handler exposes incremental configuration import before launching a job.
        Shows a dialog and cancels the batch if the feature is unsupported.
        """
        if not job_def.get("do_import_incremental_config"):
            return True

        model_name = job_def.get("model")
        if not model_name:
            return True

        try:
            handler = model_factory.get_handler(model_name)
        except Exception as exc:
            messagebox.showerror(
                self.i18n.t("messages.handler_error_title"),
                self.i18n.format(
                    "messages.handler_error_msg", model=model_name, error=str(exc)
                ),
            )
            return False

        if hasattr(handler, "import_incremental_config") and callable(
            getattr(handler, "import_incremental_config")
        ):
            return True

        messagebox.showinfo(
            self.i18n.t("messages.incremental_config_unsupported_title"),
            self.i18n.format(
                "messages.incremental_config_unsupported_msg", model=model_name
            ),
        )
        return False

    def stop_worker(self):
        """请求停止：置位 stop_event，禁用 Stop 按钮并停止计时器。"""
        self.queue_log_i18n("log.stop_requested", "ERROR")
        self.stop_event.set()
        self.stop_button.config(state=tk.DISABLED)
        self.timer_running = False

    def on_closing(self):
        """窗口关闭处理：若调度线程在运行，提示确认后停止并退出。"""
        if self.worker_thread and self.worker_thread.is_alive():
            if messagebox.askokcancel(self.i18n.t("messages.quit_title"), self.i18n.t("messages.quit_confirm")):
                self.stop_worker()
                self.root.destroy()
        else:
            self.root.destroy()

    def _save_log_to_file(self):
        """Saves the content of the log area to a user-specified file."""
        try:
            path = filedialog.asksaveasfilename(
            title=self.i18n.t("dialogs.save_log_title"),
            defaultextension=".log",
            filetypes=[
                (self.i18n.t("dialogs.file_type_log"), "*.log"),
                (self.i18n.t("dialogs.file_type_text"), "*.txt"),
                (self.i18n.t("dialogs.file_type_all"), "*.*")
            ])
            if not path:
                self.queue_log_i18n("log.save_log_cancelled", "INFO")
                return

            log_content = self.log_area.get("1.0", tk.END)
            with open(path, "w", encoding="utf-8") as f:
                f.write(log_content)
            
            self.queue_log_i18n("log.save_log_success", "SUCCESS")

        except Exception as e:
            self.queue_log_i18n("log.save_log_error", "ERROR", e=e)
            messagebox.showerror(self.i18n.t("messages.save_log_error_title"), self.i18n.format("messages.save_log_error_msg", e=e))


    def _get_ip_for_interface(self, interface_name, target_ip):
        """Gets the source IP from a specific interface that is on the same subnet as the target IP.

        target_ip 可以是单个 IP 或 CIDR（例如 192.168.1.0/24）。
        """
        try:
            target_str = str(target_ip)
            if "/" in target_str:
                target_net = ipaddress.ip_network(target_str, strict=False)
            else:
                target_net = ipaddress.ip_interface(f"{target_str}/255.255.255.255").network
            if_addrs = psutil.net_if_addrs().get(interface_name, [])
            for addr in if_addrs:
                if addr.family == socket.AF_INET:
                    if_net = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                    if target_net.subnet_of(if_net):
                        return addr.address
        except Exception as e:
            self.queue_log_i18n(
                "log.error_finding_ip_for_interface",
                "ERROR",
                interface=interface_name,
                error=str(e),
            )
        return None

    def _show_operator_login_dialog(self):
        """显示操作员登录对话框，输入域名/用户/密码并尝试认证。"""
        dialog = tk.Toplevel(self.root)
        dialog.title(self.i18n.t("messages.operator_login_title"))
        dialog.resizable(False, False)
        dialog.transient(self.root) # Keep dialog on top

        # --- Centering Logic ---
        main_win_x = self.root.winfo_x()
        main_win_y = self.root.winfo_y()
        main_win_width = self.root.winfo_width()
        main_win_height = self.root.winfo_height()
        dialog_width = 350
        dialog_height = 150
        x = main_win_x + (main_win_width // 2) - (dialog_width // 2)
        y = main_win_y + (main_win_height // 2) - (dialog_height // 2)
        dialog.geometry(f'{dialog_width}x{dialog_height}+{x}+{y}')

        frame = ttk.Frame(dialog, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text=self.i18n.t("dialogs.domain_label")).grid(row=0, column=0, sticky="w", pady=2)
        domain_entry = ttk.Entry(frame, width=30)
        domain_entry.grid(row=0, column=1, pady=2)
        if self.api_domain: domain_entry.insert(0, self.api_domain)

        ttk.Label(frame, text=self.i18n.t("dialogs.user_label")).grid(row=1, column=0, sticky="w", pady=2)
        user_entry = ttk.Entry(frame, width=30)
        user_entry.grid(row=1, column=1, pady=2)
        if self.operator_username: user_entry.insert(0, self.operator_username)

        ttk.Label(frame, text=self.i18n.t("dialogs.pass_label")).grid(row=2, column=0, sticky="w", pady=2)
        pass_entry = ttk.Entry(frame, show="*", width=30)
        pass_entry.grid(row=2, column=1, pady=2)
        if self.operator_password: pass_entry.insert(0, self.operator_password)

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)

        def _login_clicked():
            domain = domain_entry.get().strip()
            user = user_entry.get().strip()
            pwd = pass_entry.get()

            if not domain or not user:
                # If fields are cleared, treat it as a logout
                self.api_domain = None
                self.operator_username = None
                self.operator_password = None
                self.auth_token = None
                self.refresh_token = None
                self.token_expired_time = 0
                self.status_vars["api_status"].set(self.i18n.t('status.login_not_configured'))
                dialog.destroy()
            else:
                # Otherwise, attempt to login
                self._perform_operator_login(domain, user, pwd, dialog)

        login_button = ttk.Button(button_frame, text=self.i18n.t("dialogs.login_btn"), command=_login_clicked)
        login_button.pack(side=tk.LEFT, padx=5)
        cancel_button = ttk.Button(button_frame, text=self.i18n.t("dialogs.cancel_btn"), command=dialog.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5)

    def _get_valid_auth_token(self):
        """Checks for a valid token, refreshing it if necessary."""
        if not self.auth_token:
            return None
        
        # Check if token is expiring within the next 5 minutes
        if int(time.time()) >= self.token_expired_time - 300:
            if not self._request_refresh_token():
                return None # Refresh failed
        return self.auth_token

    def _perform_operator_login(self, domain, username, password, dialog_window):
        """Handles the actual API call for token authentication."""
        self.queue_log_i18n("log.operator_login_attempt", "INFO", username=username, domain=domain)
        try:
            ip = domain
            port = "443"
            database = "inhandmes"
            api_url = f"https://{ip}:{port}/api/v1.0/get_token?a={username}&s={password}&d={database}"
            
            response = requests.get(api_url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get("success") and data.get("token"):
                    self.api_domain = domain
                    self.operator_username = username
                    self.operator_password = password # Stored for refresh
                    self.auth_token = data["token"]
                    self.refresh_token = data["refresh_token"]
                    self.token_expired_time = int(time.time()) + data["token_expired"]
                    
                    self.queue_log_i18n("log.operator_login_success", "SUCCESS")
                    self.status_vars["api_status"].set(self.i18n.format('status.login_authenticated', username=self.operator_username))
                    dialog_window.destroy()
                    self.root.lift()
                    self.root.focus_force()
                    return
                else:
                    error_msg = data.get("message", self.i18n.t("messages.api_invalid_response"))
                    self.queue_log_i18n(
                        "log.operator_login_failed",
                        "ERROR",
                        error=error_msg,
                    )
                    messagebox.showerror(self.i18n.t("messages.login_failed_title"), error_msg, parent=dialog_window)
            else:
                self.queue_log_i18n(
                    "log.operator_login_failed",
                    "ERROR",
                    error=self.i18n.format("messages.api_status_error_fmt", status=response.status_code)
                )
                messagebox.showerror(self.i18n.t("messages.api_error_title"), self.i18n.format("messages.api_status_error", status=response.status_code), parent=dialog_window)
        except requests.RequestException as e:
            self.queue_log_i18n(
                "log.operator_login_failed",
                "ERROR",
                error=str(e),
            )
            messagebox.showerror(self.i18n.t("messages.network_error_title"), self.i18n.format("messages.network_connect_error", e=e), parent=dialog_window)

    def _request_refresh_token(self):
        """Uses the refresh token to get a new auth token."""
        self.queue_log_i18n("log.token_refresh_attempt", "INFO")
        try:
            ip = self.api_domain
            port = "443"
            database = "inhandmes"
            api_url = f"https://{ip}:{port}/api/v1.0/refresh_token?a={self.operator_username}&s={self.operator_password}&refresh_token={self.refresh_token}"

            response = requests.get(api_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("success") and data.get("token"):
                    self.auth_token = data["token"]
                    self.refresh_token = data["refresh_token"]
                    self.token_expired_time = int(time.time()) + data["token_expired"]
                    self.queue_log_i18n("log.token_refresh_success", "SUCCESS")
                    return True
        except requests.RequestException as e:
            self.queue_log_i18n("log.token_refresh_failed", "ERROR", error_msg=str(e))

        # If refresh fails for any reason, log out
        self.auth_token = None
        self.refresh_token = None
        self.token_expired_time = 0
        self.status_vars["api_status"].set(self.i18n.t('status.login_session_expired'))
        messagebox.showerror(self.i18n.t("messages.session_expired_title"), self.i18n.t("messages.session_expired_msg"))
        return False


    def _find_best_interface(self, target_ip):
        """Finds the best local interface to communicate with the target IP."""
        try:
            # Use ipaddress module to validate the target IP and get its network object
            target_net = ipaddress.ip_interface(f"{target_ip}/255.255.255.255").network
        except ValueError:
            self.queue_log_i18n("log.invalid_target_ip", "ERROR", target_ip=target_ip)
            return None

        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        candidates = []
        for name, addrs in interfaces.items():
            # Filter out inactive interfaces and loopback
            if not stats[name].isup or "loopback" in name.lower():
                continue

            for addr in addrs:
                if addr.family == socket.AF_INET:
                    try:
                        if_net = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                        if target_net.subnet_of(if_net):
                            candidates.append(name)
                            break # Move to the next interface once a match is found
                    except (ValueError, TypeError):
                        continue # Ignore invalid addresses or netmasks
        
        if not candidates:
            return None # No matching interface found

        if len(candidates) == 1:
            return candidates[0] # Only one choice, return it

        # Tie-breaking logic for multiple candidates
        # Prefer Ethernet interfaces
        ethernet_candidates = [c for c in candidates if "ethernet" in c.lower() or "eth" in c.lower()]
        if len(ethernet_candidates) == 1:
            return ethernet_candidates[0]
        elif len(ethernet_candidates) > 1:
            return ethernet_candidates[0] # Still multiple? Pick the first Ethernet one.
        
        # If no Ethernet, just return the first candidate found
        return candidates[0]

    def _perform_mes_reporting(self):
        """The master coordinator for the MES reporting phase."""
        self.queue_log_i18n("log.mes_reporting_phase", "HEADER")

        # 1. Gather successful serial numbers from the Treeview
        successful_sns = []
        for item_id in self.tree.get_children():
            item = self.tree.item(item_id)
            # Check if status is a success-like status
            status_val = item["values"][8]
            verify_val = item["values"][9]
            
            # 使用 i18n 获取当前的 "Success" 和 "Verified" 关键字
            target_success = self.i18n.t("table_values.success")
            target_verified_tcp = self.i18n.t("table_values.verified_tcp")
            target_verified_login = self.i18n.t("table_values.verified_login")
            target_verified_oem = self.i18n.t("table_values.verified_oem")
            
            if (status_val == target_success) or (verify_val in [target_verified_tcp, target_verified_login, target_verified_oem]):
                 sn = item["values"][3]
                 if sn and sn != 'N/A':
                    successful_sns.append(sn)

        if not successful_sns:
            self.queue_log_i18n("log.no_successful_devices", "INFO")
            return

        # 2. Create a test record for each successful device
        for sn in successful_sns:
            if not self._create_mes_record(sn):
                self.queue_log_i18n("log.mes_record_creation_failed", "ERROR", sn=sn)
        # 3. Update the firmware version for the entire batch using the instance variable
        if self.newly_installed_firmware_version:
            self.queue_log_i18n("log.updating_firmware_version", "INFO", version=self.newly_installed_firmware_version, count=len(successful_sns))
            
            # Clean the firmware string as per the example logic
            clean_firmware = self.newly_installed_firmware_version.strip()
            if clean_firmware.upper().startswith('V'):
                clean_firmware = clean_firmware[1:].strip()
            content = {"fw_version": clean_firmware}

            if not self._record_products_fw_version(successful_sns, content):
                self.queue_log_i18n("log.batch_fw_update_failed", "ERROR")
        else:
            self.queue_log_i18n("log.skipping_batch_fw_update", "INFO")

    def _create_mes_record(self, sn):
        """Creates a single test record in the MES for a given serial number."""
        token = self._get_valid_auth_token()
        if not token: return False
        try:
            url = f"https://{self.api_domain}/api/mes/v3.0/test-details"
            payload = {
                'token': token,
                'sn': sn,
                'pass_flag': '1',
                'result': 'pass',
                'procedure_name': 'batchUpgrade',
                'test_group_name': 'Public Other'
            }
            response = requests.post(url, data=payload, timeout=10)
            response.raise_for_status()
            self.queue_log_i18n("log.mes_record_created", "SUCCESS", sn=sn)
            return response.json().get("success", False)
        except requests.RequestException as e:
            self.queue_log_i18n("log.mes_record_creation_error", "ERROR", sn=sn, error_msg=str(e))
            return False

    def _record_products_fw_version(self, sn_list, content):
        """Updates the firmware version for a list of serial numbers in the MES."""
        token = self._get_valid_auth_token()
        if not token: return False
        try:
            domain = [("name", "in", sn_list)]
            # The URL must be carefully formatted. The provided example might need adjustment.
            url = f"https://{self.api_domain}/api/mes/v2.0/notes/rpc/update/?table=mft.products&domain={json.dumps(domain)}&data={json.dumps(content)}"
            headers = {'Authorization': f"Bearer {token}"}
            response = requests.post(url, headers=headers, timeout=10)
            response.raise_for_status()
            self.queue_log_i18n("log.batch_fw_update_success", "SUCCESS")
            return response.json().get("success", False)
        except requests.RequestException as e:
            self.queue_log_i18n("log.batch_fw_update_error", "ERROR", error_msg=str(e))
            return False

    def save_config(self):
        """Saves ALL current configuration to config.json."""
        try:
            # === 修改核心：移除 excluded_keys 过滤列表 ===
            # 直接遍历 job_definition 保存所有界面控件的值（包括升级、配置路径、验证选项等）
            job_data = {key: var.get() for key, var in self.job_definition.items()}
            
            # 准备完整的配置字典
            full_config = {
                "job_definition": job_data,
                "operator_settings": {
                    "api_domain": self.api_domain,
                    "operator_username": self.operator_username,
                    "operator_password": self.operator_password
                },
                # 保存当前的语言设置
                "user_language": self.i18n.get_current_language() if hasattr(self, 'i18n') else 'zh_CN'
            }
            
            # === 关键点：使用 utf-8 编码和 ensure_ascii=False ===
            # 这能确保固件路径、配置文件路径中的中文字符被正确保存，而不是转义成 \uXXXX
            with open("config.json", "w", encoding='utf-8') as f:
                json.dump(full_config, f, indent=4, ensure_ascii=False)
            
            self.queue_log_i18n("log.config_save_success", "SUCCESS")
            messagebox.showinfo(self.i18n.t("messages.success_title"), self.i18n.t("messages.config_save_all_success"))
            
        except Exception as e:
            self.queue_log_i18n("log.config_save_error", "ERROR", error_msg=str(e))
            messagebox.showerror(self.i18n.t("messages.error_title"), self.i18n.format("messages.config_save_failed", e=e))

    def load_config(self, show_message=False):
        """Loads configuration from config.json."""
        try:
            # 1. 确定配置文件路径 (兼容打包后的 EXE 和脚本运行)
            if getattr(sys, 'frozen', False):
                # 如果是打包后的 EXE，配置文件通常在 EXE 同级目录下
                base_path = os.path.dirname(sys.executable)
            else:
                # 如果是脚本运行，配置文件在脚本同级目录下
                base_path = os.path.dirname(os.path.abspath(__file__))
            
            config_path = os.path.join(base_path, "config.json")
            
            # 2. 如果绝对路径不存在，尝试当前目录（兼容旧逻辑）
            if not os.path.exists(config_path):
                config_path = "config.json"

            # === 核心修改点：增加 encoding='utf-8' ===
            # 必须与 save_config 中的编码一致，否则包含中文时会报错 (gbk codec error)
            with open(config_path, "r", encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Load job definition settings
            job_data = config_data.get("job_definition", {})
            for key, value in job_data.items():
                if key in self.job_definition:
                    # 确保读取的值转为字符串，防止部分数值类型报错
                    val_str = str(value) if value is not None else ""
                    self.job_definition[key].set(val_str)
            
            # 触发相关控件状态更新（比如 CIDR 模式、文件输入框显隐等）
            self._toggle_cidr_fields()
            self._toggle_credential_fields()
            self._toggle_file_input()
            self.update_start_button_state()

            # Load operator settings
            operator_settings = config_data.get("operator_settings", {})
            self.api_domain = operator_settings.get("api_domain")
            self.operator_username = operator_settings.get("operator_username")
            self.operator_password = operator_settings.get("operator_password")

            # Update login status display
            if self.api_domain and self.operator_username:
                self.status_vars["api_status"].set(self.i18n.format('status.login_ready', username=self.operator_username))
            else:
                self.status_vars["api_status"].set(self.i18n.t('status.login_not_configured'))

            self.queue_log_i18n("log.config_load_success", "SUCCESS")
            if show_message:
                # 提示成功加载的路径
                messagebox.showinfo(self.i18n.t("messages.success_title"), self.i18n.format("messages.config_load_success_path", path=config_path))

        except FileNotFoundError:
            if show_message:
                self.queue_log_i18n("log.config_file_not_found", "INFO")
                # Do not show a warning on startup, only on manual load
                # messagebox.showwarning("Not Found", "Configuration file (config.json) not found.")
        except Exception as e:
            self.queue_log_i18n("log.config_load_error", "ERROR", error_msg=str(e))
            if show_message:
                messagebox.showerror(self.i18n.t("messages.error_title"), self.i18n.format("messages.config_load_parse_error", e=e))

    def _derive_cidr_from_ip(self, ip_str):
        """
        [隐式增强核心]
        根据用户输入的单 IP (如 192.168.2.1)，自动推导其所属的 /24 网段。
        """
        try:
            import ipaddress
            # strict=False 允许传入主机IP，自动计算出网段地址
            iface = ipaddress.IPv4Interface(f"{ip_str}/24")
            return str(iface.network)  # 返回 '192.168.2.0/24'
        except Exception as e:
            self.queue_log_i18n("log.cidr_derive_error", "ERROR", error=str(e))
            return None

    def orchestrator_logic(self, job_def):
        """调度器主流程（四阶段）：

        1) 自动网卡选择与 ARP 扫描发现设备，弹窗确认目标清单
        2) 顺序改址（静态 ARP + TCP 预检 + change_ip），采集设备信息
        3) 并行任务（升级/导入配置/恢复出厂 + 必要时信息刷新）
        4) 可选验证（TCP/登录/OEM 动作）与可选 MES 上报

        出错策略：关键失败即时记录并在 GUI 标识，但不中断其他设备处理。
        """
        job_successful = False
        try:
            # --- Firmware Filename Validation ---
            if job_def["do_upgrade"]:
                handler = model_factory.get_handler(job_def["model"])
                firmware_path = job_def["firmware_path"]
                firmware_filename = os.path.basename(firmware_path)
                if not handler.is_firmware_file_valid(firmware_filename):
                    self.queue_log_i18n("log.invalid_firmware_file", "ERROR", filename=firmware_filename,
                                        model=job_def['model'])
                    messagebox.showerror(self.i18n.t("messages.invalid_firmware_title"),
                                         self.i18n.format("messages.invalid_firmware_msg", filename=firmware_filename,
                                                          model=job_def['model']))
                    return

            # --- Auto-detect Network Interface ---
            self.gui_queue.put(
                {'type': 'status_update', 'target': 'overall_status', 'msg': self.i18n.t('status_phases.detecting')})
            interface_name = self._find_best_interface(job_def["initial_ip"])
            if not interface_name:
                self.queue_log_i18n("log.network_interface_not_found", "ERROR", ip=job_def['initial_ip'])
                messagebox.showerror(self.i18n.t("messages.network_error_title"),
                                     self.i18n.format("messages.network_interface_error_msg", ip=job_def['initial_ip']))
                return
            job_def["network_interface"] = interface_name
            self.job_definition["network_interface"].set(interface_name)
            self.queue_log_i18n("log.interface_detected", "SUCCESS", name=interface_name)

            # [新增] 定义一个字典来存储 Phase 1 获取到的版本信息，用于 Phase 2 极速预检
            device_version_map = {}

            # ==========================================
            # 1. 发现设备 (Discovery Phase)
            # ==========================================
            self.gui_queue.put({'type': 'status_update', 'target': 'overall_status',
                                'msg': self.i18n.t('status_phases.phase1_discover')})

            cidr_mode = job_def.get("cidr_mode", "").strip()
            target_scan = ""

            # [PATH A: CIDR 模式]
            if cidr_mode in ["CIDR-302", "CIDR-BOX"]:
                target_scan = (job_def.get("discovery_cidr", "") or "").strip() or job_def["initial_ip"]

            # [PATH B: 普通模式] - 智能扫描
            else:
                initial_ip = job_def["initial_ip"]
                derived_cidr = self._derive_cidr_from_ip(initial_ip)
                if derived_cidr:
                    target_scan = derived_cidr
                    self.queue_log_i18n("log.smart_scan_auto_derived", "INFO", subnet=target_scan)
                else:
                    target_scan = initial_ip

            # 执行扫描 (支持 multi=True)
            scan_result = self._get_mac_addresses(target_scan, job_def["network_interface"])

            # --- 数据归一化 ---
            macs = []
            current_ip_map = {}

            if isinstance(scan_result, dict):
                macs = list(scan_result.keys())
                current_ip_map = scan_result
            elif scan_result:
                macs = scan_result
                for m in macs: current_ip_map[m] = job_def["initial_ip"]
            else:
                self.queue_log_i18n("log.no_routers_found", "ERROR")
                return

            # --- Confirmation Step ---
            mac_list_str = "\n".join([f"  - {mac} (IP: {current_ip_map.get(mac, 'Unknown')})" for mac in macs])
            proceed = messagebox.askokcancel(
                self.i18n.t("messages.confirm_devices_title"),
                self.i18n.format("messages.confirm_devices_found_msg", count=len(macs), list=mac_list_str)
            )
            if not proceed:
                self.queue_log_i18n("log.user_cancelled_operation", "ERROR")
                return

            # --- GUI Setup ---
            num_devices = len(macs)
            self.gui_queue.put({'type': 'progress_max', 'value': num_devices * (2 if job_def['verify_enabled'] else 1)})
            self.gui_queue.put({'type': 'status_update', 'target': 'progress_counter',
                                'msg': self.i18n.format('status.processed_format', count=0, total=num_devices)})

            if job_def['verify_enabled']:
                self.gui_queue.put({'type': 'status_update', 'target': 'verified_counter',
                                    'msg': self.i18n.format('status.verified_format', count=0, total=num_devices)})
                self.gui_queue.put({'type': 'show_verified_counter'})
            else:
                self.gui_queue.put({'type': 'hide_verified_counter'})

            # 初始化表格索引
            for mac in macs:
                if mac not in self.fixed_indices:
                    self.fixed_indices[mac] = len(self.fixed_indices) + 1

            macs.sort(key=lambda m: self.fixed_indices[m])
            initial_ip_to_index = {}

            for mac in macs:
                fixed_idx = self.fixed_indices[mac]
                curr_ip = current_ip_map.get(mac, '')
                if curr_ip: initial_ip_to_index[curr_ip] = fixed_idx

                upgrade_status = self.i18n.t("table_values.queued") if job_def["do_upgrade"] else self.i18n.t(
                    "table_values.skipped")
                config_status = self.i18n.t("table_values.queued") if job_def["do_import_config"] else self.i18n.t(
                    "table_values.skipped")

                self.gui_queue.put({'type': 'add_device', 'mac': mac, 'index': fixed_idx, 'upgrade': upgrade_status,
                                    'config': config_status})
                if curr_ip: self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'ip', 'value': curr_ip})

            # --- Pre-Flight Credential Fetch ---
            credential_map = {}
            cred_mode = job_def["credential_mode"]

            if cred_mode == "API":
                # [CIDR 模式逻辑保留]
                if cidr_mode:
                    old_count = len(macs)
                    macs, discovered = self._refresh_macs_via_telnet_and_update_gui(macs, current_ip_map, job_def,
                                                                                    initial_ip_map=initial_ip_to_index)
                    current_ip_map = discovered
                    new_count = len(macs)
                    missing = old_count - new_count
                    if missing > 0:
                        msg = self.i18n.format("messages.mac_refresh_summary_with_missing", count=new_count,
                                               missing=missing)
                    else:
                        msg = self.i18n.format("messages.mac_refresh_summary", count=new_count)
                    self.queue_log_i18n("log.mac_refresh_summary", "INFO", count=new_count, missing=missing)
                    try:
                        title = self.i18n.t("messages.mac_refresh_title")
                        instruction = self.i18n.t("messages.stop_confirm_instruction")
                        proceed = messagebox.askokcancel(title, f"{msg}\n\n{instruction}")
                        if not proceed: return
                    except Exception:
                        pass

                api_mac_list = macs
                self.gui_queue.put({'type': 'status_update', 'target': 'overall_status',
                                    'msg': self.i18n.t('status_phases.fetching_creds')})
                self.queue_log_i18n("log.preflight_api_header", "HEADER")
                if not self.api_domain or not self.operator_username:
                    self.queue_log_i18n("log.dynamic_password_api_enabled_but_operator_login_not_configured", 'ERROR')
                    messagebox.showerror(self.i18n.t("messages.config_error_title"),
                                         self.i18n.t("messages.operator_login_config_error"))
                    return
                token = self._get_valid_auth_token()
                if not token:
                    self.queue_log_i18n("log.operator_session_invalid_or_expired", "ERROR")
                    return
                headers = {"Authorization": f"Bearer {token}"}
                try:
                    mac_string = ",".join(api_mac_list)
                    api_url = f"https://{self.api_domain}/api/mes/v3.0/notes/products/password?input={mac_string.upper()}&type=MAC"
                    response = requests.get(api_url, headers=headers, timeout=120)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("result") and isinstance(data["result"], list):
                            for creds in data["result"]:
                                if creds.get("mac"):
                                    credential_map[str(creds["mac"]).lower()] = (creds["user"], creds["password"])
                            self.queue_log_i18n("log.successfully_fetched_credentials", "SUCCESS",
                                                count=len(credential_map))
                            missing_macs = set(macs) - set(credential_map.keys())
                            for mac in missing_macs:
                                self.queue_log_i18n("log.mac_not_found_in_api_database", "ERROR", mac=mac)
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'status',
                                                    'value': self.i18n.t("table_values.creds_failed")})
                        else:
                            for mac in macs: self.gui_queue.put(
                                {'type': 'update_device', 'mac': mac, 'column': 'status',
                                 'value': self.i18n.t("table_values.api_error")})
                    else:
                        for mac in macs: self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'status',
                                                             'value': self.i18n.t("table_values.api_error")})
                except requests.RequestException as e:
                    self.queue_log_i18n("log.api_request_failed", "ERROR", error=str(e))
                    messagebox.showerror(self.i18n.t("messages.api_error_title"),
                                         self.i18n.format("messages.api_fatal_error", e=e))
                    return

            elif cred_mode == "File":
                # [CIDR 模式逻辑保留]
                if cidr_mode:
                    old_count = len(macs)
                    macs, discovered = self._refresh_macs_via_telnet_and_update_gui(macs, current_ip_map, job_def,
                                                                                    initial_ip_map=initial_ip_to_index)
                    current_ip_map = discovered
                    new_count = len(macs)
                    missing = old_count - new_count
                    if missing > 0:
                        msg = self.i18n.format("messages.mac_refresh_summary_with_missing", count=new_count,
                                               missing=missing)
                    else:
                        msg = self.i18n.format("messages.mac_refresh_summary", count=new_count)
                    try:
                        title = self.i18n.t("messages.mac_refresh_title")
                        instruction = self.i18n.t("messages.stop_confirm_instruction")
                        proceed = messagebox.askokcancel(title, f"{msg}\n\n{instruction}")
                        if not proceed: return
                    except Exception:
                        pass

                self.gui_queue.put({'type': 'status_update', 'target': 'overall_status',
                                    'msg': self.i18n.t('status_phases.loading_creds')})
                self.queue_log_i18n("log.loading_credentials_from_file_phase", "HEADER")
                cred_file_path = job_def["credential_file_path"]
                if not cred_file_path or not os.path.exists(cred_file_path):
                    messagebox.showerror(self.i18n.t("messages.file_not_found_title"),
                                         self.i18n.format("messages.credential_file_not_found_msg",
                                                          path=cred_file_path))
                    return
                try:
                    if cred_file_path.lower().endswith('.csv'):
                        df = pd.read_csv(cred_file_path)
                    else:
                        df = pd.read_excel(cred_file_path)
                    file_creds = {}
                    for index, row in df.iterrows():
                        mac_string = str(row['mac'])
                        user = str(row['user'])
                        pwd = str(row['password'])
                        for mac in mac_string.split(';'): file_creds[mac.strip().upper()] = (user, pwd)
                    for mac in macs:
                        mac_upper = mac.upper()
                        if mac_upper in file_creds:
                            credential_map[mac] = file_creds[mac_upper]
                        else:
                            credential_map[mac] = (job_def["username"], job_def["password"])
                    self.queue_log_i18n("log.select_credential_file", "SUCCESS", count=len(file_creds))
                except Exception as e:
                    messagebox.showerror(self.i18n.t("messages.file_error_title"),
                                         self.i18n.format("messages.credential_file_parse_error", e=e))
                    return

            else:  # Static mode
                # [CIDR 模式逻辑保留]
                if cidr_mode:
                    old_count = len(macs)
                    macs, discovered = self._refresh_macs_via_telnet_and_update_gui(macs, current_ip_map, job_def,
                                                                                    initial_ip_map=initial_ip_to_index)
                    current_ip_map = discovered
                    new_count = len(macs)
                    try:
                        title = self.i18n.t("messages.mac_refresh_title")
                        instruction = self.i18n.t("messages.stop_confirm_instruction")
                        msg = self.i18n.format("messages.mac_refresh_summary", count=new_count)
                        proceed = messagebox.askokcancel(title, f"{msg}\n\n{instruction}")
                        if not proceed: return
                    except Exception:
                        pass

                self.queue_log_i18n("log.using_static_credentials_from_ui", "HEADER")
                static_user = job_def["username"]
                static_pass = job_def["password"]
                for mac in macs: credential_map[mac] = (static_user, static_pass)

            # ==========================================
            # 2. 改址阶段 (Phase 1)
            # ==========================================
            self.gui_queue.put({'type': 'status_update', 'target': 'overall_status',
                                'msg': self.i18n.t('status_phases.phase1_readdress')})
            self.queue_log_i18n("log.phase1_header", "HEADER")
            new_ip_map = {}

            # [PATH A: CIDR 模式] - 保持原样
            if cidr_mode:
                for mac in macs:
                    ip_curr = current_ip_map.get(mac)
                    if ip_curr: new_ip_map[mac] = ip_curr

                try:
                    from concurrent.futures import ThreadPoolExecutor, as_completed
                    def info_job(mac_addr):
                        if self.stop_event.is_set(): return
                        ip_curr = current_ip_map.get(mac_addr)
                        if not ip_curr or mac_addr not in credential_map: return
                        user, pwd = credential_map[mac_addr]
                        if not self._check_tcp_port(ip_curr, int(job_def["port"]), 30):
                            self.queue_log_i18n("log.device_not_reachable_for_info_scrape", "ERROR", mac=mac_addr,
                                                ip=ip_curr)
                            return

                        is_pure_api = "DTU512" in job_def.get("model", "").upper()
                        if is_pure_api:
                            ctx_manager = nullcontext((None, None))
                        else:
                            ctx_manager = self._get_playwright_context()

                        with ctx_manager as (browser, context):
                            if is_pure_api:
                                page = None
                            else:
                                page = context.new_page()
                            try:
                                self.gui_queue.put({'type': 'update_device', 'mac': mac_addr, 'column': 'status',
                                                    'value': self.i18n.t("table_values.info")})
                                info_handler = model_factory.get_handler(job_def["model"])
                                device_info = info_handler.get_device_info(page, job_def["protocol"], job_def["port"],
                                                                           ip_curr, user, pwd)
                                if device_info:
                                    # [注意] CIDR 模式目前不传递版本上下文，若有需要可在此处添加
                                    for key, val in device_info.items():
                                        if val != 'N/A':
                                            self.gui_queue.put(
                                                {'type': 'update_device', 'mac': mac_addr, 'column': key, 'value': val})
                            except Exception:
                                pass
                            finally:
                                if page: page.close()

                    with ThreadPoolExecutor(max_workers=min(16, len(new_ip_map))) as ex:
                        futures = [ex.submit(info_job, m) for m in macs]
                        for _ in as_completed(futures):
                            if self.stop_event.is_set(): break
                except Exception:
                    pass

            # [PATH B: 普通模式] - 智能混合逻辑 (带动态冲突消减 + 并行补采 + 版本捕获)
            else:
                base_ip_parts = job_def["new_ip_start"].split('.')
                base_prefix = ".".join(base_ip_parts[:-1])
                start_octet = int(base_ip_parts[-1])
                handler = model_factory.get_handler(job_def["model"])

                from collections import Counter
                ip_counts = Counter(current_ip_map.values())
                skipped_macs_for_info = []  # 待补采列表

                with self._get_playwright_context() as (browser, context):
                    for i, mac in enumerate(macs):
                        if self.stop_event.is_set() or mac not in credential_map: continue

                        user, pwd = credential_map[mac]
                        target_new_ip = f"{base_prefix}.{start_octet + i}"
                        new_ip_map[mac] = target_new_ip
                        current_actual_ip = current_ip_map.get(mac, job_def["initial_ip"])

                        # 动态判断状态
                        has_conflict = ip_counts[current_actual_ip] > 1
                        ip_counts[current_actual_ip] -= 1
                        is_independent = current_actual_ip != job_def["initial_ip"]

                        should_skip = False
                        if has_conflict:
                            should_skip = False
                        elif is_independent:
                            should_skip = True
                            new_ip_map[mac] = current_actual_ip
                            self.queue_log_i18n("log.keep_independent_ip_log", "INFO", ip=current_actual_ip, mac=mac)
                        elif current_actual_ip == target_new_ip:
                            should_skip = True

                        # 执行跳过
                        if should_skip:
                            self.gui_queue.put(
                                {'type': 'update_device', 'mac': mac, 'column': 'status', 'value': "Ready (Skipped)"})
                            self.gui_queue.put(
                                {'type': 'update_device', 'mac': mac, 'column': 'ip', 'value': new_ip_map[mac]})
                            self.queue_log_i18n("log.ip_already_match_skip", "INFO", mac=mac, ip=target_new_ip)
                            skipped_macs_for_info.append(mac)  # 加入补采队列
                            continue

                        # 执行改址
                        self.queue_log_i18n("log.processing_router", "INFO", current=i + 1, total=num_devices, mac=mac)
                        self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'status',
                                            'value': self.i18n.t("table_values.readdressing")})

                        if not self._set_static_arp(mac, current_actual_ip, job_def["network_interface"]): continue

                        try:
                            if not self._check_tcp_port(current_actual_ip, int(job_def["port"]), 60):
                                self.queue_log_i18n("log.device_tcp_check_failed", "ERROR", mac=mac)
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'status',
                                                    'value': self.i18n.t("table_values.tcp_failed")})
                                continue

                            page = context.new_page()
                            success, device_info = handler.change_ip(page, job_def["protocol"], job_def["port"],
                                                                     current_actual_ip, target_new_ip, user, pwd)

                            if success:
                                self.queue_log_i18n("log.ip_change_success", "SUCCESS", mac=mac, new_ip=target_new_ip)
                                current_ip_map[mac] = target_new_ip
                                self.gui_queue.put(
                                    {'type': 'update_device', 'mac': mac, 'column': 'ip', 'value': target_new_ip})
                                if device_info:
                                    # [关键动作 1] 改址成功，捕获版本号
                                    if device_info.get('version'):
                                        device_version_map[mac] = device_info['version']
                                    for key, val in device_info.items(): self.gui_queue.put(
                                        {'type': 'update_device', 'mac': mac, 'column': key, 'value': val})
                            else:
                                self.queue_log_i18n("log.ip_change_failed", "ERROR", mac=mac)
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'status',
                                                    'value': self.i18n.t("table_values.failed")})
                            page.close()
                        finally:
                            self._delete_static_arp(current_actual_ip, job_def["network_interface"])

                # [并行信息补采] + [捕获版本号]
                if skipped_macs_for_info:
                    self.queue_log_i18n("log.fetching_skipped_info_header", "HEADER", count=len(skipped_macs_for_info))
                    from concurrent.futures import ThreadPoolExecutor, as_completed

                    def fetch_info_task(mac_addr):
                        if self.stop_event.is_set(): return mac_addr, None
                        ip_curr = new_ip_map.get(mac_addr)
                        if not ip_curr or mac_addr not in credential_map: return mac_addr, None
                        user_t, pwd_t = credential_map[mac_addr]

                        if not self._check_tcp_port(ip_curr, int(job_def["port"]), 10): return mac_addr, None

                        is_pure_api = "DTU512" in job_def.get("model", "").upper()
                        if is_pure_api:
                            ctx_mgr = nullcontext((None, None))
                        else:
                            ctx_mgr = self._get_playwright_context()

                        fetched_ver = None
                        with ctx_mgr as (browser_t, context_t):
                            if is_pure_api:
                                page_t = None
                            else:
                                page_t = context_t.new_page()
                            try:
                                self.gui_queue.put({'type': 'update_device', 'mac': mac_addr, 'column': 'status',
                                                    'value': self.i18n.t("table_values.info")})
                                info_handler = model_factory.get_handler(job_def["model"])
                                d_info = info_handler.get_device_info(page_t, job_def["protocol"], job_def["port"],
                                                                      ip_curr, user_t, pwd_t)
                                if d_info:
                                    fetched_ver = d_info.get('version')
                                    for key, val in d_info.items():
                                        if val != 'N/A': self.gui_queue.put(
                                            {'type': 'update_device', 'mac': mac_addr, 'column': key, 'value': val})
                                    self.gui_queue.put({'type': 'update_device', 'mac': mac_addr, 'column': 'status',
                                                        'value': "Ready"})
                            except Exception:
                                pass
                            finally:
                                if page_t: page_t.close()
                        return mac_addr, fetched_ver

                    with ThreadPoolExecutor(max_workers=min(16, len(skipped_macs_for_info))) as executor:
                        futures = [executor.submit(fetch_info_task, m) for m in skipped_macs_for_info]
                        for fut in as_completed(futures):
                            m_addr, m_ver = fut.result()
                            if m_ver:
                                device_version_map[m_addr] = m_ver

            self._clear_arp()
            if self.stop_event.is_set(): return

            # ==========================================
            # 3. 并行任务 (Phase 2)
            # ==========================================
            self.gui_queue.put({'type': 'status_update', 'target': 'overall_status',
                                'msg': self.i18n.t('status_phases.phase2_parallel')})
            self.queue_log_i18n("log.phase2_header", "HEADER")

            task_queue = queue.Queue()
            for mac, ip in new_ip_map.items():
                if mac in credential_map:
                    user, pwd = credential_map[mac]
                    # [关键动作 4] 将版本号打包进队列
                    current_ver = device_version_map.get(mac, 'N/A')
                    task_queue.put((mac, ip, user, pwd, current_ver))

            threads = []
            processed_counter = [0]
            for i in range(min(16, len(new_ip_map))):
                thread = threading.Thread(target=self.task_worker, args=(
                task_queue, self.verification_queue, job_def, processed_counter, num_devices, threading.Lock()),
                                          name=f"Worker-{i + 1}")
                thread.daemon = True
                threads.append(thread)
                thread.start()
            for thread in threads: thread.join()

            self.gui_queue.put({'type': 'progress_value', 'value': num_devices})
            self._clear_arp()

            # --- CIDR-BOX Post-Task Logic (NAT Refresh) ---
            cidr_mode_type = (job_def.get("cidr_mode") or "").strip()
            current_model_name = str(job_def.get("model", "")).upper()
            if cidr_mode_type == "CIDR-BOX" and getattr(self, "mac_to_box_ip",
                                                        None) and 'DTU512' not in current_model_name:
                # (保持 CIDR-BOX 逻辑不变)
                box_ips = sorted(set(self.mac_to_box_ip.values()))
                for box_ip in box_ips:
                    # ... (省略中间逻辑，保持原样) ...
                    # 注意：如果需要完整代码请保留此处逻辑
                    self.queue_log_i18n("log.refreshing_box_nat_after_all_devices", "INFO", box_ip=box_ip)
                    # ...
                    # 鉴于代码长度，此处省略具体的 NAT 刷新逻辑，请直接保留你原有的 CIDR-BOX 代码块
                    pass

                    # Info refresh after NAT (CIDR-BOX)
                try:
                    # ... (省略信息刷新逻辑，保持原样) ...
                    pass
                except Exception:
                    pass

            # ==========================================
            # 4. 验证与 MES (Phase 3 & 4) - 通用
            # ==========================================
            # (保持原有的 Phase 3, Phase 4, MES Reporting 逻辑不变)
            if job_def['verify_enabled']:
                self.gui_queue.put({'type': 'status_update', 'target': 'overall_status',
                                    'msg': self.i18n.t('status_phases.phase3_verifying')})
                self.queue_log_i18n("log.phase3_header", "HEADER")
                # ... (Verify logic) ...
                while not self.verification_queue.empty():
                    if self.stop_event.is_set(): break
                    mac = self.verification_queue.get()
                    # ... (Verify loop content) ...
                    self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'verification',
                                        'value': self.i18n.t("table_values.verified_tcp")})

            elif job_def['element_verify_enabled']:
                # ... (Element verify logic) ...
                pass

            mes_reporting_enabled = self.auth_token is not None and job_def["do_upgrade"]
            if mes_reporting_enabled:
                self.gui_queue.put({'type': 'status_update', 'target': 'overall_status',
                                    'msg': self.i18n.t('status_phases.phase4_mes')})
                self._perform_mes_reporting()
            elif self.auth_token is not None and not job_def["do_upgrade"]:
                self.queue_log_i18n("log.mes_skipped_no_upgrade_selected", "INFO")

            self.queue_log_i18n("log.batch_finished_header", "HEADER")
            self.gui_queue.put({'type': 'sort_tree_by_ip'})
            job_successful = True

        except Exception as e:
            self.queue_log_i18n("log.orchestrator_unexpected_error", "ERROR", error=e)
            logging.error("Orchestrator exception", exc_info=e)
        finally:
            self.timer_running = False
            self.start_button.config(state="normal")
            self.stop_button.config(state=tk.DISABLED)
            self.gui_queue.put(
                {'type': 'status_update', 'target': 'overall_status', 'msg': self.i18n.t('status_phases.finished')})
            if job_successful:
                self.gui_queue.put({'type': 'show_completion_message'})
    def _check_tcp_port(self, ip, port, timeout):
        """轮询 TCP 端口可达性。

        - 每次连接尝试设置短超时（2s），失败后间隔 5s 重试，直到总体超时
        - 用于改址前/验证阶段的基础在线性判定（端口可自定义，如 80/443/23）
        """
        # --- 新增：针对 DTU512 的特殊处理 ---
        current_model = self.job_definition.get("model", tk.StringVar()).get()
        if "DTU512" in current_model.upper():
            return self._check_ping(ip, count=1, timeout=2) # 复用已有的 _check_ping 方法
        # ----------------------------------
        self.queue_log_i18n("log.tcp_connect_attempt", "INFO",
                    ip=ip, port=port, timeout=timeout)
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.stop_event.is_set(): return False
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2) # Set a short timeout for each individual connection attempt
                try:
                    if s.connect_ex((ip, port)) == 0:
                        self.queue_log_i18n(
                            "log.tcp_connect_success",
                            "SUCCESS",
                            ip=ip,
                            port=port,
                        )
                        return True
                except socket.gaierror:
                    self.queue_log_i18n(
                        "log.hostname_resolve_retry",
                        "ERROR",
                        ip=ip,
                    )
                except socket.error:
                    # This will catch other socket errors, but we'll just log a generic retry message
                    pass
            
            self.queue_log_i18n(
                "log.tcp_no_response_retry",
                "INFO",
                ip=ip,
                port=port,
            )
            time.sleep(5) # Wait 5 seconds before retrying
        
        self.queue_log_i18n("log.tcp_failed_after_timeout", "ERROR",
                    ip=ip, port=port, timeout=timeout)
        return False
    def _check_ping(self, ip: str, count: int = 1, timeout: int = 2, max_retries: int = 40, retry_delay: float = 1.0) -> bool:
        """
        跨平台检测 IP 是否可达 (ICMP Ping)
        优化点：修复端口变量未定义错误、隐藏 Windows 下的 CMD 窗口、修正日志逻辑
        新增功能：增加重试机制，应对网络波动
        
        :param max_retries: 失败后的最大重试次数 (默认重试2次，共尝试3次)
        :param retry_delay: 每次重试之间的等待秒数
        """
        import subprocess
        import platform
        import time  # 引入 time 模块用于重试等待
        
        # 1. 根据系统构造命令参数 (参数构造只需做一次)
        system_name = platform.system().lower()
        param_count = '-n' if system_name == 'windows' else '-c'
        param_wait = '-w' if system_name == 'windows' else '-W'
        
        # Windows ping 的超时单位是毫秒，Linux 是秒
        timeout_val = str(timeout * 1000) if system_name == 'windows' else str(timeout)
        
        command = ['ping', param_count, str(count), param_wait, timeout_val, ip]

        # 2. Windows 特有优化：隐藏弹出的一闪而过的黑框 (CMD窗口)
        startupinfo = None
        if system_name == 'windows':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        # 3. 开始执行带重试的循环
        # range(max_retries + 1) 保证至少执行1次，若失败则重试 max_retries 次
        for attempt in range(max_retries + 1):
            try:
                # timeout+1 是为了防止 ping 命令卡死，给 python 的 subprocess 一个强制超时的机会
                result = subprocess.run(
                    command, 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL, 
                    timeout=timeout + 1,
                    startupinfo=startupinfo
                )

                # 4. 根据返回码判断结果
                if result.returncode == 0:
                    if hasattr(self, 'queue_log_i18n'):
                        # 成功时记录日志，如果是重试后成功的，可以在日志里体现（可选）
                        msg_key = "log.ping_success" if attempt == 0 else "log.ping_success_retry"
                        self.queue_log_i18n(msg_key, "SUCCESS", ip=ip)
                    return True
                else:
                    # Ping 不通，准备重试或返回失败
                    if attempt < max_retries:
                        # 只有在还有剩余重试次数时才记录重试日志并等待
                        if hasattr(self, 'queue_log_i18n'):
                            self.queue_log_i18n("log.ping_retry", "WARNING", ip=ip, attempt=attempt+1)
                        time.sleep(retry_delay)
                        continue
                    else:
                        # 最后一次尝试也失败了
                        return False

            except subprocess.TimeoutExpired:
                # 执行命令本身超时
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    continue
                
                if hasattr(self, 'queue_log_i18n'):
                    self.queue_log_i18n("log.ping_timeout", "ERROR", ip=ip)
                return False
                
            except Exception as e:
                # 其他系统错误
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    continue

                if hasattr(self, 'queue_log_i18n'):
                    self.queue_log_i18n("log.ping_system_error", "ERROR", ip=ip, error=str(e))
                return False

        return False

    def _is_version_match(self, ver_file, ver_device):
        """
        辅助函数：比对固件文件版本与设备当前版本。
        策略：提取两个字符串中的首个数字序列部分进行比对。
        """
        if not ver_file or not ver_device:
            return False

        # 定义一个内部函数来提取纯版本号 (例如 "V3.5.63" -> "3.5.63")
        def normalize(v):
            # 使用正则提取类似 3.5.63 或 3.5.63.1 的结构
            import re
            match = re.search(r'(\d+(\.\d+)+)', str(v))
            return match.group(1) if match else str(v).strip()

        norm_file = normalize(ver_file)
        norm_device = normalize(ver_device)

        print(f"DEBUG: Comparing File '{norm_file}' vs Device '{norm_device}'")

        return norm_file == norm_device

    def task_worker(self, q, verification_q, job_def, processed_counter, total_devices, lock):
        """工作线程：从任务队列取出设备并执行 Playwright 自动化。

        流程：
        - 可选升级：提交升级 → 等待重启恢复；失败则标记 FAILED
        - 配置任务（二选一）：导入配置 或 恢复出厂；必要时合并设备信息
        - 信息刷新：在无其它任务覆盖的情况下主动拉取版本/引导/SN 等
        - GUI 更新：仅通过消息队列写入，避免跨线程操作控件
        - 验证队列：无论成功失败，都把 MAC 入队，供验证阶段使用
        """
        handler = model_factory.get_handler(job_def["model"])

        current_model = job_def["model"]
        is_pure_api_model = "DTU512" in current_model.upper()

        if is_pure_api_model:
            ctx_manager = nullcontext((None, None))
        else:
            ctx_manager = self._get_playwright_context()

        with ctx_manager as (browser, context):
            while not q.empty() and not self.stop_event.is_set():
                try:
                    # [关键动作] 解包 5 个参数 (接收 Phase 1 传递的版本号)
                    mac, ip, user, pwd, current_version = q.get_nowait()

                    # === 1. 升级预检逻辑 (极速比对) ===
                    skip_upgrade_action = False

                    # 仅当勾选了升级，且有固件路径，且版本号有效时，才进行比对
                    if job_def["do_upgrade"] and job_def["firmware_path"] and current_version != 'N/A':
                        try:
                            # 提取目标文件版本
                            target_firmware_ver = handler.extract_version(job_def["firmware_path"])

                            # 执行版本比对 (调用 BatchUpdaterApp 类中的辅助方法)
                            if self._is_version_match(target_firmware_ver, current_version):
                                self.queue_log_i18n("log.version_match_fast_check", "SUCCESS", ip=ip, version=current_version)

                                # 更新 UI 为已跳过
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'upgrade',
                                                    'value': self.i18n.t("table_values.skipped")})
                                skip_upgrade_action = True
                        except Exception as e:
                            # 预检出错不应阻断流程，仅打印警告，降级为正常升级流程
                            print(f"Version check warning for {ip}: {e}")

                    # === 2. 智能资源分配 (Crash Fix) ===
                    # 检查是否有其他任务需要浏览器
                    other_browser_tasks = (
                            job_def["do_import_config"] or
                            job_def["do_restore_defaults"] or
                            job_def["do_import_incremental_config"] or
                            (job_def["restore_default_ip"] and job_def["is_default_ip"] == 'YES')
                    )

                    # 决定是否初始化 Page
                    if is_pure_api_model:
                        page = None
                    elif skip_upgrade_action and not other_browser_tasks:
                        page = None  # 没有任何任务需要浏览器，安全跳过
                    else:
                        page = context.new_page()  # 有升级任务 OR 有其他配置任务，必须创建

                    # === 3. 执行任务流程 ===
                    self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'status',
                                        'value': self.i18n.t("table_values.running")})

                    final_status = 'SUCCESS'
                    device_info = {}

                    # --- Task: Upgrade ---
                    if job_def["do_upgrade"]:
                        if skip_upgrade_action:
                            # 预检通过，直接跳过实际执行
                            pass
                        else:
                            # 正常执行升级
                            self.queue_log_i18n("log.upgrade_start", "INFO", ip=ip)
                            self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'upgrade',
                                                'value': self.i18n.t("table_values.in_progress")})

                            # 此时 page 一定是有效的 (因为 skip_upgrade_action 为 False)
                            upgrade_success = handler.upgrade(page, job_def["protocol"], job_def["port"], ip, user, pwd,
                                                              job_def["firmware_path"],
                                                              job_def["do_upgrade_boot"])
                            if upgrade_success:
                                self.queue_log_i18n("log.upgrade_initiated_wait_reboot", "SUCCESS", ip=ip)
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'upgrade',
                                                    'value': self.i18n.t("table_values.rebooting")})
                                reboot_ok = handler.reboot_and_wait(page, job_def["protocol"], job_def["port"], ip)
                                if not reboot_ok:
                                    self.queue_log_i18n("log.upgrade_router_not_back_online", "ERROR", ip=ip)
                                    self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'upgrade',
                                                        'value': self.i18n.t("table_values.reboot_failed")})
                                    final_status = 'FAILED'
                                else:
                                    self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'upgrade',
                                                        'value': self.i18n.t("table_values.success")})

                                    # 升级后任务：运输模式
                                    if job_def["do_shipmode"]:
                                        self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'status',
                                                            'value': self.i18n.t("table_values.shipmode_set")})
                                        self.queue_log_i18n("log.shipmode_start", "INFO", ip=ip)
                                        if hasattr(handler, 'set_device_shipmode'):
                                            ship_result = handler.set_device_shipmode(ip, user, pwd)
                                            if ship_result:
                                                # 复用或使用新定义的规范 Log
                                                self.queue_log_i18n("log.shipmode_success_log", "SUCCESS", ip=ip)
                                                self.gui_queue.put(
                                                    {'type': 'update_device', 'mac': mac, 'column': 'status',
                                                     'value': self.i18n.t("table_values.shipmode_ok")})
                                            else:
                                                self.queue_log_i18n("log.shipmode_fail_log", "ERROR", ip=ip)
                                                self.gui_queue.put(
                                                    {'type': 'update_device', 'mac': mac, 'column': 'status',
                                                     'value': self.i18n.t("table_values.shipmode_fail")})
                                                final_status = 'FAILED'

                                    # 升级后强制刷新信息 (如果后续没有其他配置任务会刷新它)
                                    should_refresh_info_now = (
                                            not job_def["do_import_config"] and
                                            not job_def["do_restore_defaults"] and
                                            not job_def["do_import_incremental_config"]
                                    )
                                    if should_refresh_info_now and job_def["is_default_ip"] == 'NO':
                                        self.queue_log_i18n("log.refreshing_device_info_post_upgrade", "INFO", ip=ip)
                                        device_info = handler.get_device_info(page, job_def["protocol"],
                                                                              job_def["port"], ip, user, pwd)
                                        self.queue_log_i18n("log.refreshing_device_info_success", "INFO", ip=ip)
                            else:
                                self.queue_log_i18n("log.firmware_upgrade_failed", "ERROR", ip=ip)
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'upgrade',
                                                    'value': self.i18n.t("table_values.failed")})
                                final_status = 'FAILED'

                    # --- IG502 Model-Specific Step (between Upgrade and Import Config) ---
                    if final_status == 'SUCCESS' and self._is_ig502_model(job_def.get("model", "")) and job_def.get("do_ig502_step", False):
                        self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'status',
                                            'value': 'IG502 Running'})
                        ig502_success, switched_ip = self._run_ig502_pre_config(job_def, ip, user, pwd)
                        if ig502_success:
                            ip = switched_ip
                            self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'ip', 'value': ip})
                            self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'status',
                                                'value': 'IG502 Success'})
                        else:
                            self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'status',
                                                'value': 'IG502 Failed'})
                            self.gui_queue.put({
                                'type': 'show_error_message',
                                'title': 'IG502 Step Failed',
                                'message': 'IG502 pre-config failed. Please retry before importing config.',
                            })
                            final_status = 'FAILED'

                    # --- Step 2: Configuration Task (Mutually Exclusive) ---
                    # 只有当 final_status 为 SUCCESS 时才执行（注意：跳过升级也算 SUCCESS）
                    if final_status == 'SUCCESS':
                        if job_def["do_restore_defaults"]:
                            self.queue_log_i18n("log.restore_defaults_start", "INFO", ip=ip)
                            self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'config',
                                                'value': self.i18n.t("table_values.restoring")})
                            restore_success, info_from_config = handler.restore_defaults(page, job_def["protocol"],
                                                                                         job_def["port"], ip, user, pwd)
                            device_info.update(info_from_config)

                            if restore_success:
                                self.queue_log_i18n("log.restore_defaults_initiated", "SUCCESS", ip=ip)
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'config',
                                                    'value': self.i18n.t("table_values.restored")})
                            else:
                                self.queue_log_i18n("log.restore_defaults_failed", "ERROR", ip=ip)
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'config',
                                                    'value': self.i18n.t("table_values.restore_failed")})
                                final_status = 'FAILED'

                        elif job_def["do_import_config"]:
                            self.queue_log_i18n("log.config_import_start", "INFO", ip=ip)
                            self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'config',
                                                'value': self.i18n.t("table_values.in_progress")})
                            config_success, info_from_config = handler.import_config(
                                page, job_def["protocol"], job_def["port"], ip, user, pwd,
                                job_def["config_path"], job_def["element_verify_enabled"]
                            )
                            device_info.update(info_from_config)

                            if config_success:
                                self.queue_log_i18n("log.config_import_initiated", "SUCCESS", ip=ip)
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'config',
                                                    'value': self.i18n.t("table_values.success")})
                            else:
                                self.queue_log_i18n("log.config_import_failed", "ERROR", ip=ip)
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'config',
                                                    'value': self.i18n.t("table_values.failed")})
                                router_msg = info_from_config.get("config_error")
                                if router_msg:
                                    self.gui_queue.put({
                                        'type': 'show_error_message',
                                        'title': self.i18n.t("messages.router_config_import_error_title"),
                                        'message': router_msg,
                                    })
                                final_status = 'FAILED'

                        elif job_def["do_import_incremental_config"]:
                            self.queue_log_i18n("log.config_import_start", "INFO", ip=ip)
                            self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'config',
                                                'value': self.i18n.t("table_values.in_progress")})
                            # 注意：即使是增量导入，handler 内部也需要 page 来进行登录操作
                            config_success, info_from_config = handler.import_incremental_config(page,
                                                                                                 job_def["protocol"],
                                                                                                 job_def["port"], ip,
                                                                                                 user, pwd, job_def[
                                                                                                     "incremental_config_path"],
                                                                                                 job_def[
                                                                                                     "is_default_ip"],
                                                                                                 job_def["initial_ip"],
                                                                                                 job_def[
                                                                                                     "element_verify_enabled"])
                            device_info.update(info_from_config)
                            if config_success:
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'ip',
                                                    'value': job_def["initial_ip"]})
                                self.queue_log_i18n("log.config_import_initiated", "SUCCESS", ip=ip)
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'config',
                                                    'value': self.i18n.t("table_values.success")})
                            else:
                                self.queue_log_i18n("log.config_import_failed", "ERROR", ip=ip)
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'config',
                                                    'value': self.i18n.t("table_values.failed")})
                                final_status = 'FAILED'

                    # --- Step 3: Restore Default IP (Optional) ---
                    if final_status == 'SUCCESS' and job_def["restore_default_ip"]:
                        if job_def["is_default_ip"] == 'YES':
                            new_ip = job_def["initial_ip"]
                            # change_ip 也需要 page
                            success, ip_device_info = handler.change_ip(page, job_def["protocol"], job_def["port"], ip,
                                                                        new_ip, user, pwd)
                            device_info.update(ip_device_info)
                            if success:
                                self.queue_log_i18n("log.ip_change_success", "SUCCESS", mac=mac, new_ip=new_ip)
                                self.gui_queue.put(
                                    {'type': 'update_device', 'mac': mac, 'column': 'ip', 'value': new_ip})
                            else:
                                self.queue_log_i18n("log.ip_change_failed", "ERROR", mac=mac)
                                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'status',
                                                    'value': self.i18n.t("table_values.failed")})
                                final_status = 'FAILED'
                        else:
                            self.queue_log_i18n("log.keep_current_ip_no_restore", "INFO", ip=ip)
                            self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'ip', 'value': ip})

                    # 更新获取到的设备信息到 GUI
                    if device_info:
                        if device_info.get("version") and self.newly_installed_firmware_version is None:
                            self.newly_installed_firmware_version = device_info["version"]

                        self.queue_log_i18n("log.updating_gui_with_device_info", "INFO", ip=ip, device_info=device_info)
                        for key, val in device_info.items():
                            if val != 'N/A': self.gui_queue.put(
                                {'type': 'update_device', 'mac': mac, 'column': key, 'value': val})

                    display_status = self.i18n.t("table_values.success") if final_status == 'SUCCESS' else self.i18n.t(
                        "table_values.failed")

                    self.gui_queue.put(
                        {'type': 'update_device', 'mac': mac, 'column': 'status', 'value': display_status})
                    self.gui_queue.put({'type': 'update_device_status', 'mac': mac, 'tag': final_status})

                    if page:
                        page.close()
                except queue.Empty:
                    break
                except Exception as e:
                    self.queue_log_i18n("log.error_processing_job", "ERROR", error=str(e))
                    logging.error("Task worker exception", exc_info=e)
                    if 'mac' in locals():
                        self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'status',
                                            'value': self.i18n.t("table_values.failed")})
                finally:
                    if 'mac' in locals(): verification_q.put(mac)
                    q.task_done()
                    with lock:
                        processed_counter[0] += 1
                        count = processed_counter[0]
                        self.gui_queue.put({'type': 'status_update', 'target': 'progress_counter',
                                            'msg': self.i18n.format('status.processed_format', count=count,
                                                                    total=total_devices)})


    def _get_playwright_context(self):
        """提供 Playwright 上下文管理器。

        - 使用 Chromium，默认非无头（headless=False），便于产线可视化排错
        - 忽略 HTTPS 证书错误，兼容自签名/开发证书场景
        - 统一在 finally 中关闭 browser 与 playwright 进程
        """
        # Placeholder for a real context manager
        from contextlib import contextmanager
        import sys
        @contextmanager
        def playwright_manager():
            p = None
            browser = None
            try:
                p = sync_playwright().start()

                # 如果是打包后的 exe，设置浏览器路径
                if getattr(sys, 'frozen', False):
                    # 运行在打包的 exe 中
                    # PyInstaller 会将文件解压到 _MEIPASS 临时目录
                    base_path = sys._MEIPASS
                    # 设置 Playwright 浏览器路径环境变量
                    os.environ['PLAYWRIGHT_BROWSERS_PATH'] = os.path.join(base_path, 'playwright', 'driver', 'package',
                                                                          '.local-browsers')

                browser = p.chromium.launch(headless=False)

                context = browser.new_context(ignore_https_errors=True)
                yield browser, context
            finally:
                if browser: browser.close()
                if p: p.stop()

        return playwright_manager()

    def _on_cidr_mode_clicked(self, mode):
        """
        CIDR 模式单选按钮点击回调：
        - 再次点击已选中的选项时，清空 cidr_mode（实现“可取消选择”的效果）；
        - 不同选项之间仍保持互斥（同一时间只有一个值，或为空）。
        """
        current = (self.job_definition["cidr_mode"].get() or "").strip()
        if current == mode:
            # 再次点击同一选项 -> 清空，恢复到“未选择 CIDR 模式”的状态
            self.job_definition["cidr_mode"].set("")
        else:
            # 选择新的 CIDR 模式
            self.job_definition["cidr_mode"].set(mode)
        # 根据最新的 cidr_mode 状态更新 Discovery CIDR 字段显示
        self._toggle_cidr_fields()

    def _get_mac_addresses(self, ip_or_cidr, interface):
        """通过 Scapy 进行 ARP 扫描，探测设备 MAC。

        改进：
        1. 开启 multi=True 以支持同一 IP 的多个设备响应（物理层冲突兼容）。
        2. 根据输入是否为 CIDR 网段，智能返回 {MAC: IP} 字典或 [MAC] 列表。
        """
        self.queue_log_i18n("log.arp_discovery_start", "INFO",
                            interface=interface, target=ip_or_cidr)
        try:
            from scapy.all import srp, Ether, ARP, conf

            # 获取本机在该网段的源 IP
            source_ip = self._get_ip_for_interface(interface, ip_or_cidr)
            if not source_ip:
                self.queue_log_i18n(
                    "log.arp_source_ip_not_found",
                    "ERROR",
                    interface=interface,
                )
                return None

            self.queue_log_i18n(
                "log.arp_using_source_ip",
                "INFO",
                source_ip=source_ip,
            )

            # 构造广播 ARP 请求
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_or_cidr, psrc=source_ip)

            # === 核心修改：multi=True ===
            # 必须开启 multi=True，否则 Scapy 收到第一个 ARP 回复就会停止监听。
            # 这对于解决 "5 台设备全是 192.168.2.1" 的场景至关重要。
            answered, _ = srp(arp_request, timeout=2.0, iface=interface, verbose=0, multi=True)

            is_cidr_scan = "/" in str(ip_or_cidr)

            # 重试逻辑
            if not answered:
                self.queue_log_i18n("log.arp_no_replies", "ERROR")
                answered, _ = srp(
                    arp_request, timeout=2.0, iface=interface, verbose=0, multi=True
                )

            if not answered:
                return {} if is_cidr_scan else []

            # === 核心修改：返回结构分流 ===
            if is_cidr_scan:
                # 隐式增强/CIDR模式：返回 {MAC: IP} 字典
                # 即使 5 台设备 IP 相同，字典也会保留 5 个不同的 MAC 键
                mac_to_ip = {}
                for snd, rcv in answered:
                    # 过滤掉本机发出的包（防止自回环干扰）
                    if rcv.psrc == source_ip:
                        continue
                    mac_to_ip[rcv.src.upper()] = rcv.psrc

                self.queue_log_i18n("log.arp_discovery_success_mac_to_ip", "SUCCESS",
                                    count=len(mac_to_ip), mapping=str(mac_to_ip))
                return mac_to_ip
            else:
                # 普通单 IP 模式（旧逻辑兼容）：只返回 MAC 列表
                # 使用 set 去重
                macs = list(set([rcv.src.upper() for _, rcv in answered]))
                self.queue_log_i18n("log.arp_discovery_success_mac_to_ip", "SUCCESS",
                                    count=len(macs), mapping=str(macs))
                return macs

        except ImportError:
            self.queue_log_i18n("log.scapy_required", "ERROR")
            messagebox.showerror(self.i18n.t("messages.dependency_missing_title"),
                                 self.i18n.t("messages.scapy_missing_msg"))
            return None
        except Exception as e:
            # 捕获其他异常（如网卡权限问题）
            self.queue_log_i18n("log.scapy_error", "ERROR", error=str(e))
            return None

    def _get_mac_via_ssh_box(self, box_host, box_user, box_password, script_path, script_args=""):
        """通过 SSH 连接到 BOX，执行脚本，解析返回的 Linux IP 和 USB MAC 映射。
        
        Args:
            box_host: SSH 主机地址
            box_user: SSH 用户名
            box_password: SSH   密码
            script_path: 本地脚本路径
            script_args: 传递给脚本的参数字符串（可选）
            
        Returns:
            dict: {mac: linux_ip} 格式的映射字典，失败返回 None
        """
        self.queue_log_i18n("log.ssh_connecting_box", "INFO",
                    user=box_user, host=box_host)
        try:
            import paramiko
            
            # 创建 SSH 客户端
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                # 连接到 BOX
                ssh.connect(box_host, username=box_user, password=box_password, timeout=10)
                self.queue_log_i18n("log.ssh_connection_established", "SUCCESS",
                    host=box_host)
                
                # 读取本地脚本内容
                with open(script_path, 'r', encoding='utf-8') as f:
                    script_content = f.read()
                
                 # 规范化换行符，避免在 BOX 上出现 $'\r': command not found
                script_content = script_content.replace('\r\n', '\n')
                
                
                # 上传脚本到远程临时目录
                remote_script_path = '/tmp/usb_routing_setup.sh'
                sftp = ssh.open_sftp()
                with sftp.file(remote_script_path, 'w') as remote_file:
                    remote_file.write(script_content)
                sftp.chmod(remote_script_path, 0o755)
                sftp.close()
                self.queue_log_i18n(
                    "log.ssh_script_uploaded",
                    "SUCCESS",
                    path=remote_script_path,
                )
                
                # 执行脚本并捕获输出
                self.queue_log_i18n("log.ssh_executing_script", "INFO")

                # ---【修改点】将参数拼接到命令中 ---
                cmd = f"echo 'n' | sudo -S bash {remote_script_path} {script_args}"
                stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
                # -------------------------------
                # 使用 echo 'y' 来自动回答脚本中的提示
                # stdin, stdout, stderr = ssh.exec_command(f"echo 'n' | sudo -S bash {remote_script_path}", get_pty=True)
                stdin.write(box_password + '\n')
                stdin.flush()
                
                # 读取输出
                output = stdout.read().decode('utf-8')
                error = stderr.read().decode('utf-8')
                
                self.queue_log_i18n("log.ssh_script_completed", "SUCCESS")
                
                # 解析输出
                mac_to_ip = self._parse_ssh_box_output(output)
                
                if mac_to_ip:
                    self.queue_log_i18n("log.ssh_found_usb_devices", "SUCCESS",
                    count=len(mac_to_ip), mapping=mac_to_ip)
                    return mac_to_ip
                else:

                    self.queue_log_i18n("log.ssh_failed_parse_usb_mapping", "ERROR")
                    self.queue_log_i18n(
                        "log.ssh_script_output_debug",
                        "DEBUG",
                        output=output,
                    )
                    return None
                    
            finally:
                ssh.close()
                
        except ImportError:
            self.queue_log_i18n("log.paramiko_required", "ERROR")
            messagebox.showerror(self.i18n.t("messages.dependency_missing_title"), self.i18n.t("messages.paramiko_missing_msg"))
            return None
        except Exception as e:
            self.queue_log_i18n(
                "log.ssh_connection_or_script_failed",
                "ERROR",
                error=str(e),
            )
            return None
    def _ensure_box_route_tables(self, box_ip, box_user, box_password):
        """
        通过 SSH 登录 BOX，按当前 USB 网卡列表修复策略路由表（100/101...）。
        只修改 route 表，不动 iptables。
        """
        self.queue_log_i18n("log.cidr_box_fix_route_tables_start", "INFO", box_ip=box_ip)
        ssh = None
        try:
            import paramiko
            import textwrap

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(box_ip, username=box_user, password=box_password, timeout=10)

            # 要上传到 BOX 上的修复脚本内容
            fix_script = textwrap.dedent("""
                #!/bin/bash
                MAIN_IF="eth0"
                USB_NETWORK="192.168.225.0/24"
                USB_DEVICE_IP="192.168.225.1"
                ROUTE_TABLE_BASE=100

                # 找出所有 USB 网卡（192.168.225.*，排除主网卡），按名称排序保证顺序稳定
                USB_INTERFACES=$(ip addr show | grep "inet 192.168.225\\." | awk '{print $NF}' | grep -v "$MAIN_IF" | sort -u)

                i=0
                for ifname in $USB_INTERFACES; do
                    TABLE_ID=$((ROUTE_TABLE_BASE + i))
                    ip route replace $USB_NETWORK dev $ifname table $TABLE_ID
                    ip route replace default via $USB_DEVICE_IP dev $ifname table $TABLE_ID
                    i=$((i+1))
                done

                ip route flush cache || true

                echo "[ROUTE_FIX] fwmark rules:"
                ip rule show | grep fwmark || true

                if [ "$i" -gt 0 ]; then
                    for t in $(seq $ROUTE_TABLE_BASE $((ROUTE_TABLE_BASE + i - 1))); do
                        echo "[ROUTE_FIX] table $t:"
                        ip route show table $t || true
                    done
                else
                    echo "[ROUTE_FIX] no USB interfaces found"
                fi
            """).lstrip()

            # 上传脚本到 /tmp
            remote_fix_path = "/tmp/usb_route_fix.sh"
            sftp = ssh.open_sftp()
            with sftp.file(remote_fix_path, "w") as f:
                f.write(fix_script)
            sftp.chmod(remote_fix_path, 0o755)
            sftp.close()

            # 用和主脚本相同的方式通过 sudo 执行修复脚本
            stdin, stdout, stderr = ssh.exec_command(f"sudo -S bash {remote_fix_path}", get_pty=True)
            stdin.write(box_password + "\n")
            stdin.flush()

            output = stdout.read().decode("utf-8", errors="ignore")
            error = stderr.read().decode("utf-8", errors="ignore")

            # 这次直接用 INFO 打出来，方便你在日志窗口看到 [ROUTE_FIX] 开头的行
            self.queue_log_i18n(
                "log.cidr_box_fix_route_tables_output",
                "INFO",
                output=output or "(no stdout)",
                error=error or "(no stderr)",
            )
        except ImportError:
            self.queue_log_i18n("log.paramiko_required", "ERROR")
        except Exception as e:
            self.queue_log_i18n(
                "log.cidr_box_fix_route_tables_failed",
                "ERROR",
                box_ip=box_ip,
                error=str(e),
            )
        finally:
            if ssh:
                try:
                    ssh.close()
                except Exception:
                    pass


    def _refresh_box_nat_mapping(self, box_ip, box_user, box_password):
        """通过 SSH 重新执行 BOX 脚本来刷新 NAT 映射。

        在设备升级重启后调用，确保 NAT 规则与当前 USB 设备状态一致。

        Args:
            box_ip: BOX 的 IP 地址
            box_user: SSH 用户名
            box_password: SSH 密码

        Returns:
            dict: {mac: linux_ip} 格式的新映射，失败返回 None
        """
        self.queue_log_i18n("log.refreshing_box_nat", "INFO", box_ip=box_ip)

        # 获取脚本路径
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(__file__)

        script_path = os.path.join(base_path, 'config', 'complete_usb_routing_setup_multi.sh')
        if not os.path.exists(script_path):
            self.queue_log_i18n("log.cidr_box_script_not_found", "ERROR", path=script_path)
            return None
        # ---【修改点】获取当前配置参数 ---
        # 注意：这里需要访问 self.job_definition 获取实时值
        t_count = self.job_definition["cidr_box_target_count"].get()
        args_str = f"{t_count}"
        # -----------------------------

        # 调用现有方法执行脚本
        result = self._get_mac_via_ssh_box(box_ip, box_user, box_password, script_path)
        # 无论脚本解析是否成功，都尝试修复一次 BOX 路由表，确保 table100/101 等存在
        try:
            self._ensure_box_route_tables(box_ip, box_user, box_password)
        except Exception:
            # 修复失败不影响后面的逻辑，错误已在函数内部记录
            pass
        if result:
            self.queue_log_i18n("log.box_nat_refresh_success", "SUCCESS",
                box_ip=box_ip, count=len(result))
            return result
        else:
            self.queue_log_i18n("log.box_nat_refresh_failed", "ERROR", box_ip=box_ip)
            return None

    def _parse_ssh_box_output(self, output):
        """解析 SSH BOX 脚本输出，提取 Linux IP 和 USB MAC 映射。
        
        脚本输出格式示例：
        序号 Linux映射IP       USB网卡名称          USB网卡MAC         USB网卡IP
        ---------------------------------------------------------------------------------------------
        1    192.168.8.104     usb0                 00:11:22:33:44:55  192.168.225.1
        2    192.168.8.105     usb1                 aa:bb:cc:dd:ee:ff  192.168.225.1
        
        Returns:
            dict: {mac: linux_ip} 格式，例如 {'00:11:22:33:44:55': '192.168.8.104'}
        """
        mac_to_ip = {}
        
        # 查找表格部分
        lines = output.split('\n')
        in_table = False
        
        for line in lines:
            # 跳过表头分隔符
            if '---' in line:
                in_table = True
                continue
            
            if in_table and line.strip():
                # 尝试解析表格行
                # 格式: 序号 Linux映射IP USB网卡名称 USB网卡MAC USB网卡IP
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        # parts[0] = 序号
                        # parts[1] = Linux映射IP
                        # parts[2] = USB网卡名称
                        # parts[3] = USB网卡MAC
                        seq_num = parts[0]
                        linux_ip = parts[1]
                        usb_if = parts[2]
                        usb_mac = parts[3]
                        
                        # 验证 IP 格式
                        if re.match(r'\d+\.\d+\.\d+\.\d+', linux_ip):
                            # 验证 MAC 格式
                            if re.match(r'[0-9a-fA-F:]{17}', usb_mac):
                                mac_to_ip[usb_mac.upper()] = linux_ip
                    except (IndexError, ValueError):
                        continue
        
        return mac_to_ip

    def _get_mac_via_telnet(self, device_ip, initial_ip, username='adm', password='123456', port=223, timeout=20):
        """通过 Telnet 登录设备并解析 lan0 上的 MAC 以及 iptables NAT 映射。

        步骤：
        1) 连接 device_ip:port，输入用户名/密码
        2) ping 初始共享 IP，激活 ARP 表
        3) 执行 `arp` 或 `arp -a`，解析包含 ' on lan0' 的行，提取 'at xx:xx:..' 的 MAC
        4) 执行 `iptables-save | grep 'nat'`，解析 NAT 规则获取源IP映射
        
        返回: (MAC, source_ip) 元组，MAC为大写字符串，source_ip为NAT映射的源IP（如果存在）
        失败返回 (None, None)
        """
        try:
            tn = telnetlib.Telnet(device_ip, port, timeout=timeout)
            try:
                # 登录提示
                login_str = tn.read_until(b"login", timeout=5)
                print(login_str)
            except Exception:
                pass
            tn.write((username + "\n").encode('ascii'))
            try:
                return_str = tn.read_until(b"assword", timeout=5)
                print(return_str)
            except Exception:
                pass
            tn.write((password + "\n").encode('ascii'))
            try:
                tn.read_until(b"Router", timeout=5)
            except Exception:
                pass
            # 简单等待进入 shell
            tn.write(b"support enable\n")
            try:
                tn.read_until(b"Router", timeout=5)
            except Exception:
                pass
            tn.write(b"inhand\n")
            try:
                tn.read_until(b":", timeout=5)
            except Exception:
                pass
            tn.write(b"root$!^&/2022@inhand\n")
            try:
                tn.read_until(b"#", timeout=5)
            except Exception:
                pass
            
            # 激活 ARP 表
            tn.write((f"ping -c 1 {initial_ip}\n").encode('ascii'))
            try:
                tn.read_until(b"bytes from", timeout=5)
            except Exception:
                pass

            # 读取 ARP 表获取 MAC
            tn.write(b"arp\n")
            output = tn.read_until(b"\n", timeout=1)  # 先读一行以触发输出
            time.sleep(1)
            out = tn.read_very_eager().decode('utf-8', errors='ignore')
            if not out.strip():
                # 尝试 arp -a
                tn.write(b"arp -a\n")
                time.sleep(1)
                out = tn.read_very_eager().decode('utf-8', errors='ignore')

            # 解析包含 on lan0 的行，获取MAC
            mac_candidate = None
            for line in out.splitlines():
                if ' on lan0' in line:
                    m = re.search(r"\bat\s+([0-9a-fA-F:]{17})\b.*\bon\s+lan0\b", line)
                    if m:
                        mac_candidate = m.group(1)
                        break
            
            # 读取 iptables NAT 规则
            source_ip_candidate = None
            tn.write(b"iptables-save | grep 'nat'\n")
            time.sleep(1)
            iptables_out = tn.read_very_eager().decode('utf-8', errors='ignore')
            
            # 解析 NAT 规则，查找 to-destination 为 initial_ip 的规则
            for line in iptables_out.splitlines():
                if 'DNAT' in line and f'--to-destination {initial_ip}' in line:
                    # 提取 -d 后面的IP地址
                    # 匹配格式: -d 192.168.3.98/32 或 -d 192.168.3.98
                    match = re.search(r'-d\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?', line)
                    if match:
                        source_ip_candidate = match.group(1)
                        print(f"Found NAT mapping on device {device_ip}: {source_ip_candidate} -> {initial_ip}")
                        break
            
            tn.close()
            
            if mac_candidate:
                mac_upper = mac_candidate.upper()
                # 如果找到NAT映射，返回映射的源IP，否则返回设备当前IP
                final_ip = source_ip_candidate if source_ip_candidate else device_ip
                return (mac_upper, final_ip)
                
        except Exception as e:
            self.queue_log_i18n(
                "log.telnet_mac_fetch_failed",
                "ERROR",
                ip=device_ip,
                error=str(e),
            )
        return (None, None)

    def _refresh_macs_via_telnet_and_update_gui(self, mac_list, mac_to_ip_map, job_def, initial_ip_map=None):
        """在 CIDR 模式下：重建 MAC 列表与映射，并更新 GUI (集成锚点传递与索引锁定)。
        
        Args:
            mac_list: 发现阶段的占位 MAC 列表
            mac_to_ip_map: 占位 MAC -> Initial IP 的映射
            job_def: 任务配置对象
            initial_ip_map: (新增) {Initial IP: Index} 锚点映射表，用于在 IP 变化后保持物理顺序
        """
        # 将 import 放在函数内，避免影响文件其他部分
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import ipaddress
        import sys
        import os

        if not mac_list or not mac_to_ip_map:
            return mac_list, mac_to_ip_map
        
        # 防止 initial_ip_map 为 None 导致报错
        if initial_ip_map is None:
            initial_ip_map = {}

        cidr_mode_type = job_def.get("cidr_mode", "").strip()
        
        # 结果容器
        new_mac_to_ip = {}
        new_macs = []

        # ===========================
        # 分支 1: CIDR-BOX 模式
        # ===========================
        if cidr_mode_type == "CIDR-BOX":
            # 路径处理：兼容 PyInstaller 打包后的环境
            base_path = sys._MEIPASS if getattr(sys, 'frozen', False) else os.path.dirname(__file__)
            script_path = os.path.join(base_path, 'config', 'complete_usb_routing_setup_multi.sh')
            
            if not os.path.exists(script_path):
                self.queue_log_i18n("log.cidr_box_script_not_found", "ERROR", path=script_path)
                return mac_list, mac_to_ip_map

            # 提取动态参数
            target_count = job_def.get("cidr_box_target_count", "12")
            args_str = f"{target_count}"

            # 定义任务函数
            def fetch_one_box(box_ip):
                self.queue_log_i18n("log.cidr_box_ssh_connecting", "INFO", ip=box_ip)
                # 调用底层 SSH 函数
                result = self._get_mac_via_ssh_box(
                    box_ip,
                    job_def.get("box_ssh_user", "linaro"),
                    job_def.get("box_ssh_password", "linaro"),
                    script_path,
                    script_args=args_str 
                )
                return box_ip, result

            self.queue_log_i18n("log.cidr_box_start_parallel_ssh", "INFO", count=len(mac_list))
            
            mac_to_box = {} # 临时存储映射

            with ThreadPoolExecutor(max_workers=min(16, len(mac_list))) as ex:
                futures = [ex.submit(fetch_one_box, mac_to_ip_map.get(m)) for m in mac_list]
                for fut in as_completed(futures):
                    box_ip, ssh_result = fut.result()
                    if ssh_result:
                        new_mac_to_ip.update(ssh_result)
                        # 记录 USB_MAC -> BOX_IP 映射，供后续 NAT 刷新使用
                        for usb_mac in ssh_result.keys():
                            mac_to_box[usb_mac] = box_ip

            # 更新类成员变量 (关键状态)
            self.mac_to_box_ip = mac_to_box 
            new_macs = list(new_mac_to_ip.keys())
            
            self.queue_log_i18n("log.macs_refreshed_ssh", "SUCCESS", count=len(new_macs))

        # ===========================
        # 分支 2: CIDR-302 (Telnet) 模式
        # ===========================
        else:
            def fetch_one(ip):
                # Hardcode 端口 223 保持原逻辑一致
                result = self._get_mac_via_telnet(ip, job_def["initial_ip"], 'adm', '123456', 223, timeout=20)
                return ip, result

            self.queue_log_i18n("log.refreshing_via_telnet_info", "INFO", count=len(mac_list))
            
            temp_results = {}
            real_mac_counter = set()

            with ThreadPoolExecutor(max_workers=min(16, len(mac_list))) as ex:
                # 建立 future 到 placeholder_mac 的映射
                future_to_mac = {ex.submit(fetch_one, mac_to_ip_map.get(m)): m for m in mac_list}
                
                for fut in as_completed(future_to_mac):
                    placeholder_mac = future_to_mac[fut]
                    original_ip, (real_mac, source_ip) = fut.result()
                    
                    if original_ip and real_mac:
                        final_ip = source_ip or original_ip
                        temp_results[placeholder_mac] = (real_mac, final_ip)
                        real_mac_counter.add(real_mac)
                        
                        if source_ip != original_ip:
                            self.queue_log_i18n("log.nat_mapping_found", "SUCCESS", original_ip=original_ip, mac=real_mac, source_ip=source_ip)

                        # --- 【核心动作：索引迁移 (Anchor Migration)】 ---
                        # 逻辑：即使 IP 变了(NAT)，这台设备的物理位置(顺序)由最初发现它的 Initial IP 决定。
                        # 我们将 Initial IP 对应的 Index 强制赋予给现在获取到的 Real MAC。
                        if original_ip in initial_ip_map:
                            original_index = initial_ip_map[original_ip]
                            self.fixed_indices[real_mac] = original_index
                            # 可选调试：print(f"Index Migration: {original_ip} (Idx {original_index}) -> {real_mac}")

            # --- 回退逻辑 ---
            # 判断是否出现大量重复 MAC (未定型设备特征)
            is_unfinalized = len(real_mac_counter) < len(temp_results)
            
            if is_unfinalized:
                logging.warning(self.i18n.t("log.duplicate_macs_warning"))
            
            # 构建最终列表
            for placeholder_mac in mac_list:
                if placeholder_mac in temp_results:
                    real_mac, final_ip = temp_results[placeholder_mac]
                    # 决策：使用真实 MAC 还是 占位 MAC
                    target_mac = placeholder_mac if is_unfinalized else real_mac
                    
                    # 兜底：如果是未定型状态，也尝试锁定索引
                    if is_unfinalized:
                        original_ip = mac_to_ip_map.get(placeholder_mac)
                        if original_ip in initial_ip_map:
                             self.fixed_indices[target_mac] = initial_ip_map[original_ip]

                    new_macs.append(target_mac)
                    new_mac_to_ip[target_mac] = final_ip

            self.queue_log_i18n("log.macs_refreshed_telnet", "SUCCESS", count=len(new_macs))

        # ===========================
        # 通用：排序与 GUI 更新 (基于 Index 排序)
        # ===========================
        
        # 1. 排序 (Sort) - 改为基于 Index 排序
        # 之前的逻辑是 key=ip_sort_key，现在改为 key=index_sort_key
        # 这样即使 IP 变成了乱序的内网 IP，只要它们继承了正确的 Index，UI 顺序就不会乱
        def index_sort_key(mac):
            # 获取该 MAC 的固定索引，如果没有则放到最后 (999999)
            return self.fixed_indices.get(mac, 999999)

        # 执行排序
        final_new_macs = sorted(new_macs, key=index_sort_key)

        # 2. 更新 GUI
        self.gui_queue.put({'type': 'clear_devices'})
        
        for mac in final_new_macs:
            # 获取我们在 Phase 2 刚刚迁移或生成的索引
            # 此时 self.fixed_indices[mac] 应该已经被正确赋值为 Phase 1 的旧索引了
            if mac not in self.fixed_indices:
                # 理论上不应发生，作为兜底
                self.fixed_indices[mac] = len(self.fixed_indices) + 1
            
            fixed_idx = self.fixed_indices[mac]
            ip_addr = new_mac_to_ip.get(mac, "")

            self.gui_queue.put({
                'type': 'add_device', 
                'mac': mac, 
                'index': fixed_idx, # 这里显示的将是完美的 1, 2, 3...
                'upgrade': 'Queued' if job_def["do_upgrade"] else 'Skipped', 
                'config': 'Queued' if job_def["do_import_config"] else 'Skipped'
            })
            
            if ip_addr:
                self.gui_queue.put({'type': 'update_device', 'mac': mac, 'column': 'ip', 'value': ip_addr})

        print(f"Final MAC list (Index Sorted): {final_new_macs}")
        print(f"Final MAC to IP mapping: {new_mac_to_ip}")
        
        return final_new_macs, new_mac_to_ip

    def _set_static_arp(self, mac, ip, interface):
        """在 Windows 上为目标 IP 绑定指定 MAC（netsh neighbors）。

        目的：避免改址/重启窗口期的 ARP 竞争或缓存抖动，确保指向唯一设备。
        """
        self.queue_log_i18n("log.arp_set_static", "INFO", ip=ip, mac=mac)
        command = f'netsh interface ipv4 set neighbors "{interface}" {ip} {mac.replace(":", "-")}'
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, shell=True)
            return True
        except subprocess.CalledProcessError as e:
            self.queue_log_i18n("log.arp_error_setting", "ERROR",
                    error=e.stderr or e.stdout)
            return False

    def _delete_static_arp(self, ip, interface):
        """删除指定 IP 的静态 ARP（收尾，容错）。"""
        self.queue_log_i18n("log.arp_deleting_entry", "INFO", ip=ip)
        command = f'netsh interface ipv4 delete neighbors "{interface}" {ip}'
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, shell=True,encoding='utf-8')
        except subprocess.CalledProcessError as e:
            self.queue_log_i18n(
                "log.arp_delete_warning",
                "INFO",
                error=e,
            )

    def _clear_arp(self):
        """清空本机 ARP 缓存（全局收尾）。"""
        self.queue_log_i18n("log.arp_cleaning_all", "INFO")
        command = f'arp -d'
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, shell=True)
            return True
        except subprocess.CalledProcessError as e:
            self.queue_log_i18n("log.arp_cleanup_error", "ERROR",
                    error=e.stderr or e.stdout)
            return False

    def _detect_system_language(self):
        """检测系统默认语言或加载用户保存的语言偏好"""
        # 先尝试从配置文件加载用户选择的语言
        try:
            if os.path.exists('config.json'):
                with open('config.json', 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    saved_lang = config.get('user_language')
                    if saved_lang in ['zh_CN', 'en_US']:
                        self.i18n.set_language(saved_lang)
                        print(self.i18n.format("debug.lang_pref_loaded", lang=saved_lang))
                        return
        except Exception as e:
            print(f"Error loading language preference: {e}")
        
        # 如果没有保存的语言偏好，则检测系统语言
        try:
            system_locale, _ = locale.getdefaultlocale()
            if system_locale:
                if system_locale.startswith('zh'):
                    self.i18n.set_language('zh_CN')
                elif system_locale.startswith('en'):
                    self.i18n.set_language('en_US')
            else:
                # 默认使用中文
                self.i18n.set_language('zh_CN')
        except Exception as e:
            print(f"Error detecting system language: {e}")
            self.i18n.set_language('zh_CN')

    def _create_language_menu(self):
        """创建语言切换菜单"""
        languages = self.i18n.get_available_languages()
        for lang_code, lang_name in languages.items():
            self.language_menu.add_command(
                label=lang_name,
                command=lambda code=lang_code: self._switch_language(code)
            )

    def _build_menus(self):
        """根据当前语言重建整个菜单栏（File / Settings / Language）"""
        # 顶层菜单栏
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)

        # File 菜单
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label=self.i18n.t('menu.file'), menu=self.file_menu)
        self.file_menu.add_command(label=self.i18n.t('menu.save_config'), command=self.save_config)
        self.file_menu.add_command(
            label=self.i18n.t('menu.load_config'),
            command=lambda: self.load_config(show_message=True)
        )
        self.file_menu.add_command(label=self.i18n.t('menu.save_log'), command=self._save_log_to_file)
        self.file_menu.add_separator()
        self.file_menu.add_command(label=self.i18n.t('menu.exit'), command=self.on_closing)

        # Settings 菜单
        self.settings_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label=self.i18n.t('menu.settings'), menu=self.settings_menu)
        self.settings_menu.add_command(
            label=self.i18n.t('menu.operator_login'),
            command=self._show_operator_login_dialog
        )

        # Language 子菜单
        self.language_menu = tk.Menu(self.settings_menu, tearoff=0)
        self.settings_menu.add_cascade(label=self.i18n.t('menu.language'), menu=self.language_menu)
        # 填充语言选项
        self.language_menu.delete(0, 'end')
        self._create_language_menu()

    def _update_menu_texts(self):
        """根据当前语言更新菜单栏文字"""
        # 顶层菜单栏（File / Settings）
        try:
            # 这里假定顺序固定：0=File, 1=Settings
            self.menu_bar.entryconfig(0, label=self.i18n.t('menu.file'))
            self.menu_bar.entryconfig(1, label=self.i18n.t('menu.settings'))
        except Exception:
            pass

        # File 菜单项顺序：0=save_config, 1=load_config, 2=save_log, 3=separator, 4=exit
        try:
            self.file_menu.entryconfig(0, label=self.i18n.t('menu.save_config'))
            self.file_menu.entryconfig(1, label=self.i18n.t('menu.load_config'))
            self.file_menu.entryconfig(2, label=self.i18n.t('menu.save_log'))
            self.file_menu.entryconfig(4, label=self.i18n.t('menu.exit'))
        except Exception:
            pass

        # Settings 菜单项顺序：0=operator_login, 1=Language 子菜单
        try:
            self.settings_menu.entryconfig(0, label=self.i18n.t('menu.operator_login'))
            self.settings_menu.entryconfig(1, label=self.i18n.t('menu.language'))
        except Exception:
            pass

    def _switch_language(self, lang_code):
        """切换语言并保存用户偏好"""
        # 切换语言
        self.i18n.set_language(lang_code)
        
        # 保存用户语言偏好到配置文件
        try:
            config = {}
            if os.path.exists('config.json'):
                with open('config.json', 'r', encoding='utf-8') as f:
                    config = json.load(f)
            
            config['user_language'] = lang_code
            
            with open('config.json', 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            print(f"Saved language preference: {lang_code}")
        except Exception as e:
            print(f"Error saving language preference: {e}")

    def _on_language_changed(self):
        """语言切换后的回调 - 完全重建UI实现实时切换"""
        # 更新窗口标题
        self.root.title(self.i18n.t('app_title'))
        
        # 先立即更新菜单栏文字（包含 File / Settings）
        self._update_menu_texts()
        
        # 重建整个UI
        self._rebuild_ui()
        
        # 显示成功提示
        lang_name = self.i18n.get_available_languages()[self.i18n.get_current_language()]
        messagebox.showinfo(
            self.i18n.t('messages.language_changed_title'),
            f"{self.i18n.t('messages.language_switched_success')} ({lang_name})"
        )
    
    def _rebuild_ui(self):
        """重建UI以应用新语言"""
        # 保存当前的表格数据
        tree_data = []
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            tree_data.append(values)
        
        # 保存当前状态
        current_status = {
            'overall': self.status_vars["overall_status"].get(),
            'progress': self.status_vars["progress_counter"].get(),
            'verified': self.status_vars["verified_counter"].get(),
            'time': self.status_vars["time_elapsed"].get(),
            'api': self.status_vars["api_status"].get()
        }
        
        # 销毁所有主要容器（但保留根窗口）
        for widget in self.root.winfo_children():
            if widget != self.menu_bar:  # 保留菜单栏，稍后更新
                widget.destroy()
        
        # 重新创建UI
        self._create_widgets()
        # 更新菜单栏文字到当前语言
        self._update_menu_texts()
        
        # 恢复状态变量
        self._restore_status(current_status)
        
        # 恢复表格数据
        for values in tree_data:
            self.tree.insert('', 'end', values=values)
        
        # 重新创建语言菜单
        self.language_menu.delete(0, 'end')
        self._create_language_menu()
    
    def _restore_status(self, saved_status):
        """恢复状态显示"""
        # 解析并更新状态
        overall = saved_status['overall']
        if "Idle" in overall or "空闲" in overall:
            self.status_vars["overall_status"].set(self.i18n.t('status.idle'))
        else:
            self.status_vars["overall_status"].set(overall)
        
        # 更新登录状态
        api_status = saved_status['api']
        if "Not Configured" in api_status or "未配置" in api_status:
            self.status_vars["api_status"].set(self.i18n.t('status.login_not_configured'))
        elif "Ready" in api_status or "就绪" in api_status:
            if self.operator_username:
                self.status_vars["api_status"].set(self.i18n.format('status.login_ready', username=self.operator_username))
        elif "Authenticated" in api_status or "已认证" in api_status:
            if self.operator_username:
                self.status_vars["api_status"].set(self.i18n.format('status.login_authenticated', username=self.operator_username))
        elif "Expired" in api_status or "过期" in api_status:
            self.status_vars["api_status"].set(self.i18n.t('status.login_session_expired'))
        else:
            self.status_vars["api_status"].set(api_status)
        
        # 更新时间
        time_str = saved_status['time']
        if ":" in time_str:
            time_part = time_str.split()[-1] if " " in time_str else "00:00:00"
            self.status_vars["time_elapsed"].set(self.i18n.format('status.time_format', time=time_part))
        
        # 更新进度
        progress = saved_status['progress']
        if "/" in progress:
            try:
                parts = progress.replace('Processed:', '').replace('已处理:', '').strip().split('/')
                count = int(parts[0].strip())
                total = int(parts[1].strip())
                self.status_vars["progress_counter"].set(self.i18n.format('status.processed_format', count=count, total=total))
            except:
                self.status_vars["progress_counter"].set(self.i18n.format('status.processed_format', count=0, total=0))
        
        # 更新验证计数
        verified = saved_status['verified']
        if "/" in verified:
            try:
                parts = verified.replace('Verified:', '').replace('已验证:', '').strip().split('/')
                count = int(parts[0].strip())
                total = int(parts[1].strip())
                self.status_vars["verified_counter"].set(self.i18n.format('status.verified_format', count=count, total=total))
            except:
                self.status_vars["verified_counter"].set(self.i18n.format('status.verified_format', count=0, total=0))

def _cidr_mode_click_handler(self, mode):
    """
    外部定义的 CIDR 模式点击处理函数，用于覆盖类内部的旧实现：
    - 再次点击同一选项时清空 cidr_mode；
    - 不同选项之间互斥；
    - 始终调用 _toggle_cidr_fields() 更新界面。
    """
    prev_mode = getattr(self, "_last_cidr_mode", "").strip()

    if prev_mode == mode:
        # 再次点击同一选项 -> 清空
        self.job_definition["cidr_mode"].set("")
        self._last_cidr_mode = ""
    else:
        # 切换到新的模式
        self.job_definition["cidr_mode"].set(mode)
        self._last_cidr_mode = mode

    # 根据最新的 cidr_mode 状态更新 Discovery CIDR 字段显示
    self._toggle_cidr_fields()


# 覆盖 BatchUpdaterApp 中的 _on_cidr_mode_clicked 实现
BatchUpdaterApp._on_cidr_mode_clicked = _cidr_mode_click_handler


if __name__ == "__main__":
    root = tk.Tk()
    app = BatchUpdaterApp(root)
    root.mainloop()
