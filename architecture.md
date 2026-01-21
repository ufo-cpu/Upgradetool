# Software Architecture: Router Batch Management Tool

## 1. Overview

This document outlines the software architecture for the Router Batch Management Tool. The application is a professional-grade utility designed to automate the process of re-addressing, upgrading firmware, importing configurations, and reporting results for a large number of routers.

The architecture is built on a multi-threaded, producer-consumer model to ensure the Graphical User Interface (GUI) remains responsive. It uses a **Strategy Pattern** via a model factory to dynamically handle different router models, making the tool scalable and easy to maintain.

The core workflow is a **four-phase process**:
1.  **Phase 1 (Sequential Re-addressing):** All routers, which initially share the same IP address, are sequentially isolated and assigned a new, unique IP.
2.  **Phase 2 (Parallel Tasks):** A pool of worker threads performs user-selected tasks (e.g., firmware upgrade, configuration import) in parallel on the now-uniquely-addressed routers.
3.  **Phase 3 (Sequential Verification):** An optional, sequential verification step confirms the final state of the devices after all tasks and reboots are complete.
4.  **Phase 4 (MES Reporting):** An optional, final reporting step that sends the results of a successful upgrade job to a Manufacturing Execution System (MES).

---

## 2. Core Components

The application is composed of several primary components:

### 2.1. The GUI (The "Control Panel")

The GUI is the user's interface for setting up and monitoring the batch job. It runs exclusively in the main thread.

*   **Technology:** Tkinter with `ttk` themed widgets.
*   **Key Features:**
    *   **Menu Bar:** Provides access to application-level settings like saving/loading job templates and the Operator Login.
    *   **Dynamic Configuration:** The main panel allows for detailed job definition, including model selection, IP ranges, task selection, and credentials.
    *   **Real-Time Status:** A multi-faceted status display includes an overall status message, an elapsed time counter, progress counters for processed and verified devices, and a multi-stage progress bar.
    *   **Detailed Results Table:** A `Treeview` widget displays the per-device status for each stage of the process.
    *   **Log Window:** A large, scrolled text area for detailed, timestamped logs from all threads.

### 2.2. The Orchestrator (The "Job Dispatcher")

This is the main worker thread (`orchestrator_logic`) that manages the entire lifecycle of the batch process.

*   **Responsibilities:**
    *   Gathers the complete job definition from the GUI.
    *   **Automatic Network Detection:** Intelligently discovers the correct local network interface to use by matching subnets; it does not require user input.
    *   **Device Discovery:** Uses Scapy to perform an ARP scan and discover all target devices.
    *   **Credential Management:** Manages both static and dynamic credentials.
        *   **Static Mode:** Uses a single username/password from the UI.
        *   **Dynamic Mode:** Performs a "Pre-Flight Credential Fetch," calling a secure API for each device to build a map of credentials before starting any work.
    *   Executes the sequential **Phase 1 (IP Re-addressing)**, now hardened with a TCP check to ensure device readiness.
    *   Manages a thread pool of workers for **Phase 2 (Parallel Tasks)**.
    *   Manages the optional **Phase 3 (Verification)** and **Phase 4 (MES Reporting)**.

### 2.3. The "Model Handler" Architecture (Strategy Pattern)

This component makes the tool extensible. The logic for handling each router model is encapsulated in its own "handler" class, loaded dynamically by a factory.

*   **The "Contract" (Interface):** Every handler class implements a common set of methods, such as:
    *   `change_ip(...)`
    *   `upgrade(...)`
    *   `import_config(...)`
    *   `restore_defaults(...)`
    *   `run_oem_action(...)`: An extensible method for running complex, multi-protocol (Telnet + Playwright) OEM-specific commands.
*   **The Model Factory (`model_factory.py`):** A central module responsible for discovering and instantiating the correct handler class at runtime.

### 2.4. The Worker Threads (The "Consumers")

A pool of up to 16 threads that execute the Phase 2 jobs in parallel.

*   **Workflow:**
    1.  Receives a complete "job package" from the Orchestrator's task queue, including the specific IP and credentials for one device.
    2.  Uses the `model_factory` to get the appropriate handler.
    3.  Launches a Playwright instance to perform the web automation tasks.
    4.  Calls the appropriate methods on the handler (`handler.upgrade()`, `handler.import_config()`, etc.).
    5.  The logic is optimized to prevent redundant information scraping if multiple tasks are selected.
    6.  Reports progress and success/failure back to the GUI via the logging queue.

### 2.5. Authentication and Session Management

The application includes a professional-grade, token-based authentication system for the operator.

*   **Operator Login:** A menu-driven dialog allows the operator to log in against a specific API endpoint (`/api/v1.0/get_token`).
*   **Token Management:** Upon successful login, the application securely stores a session token, a refresh token, and the token's expiry time in memory.
*   **Auto-Refreshing Token:** Before any authenticated API call is made, a central helper method (`_get_valid_auth_token`) checks if the session token is about to expire. If so, it automatically uses the refresh token to get a new session token, ensuring the session remains active seamlessly.
*   **Secure API Calls:** All subsequent API calls (for dynamic device passwords or MES reporting) are made with the secure session token in the `Authorization` header.

---

## 3. Workflow & Sequence of Events

1.  **Startup:** The GUI launches. It can optionally auto-load a saved job template from `config.json`.
2.  **Operator Login (Optional):** The user goes to `Settings -> Operator Login...` to authenticate against the API, establishing a secure session.
3.  **Job Definition:** The user selects a model and chooses tasks (Upgrade, Import/Restore). They provide static credentials or check "Use Dynamic Password API".
4.  **Start Batch:** The user clicks "Start Batch". The `Orchestrator` thread is launched.
5.  **Pre-Flight Checks:**
    *   The orchestrator auto-detects the correct network interface.
    *   It discovers all router MAC addresses via an ARP scan.
    *   If in dynamic password mode, it performs the "Pre-Flight Credential Fetch," calling the API for each MAC to build a credential map. Devices that fail this step are marked and skipped.
6.  **Phase 1 (Sequential Re-addressing):** For each device with valid credentials, the orchestrator performs a TCP readiness check, then uses Playwright to assign a new, unique IP address.
7.  **Phase 2 (Parallel Tasks):** The orchestrator populates a task queue with the device's new IP and its specific credentials. A pool of worker threads consumes this queue in parallel, performing the selected tasks.
8.  **Phase 3 (Parallel Verification):** If enabled, the orchestrator verifies the final state of the devices, using either a full web login or a simple TCP check, and optionally running a complex OEM-specific action.
9.  **Phase 4 (MES Reporting):** If enabled (by being logged in and having run an upgrade), the orchestrator gathers a list of all successful devices and makes the necessary API calls to the MES to report the results.
10. **Completion:** The orchestrator thread finishes, and the UI is reset to an idle state.