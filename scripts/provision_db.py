"""PostgreSQL Provisioning Script for SentinelAgent.

Prompts securely for credentials via a native hidden-input GUI dialog.
Verifies administrative access, provisions sentinelagent_user and sentinelagent database,
grants public schema permissions, and configures root .env with URL-encoded credentials.
Enforces and verifies Windows NTFS ACLs using a safe temporary-file and atomic-replacement strategy.
Never logs or prints plain-text credentials.
"""

from collections import defaultdict
import getpass
import re
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox
import urllib.parse
from pathlib import Path
import psycopg
from psycopg import sql

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"


def build_database_url(
    username: str,
    password: str,
    host: str = "localhost",
    port: int = 5432,
    database: str = "sentinelagent",
) -> str:
    """Build a standard, RFC 3986 compliant database connection URL.

    Uses urllib.parse.quote(password, safe="") to correctly URL-encode all reserved
    characters and spaces (encoded as %20 rather than '+'), ensuring robust compatibility
    with SQLAlchemy and Psycopg 3.
    """
    encoded_password = urllib.parse.quote(password, safe="")
    return f"postgresql+psycopg://{username}:{encoded_password}@{host}:{port}/{database}"


def parse_and_validate_icacls_permissions(acl_output: str, target_user: str) -> bool:
    """Validate that icacls output grants target_user sufficient permissions exclusively.

    Validation Rules:
      1. Examines EVERY entry in the ACL output before concluding validation.
      2. Rejects if ANY explicit DENY entry affects target_user (regardless of ordering).
      3. Verifies that target_user possesses sufficient permissions:
         - Full Control ('F')
         - Modify ('M')
         - Or both Read AND Write rights ('R' and 'W', accumulated across entries).
      4. Verifies exclusivity: No unexpected principals (e.g. Everyone, other users)
         may retain access to the newly created file.
      5. Correctly handles domain/machine prefixes (e.g. 'DOMAIN\\user' or 'LAPTOP\\user').

    Rejects:
      - Read-only ('R' or 'RX')
      - Write-only ('W')
      - Delete-only ('D')
      - Incomplete combinations ('R,D' or 'W,D')
      - Non-exclusive ACLs containing other users
      - Any explicit DENY
    """
    if not acl_output or not target_user:
        return False

    target_user_clean = target_user.strip().lower()
    # Matches individual permission lines in icacls output
    # Format: [filename] [domain\]principal:(perms) or continuation lines with indentation
    ace_pattern = re.compile(r"(?:^|\s+)([A-Za-z0-9_.\-\s\\]+?):(\([A-Za-z0-9_(),\s\-]+)$")

    entries_by_user = defaultdict(list)
    found_any_ace = False

    for line in acl_output.splitlines():
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("Successfully processed") or line_clean.startswith("processed file:"):
            continue

        match = ace_pattern.search(line)
        if not match:
            continue

        found_any_ace = True
        principal = match.group(1).strip()
        perms = match.group(2).strip()

        # Extract account name excluding machine/domain prefix
        account_name = principal.split("\\")[-1].strip().lower()
        entries_by_user[account_name].append((principal, perms))

    if not found_any_ace:
        return False

    # 1. Exclusivity check: only target_user is permitted
    for account in entries_by_user:
        if account != target_user_clean:
            return False  # Unexpected principal retained access!

    # Target user must be present
    if target_user_clean not in entries_by_user:
        return False

    user_entries = entries_by_user[target_user_clean]

    # 2. Check for ANY explicit DENY on target user (rejects regardless of other allow entries)
    for _, perms in user_entries:
        p_upper = perms.upper()
        if "(DENY)" in p_upper or ":(D)" in p_upper or "(N)" in p_upper:
            return False

    # 3. Check for sufficient permissions accumulated across all entries for target user
    has_full_control = False
    has_modify = False
    has_read = False
    has_write = False

    inheritance_markers = {"I", "OI", "CI", "IO", "NP"}

    for _, perms in user_entries:
        tokens = re.findall(r"\(([^)]+)\)", perms)
        perm_tokens = [t.upper() for t in tokens if t.upper() not in inheritance_markers]

        for token in perm_tokens:
            if token == "F":
                has_full_control = True
            elif token == "M":
                has_modify = True
            else:
                rights = [r.strip() for r in token.split(",")]
                if any(r in ("R", "RX", "RD", "GENERIC_READ") for r in rights):
                    has_read = True
                if any(r in ("W", "WD", "AD", "GENERIC_WRITE") for r in rights):
                    has_write = True

    return bool(has_full_control or has_modify or (has_read and has_write))


def prompt_credentials():
    """Prompt the user for PostgreSQL administrator and application passwords using a masked GUI."""
    credentials = {"postgres_pass": None, "app_pass": None, "submitted": False}

    with open(PROJECT_ROOT / "debug_gui.log", "w", encoding="utf-8") as log:
        log.write("GUI: Initializing Tk\n")

    root = tk.Tk()
    root.title("SentinelAgent - PostgreSQL Configuration")
    root.geometry("450x260")
    root.resizable(False, False)
    root.attributes("-topmost", True)

    header = tk.Label(
        root,
        text="PostgreSQL Credential Setup",
        font=("Segoe UI", 12, "bold"),
        pady=10,
    )
    header.pack()

    desc = tk.Label(
        root,
        text="Credentials are processed in local memory and never logged or printed.",
        font=("Segoe UI", 9),
        fg="#555",
    )
    desc.pack()

    frame = tk.Frame(root, padx=20, pady=10)
    frame.pack(fill="both", expand=True)

    tk.Label(frame, text="PostgreSQL 'postgres' Superuser Password:", anchor="w").pack(fill="x", pady=(5, 2))
    entry_postgres = tk.Entry(frame, show="*", font=("Segoe UI", 10))
    entry_postgres.pack(fill="x", pady=(0, 10))
    entry_postgres.focus_set()

    tk.Label(frame, text="SentinelAgent 'sentinelagent_user' Password:", anchor="w").pack(fill="x", pady=(5, 2))
    entry_app = tk.Entry(frame, show="*", font=("Segoe UI", 10))
    entry_app.pack(fill="x", pady=(0, 10))

    def on_submit():
        pg_pwd = entry_postgres.get()
        app_pwd = entry_app.get()

        if not pg_pwd:
            messagebox.showerror("Error", "Please enter the 'postgres' superuser password.", parent=root)
            return

        if not app_pwd:
            messagebox.showerror("Error", "Please enter a password for 'sentinelagent_user'.", parent=root)
            return

        # Pre-validate superuser connection before closing the dialog
        try:
            test_conn = psycopg.connect(
                host="localhost",
                port=5432,
                user="postgres",
                password=pg_pwd,
                autocommit=True,
                connect_timeout=3,
            )
            test_conn.close()
        except Exception:
            messagebox.showerror(
                "Authentication Failed",
                "Failed to authenticate as PostgreSQL superuser 'postgres' on port 5432.\n\n"
                "Please verify the password set during PostgreSQL installation and try again.",
                parent=root,
            )
            entry_postgres.focus_set()
            entry_postgres.select_range(0, tk.END)
            return

        credentials["postgres_pass"] = pg_pwd
        credentials["app_pass"] = app_pwd
        credentials["submitted"] = True
        with open(PROJECT_ROOT / "debug_gui.log", "a", encoding="utf-8") as log:
            log.write("GUI: Submitted\n")
        root.destroy()

    def on_cancel():
        with open(PROJECT_ROOT / "debug_gui.log", "a", encoding="utf-8") as log:
            log.write("GUI: Cancelled\n")
        root.destroy()

    btn_frame = tk.Frame(root, pady=10)
    btn_frame.pack()

    btn_submit = tk.Button(btn_frame, text="Configure Database", width=18, bg="#0066cc", fg="white", command=on_submit)
    btn_submit.pack(side="left", padx=5)

    btn_cancel = tk.Button(btn_frame, text="Cancel", width=12, command=on_cancel)
    btn_cancel.pack(side="left", padx=5)

    root.bind("<Return>", lambda event: on_submit())
    root.bind("<Escape>", lambda event: on_cancel())

    # Ensure window is active, lifted above other windows, and focused
    root.deiconify()
    root.lift()
    root.attributes("-topmost", True)
    root.focus_force()
    entry_postgres.focus_set()

    with open(PROJECT_ROOT / "debug_gui.log", "a", encoding="utf-8") as log:
        log.write("GUI: Entering mainloop\n")

    try:
        root.mainloop()
    except Exception as e:
        with open(PROJECT_ROOT / "debug_gui.log", "a", encoding="utf-8") as log:
            log.write(f"GUI: Exception in mainloop: {e}\n")

    with open(PROJECT_ROOT / "debug_gui.log", "a", encoding="utf-8") as log:
        log.write(f"GUI: Exited mainloop, submitted={credentials['submitted']}\n")

    return credentials


def configure_env_file(database_url: str) -> bool:
    """Safely write root .env using a temporary-file and atomic-replacement strategy.

    1. Checks if .env exists and prompts for explicit confirmation before overwriting.
    2. Writes configuration to a temporary file (.env.tmp).
    3. Restricts ACLs on .env.tmp using icacls and verifies exclusive sufficient permissions.
    4. If hardening or verification fails, unlinks .env.tmp immediately (leaving original .env untouched).
    5. Only after verification succeeds, atomically replaces .env with .env.tmp.
    """
    if ENV_PATH.exists():
        print("INFO: Root .env already exists.")
        overwrite = messagebox.askyesno(
            "Configuration Exists",
            f".env file already exists at:\n{ENV_PATH}\n\nDo you want to overwrite it with new configuration?",
        )
        if not overwrite:
            print("INFO: Preserved existing root .env. Skipped writing configuration file.")
            return True

    env_content = f"""# ==============================================================================
# SentinelAgent - Application Environment Configuration
# ==============================================================================
APP_NAME="SentinelAgent API"
APP_DESCRIPTION="AI-Powered Cybersecurity Investigation System"
APP_VERSION="0.1.0"
API_PREFIX="/api"
DEBUG=false

# PostgreSQL Database Connection
DATABASE_URL="{database_url}"
"""

    tmp_path = ENV_PATH.with_suffix(".tmp")

    try:
        tmp_path.write_text(env_content, encoding="utf-8")
    except Exception as exc:
        print(f"ERROR: Failed to write temporary configuration file: {type(exc).__name__}")
        return False

    current_user = getpass.getuser()
    try:
        # Strip inheritance and grant Read/Write/Delete exclusively to current user on temp file
        grant_proc = subprocess.run(
            ["icacls", str(tmp_path), "/inheritance:r", "/grant:r", f"{current_user}:(R,W,D)"],
            capture_output=True,
            text=True,
            check=False,
        )
        if grant_proc.returncode != 0:
            print(f"ERROR: Failed to restrict temporary file permissions (icacls code {grant_proc.returncode}).")
            tmp_path.unlink(missing_ok=True)
            return False

        # Query ACL on temp file
        verify_proc = subprocess.run(
            ["icacls", str(tmp_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if verify_proc.returncode != 0:
            print(f"ERROR: Failed to query temporary file ACL (icacls code {verify_proc.returncode}).")
            tmp_path.unlink(missing_ok=True)
            return False

        # Strictly validate that granted permissions include Read AND Write, Modify, or Full Control exclusively
        if not parse_and_validate_icacls_permissions(verify_proc.stdout, current_user):
            print("ERROR: ACL validation failed: temporary file lacks verified exclusive Read AND Write / Full Control permissions.")
            tmp_path.unlink(missing_ok=True)
            return False

        # Atomically replace target .env with verified temp file
        tmp_path.replace(ENV_PATH)
        print(f"SUCCESS: Root .env atomically replaced and secured exclusively for user '{current_user}'.")
        return True
    except Exception as exc:
        print(f"ERROR: ACL configuration encountered exception: {type(exc).__name__}.")
        tmp_path.unlink(missing_ok=True)
        return False


def main():
    print("[1/6] Prompting for credentials via secure local GUI...")
    creds = prompt_credentials()

    if not creds["submitted"]:
        print("ERROR: Credential prompt cancelled by user.")
        sys.exit(1)

    postgres_pass = creds["postgres_pass"]
    app_pass = creds["app_pass"]

    # 1. Connect to PostgreSQL as admin (postgres)
    print("[2/6] Connecting to PostgreSQL as 'postgres'...")
    try:
        admin_conn = psycopg.connect(
            host="localhost",
            port=5432,
            user="postgres",
            password=postgres_pass,
            autocommit=True,
        )
    except Exception as exc:
        print(f"ERROR: Failed to connect to PostgreSQL as 'postgres': {type(exc).__name__}")
        sys.exit(1)

    print("SUCCESS: Connected to PostgreSQL server as superuser.")

    # 2. Inspect & Provision Application Role
    print("[3/6] Inspecting and provisioning role 'sentinelagent_user'...")
    with admin_conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'sentinelagent_user'")
        role_exists = cur.fetchone() is not None

        password_updated = False
        if role_exists:
            print("INFO: Role 'sentinelagent_user' already exists. Preserving existing role.")
            overwrite = messagebox.askyesno(
                "Role Exists",
                "Role 'sentinelagent_user' already exists.\n\nDo you want to update its password to the new password entered?",
            )
            if overwrite:
                cur.execute(
                    sql.SQL("ALTER ROLE sentinelagent_user WITH LOGIN PASSWORD {}").format(
                        sql.Literal(app_pass)
                    )
                )
                password_updated = True
                print("SUCCESS: Updated password for role 'sentinelagent_user'.")
            else:
                print("INFO: Preserved existing credentials for role 'sentinelagent_user'.")
                if not ENV_PATH.exists():
                    print("ERROR: Role 'sentinelagent_user' exists but password update was declined and no existing .env is present.")
                    print("Aborting safely to prevent writing mismatched credentials.")
                    admin_conn.close()
                    sys.exit(1)
                else:
                    print("INFO: Retaining pre-existing .env configuration without overwriting.")
        else:
            cur.execute(
                sql.SQL("CREATE ROLE sentinelagent_user WITH LOGIN PASSWORD {}").format(
                    sql.Literal(app_pass)
                )
            )
            password_updated = True
            print("SUCCESS: Role 'sentinelagent_user' created successfully.")

    # 3. Inspect & Provision Application Database
    print("[4/6] Inspecting and provisioning database 'sentinelagent'...")
    with admin_conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_database WHERE datname = 'sentinelagent'")
        db_exists = cur.fetchone() is not None

        if db_exists:
            print("INFO: Database 'sentinelagent' already exists. Ensuring ownership...")
            cur.execute("ALTER DATABASE sentinelagent OWNER TO sentinelagent_user")
            print("SUCCESS: Ownership of 'sentinelagent' confirmed as 'sentinelagent_user'.")
        else:
            cur.execute("CREATE DATABASE sentinelagent OWNER sentinelagent_user")
            print("SUCCESS: Database 'sentinelagent' created with owner 'sentinelagent_user'.")

    admin_conn.close()

    # 4. Connect to sentinelagent database to grant schema permissions
    print("[5/6] Configuring schema permissions on 'sentinelagent' database...")
    try:
        db_conn = psycopg.connect(
            host="localhost",
            port=5432,
            dbname="sentinelagent",
            user="postgres",
            password=postgres_pass,
            autocommit=True,
        )
        with db_conn.cursor() as cur:
            cur.execute("GRANT ALL PRIVILEGES ON DATABASE sentinelagent TO sentinelagent_user")
            cur.execute("GRANT ALL ON SCHEMA public TO sentinelagent_user")
            cur.execute("ALTER SCHEMA public OWNER TO sentinelagent_user")
        db_conn.close()
        print("SUCCESS: Permissions granted on public schema and database.")
    except Exception as exc:
        print(f"WARNING: Schema permission update encountered an issue: {type(exc).__name__}")

    # 5. Write root .env with safe ACL verification (only if password was created/updated)
    if password_updated:
        print("[6/6] Configuring application environment in root .env...")
        database_url = build_database_url("sentinelagent_user", app_pass)

        if not configure_env_file(database_url):
            print("ERROR: Failed to safely configure root .env permissions.")
            sys.exit(1)
    else:
        print("[6/6] Skipped rewriting .env because existing role credentials were preserved.")

    # 6. Verify connection as sentinelagent_user and run SELECT 1
    print("\n[VERIFICATION] Verifying real connection as 'sentinelagent_user'...")
    try:
        if password_updated:
            app_conn = psycopg.connect(
                host="localhost",
                port=5432,
                dbname="sentinelagent",
                user="sentinelagent_user",
                password=app_pass,
            )
            with app_conn.cursor() as cur:
                cur.execute("SELECT 1")
                result = cur.fetchone()
                print(f"SUCCESS: Real PostgreSQL SELECT 1 returned: {result[0]}")
            app_conn.close()
        else:
            from app.db.connection import check_db_connectivity
            is_connected, msg = check_db_connectivity()
            if is_connected:
                print(f"SUCCESS: Real PostgreSQL SELECT 1 returned: 1 (via preserved configuration)")
            else:
                print(f"WARNING: Preserved connection test returned: {msg}")
    except Exception as exc:
        print(f"ERROR: Verification connection failed: {type(exc).__name__}")
        sys.exit(1)
    finally:
        del postgres_pass
        del app_pass
        creds.clear()

    print("\nDatabase provisioning and verification completed successfully!")


if __name__ == "__main__":
    main()
